const fs = require('fs');
const path = require('path');
const config = require('./config');
const db = require('./database');

// Create security log directory if it doesn't exist
const logDir = path.join(__dirname, '..', config.logging.dir);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Set up security log file
const securityLogStream = fs.createWriteStream(
  path.join(logDir, `security-${new Date().toISOString().split('T')[0]}.log`),
  { flags: 'a' }
);

// Load IP blacklist from storage
let ipBlacklist = db.objectToMap(
  db.loadData(config.database.ipBlacklistDb, {})
);

// Keep track of connection attempts by IP
let connectionAttempts = new Map();
let securityViolations = new Map();
let userAgents = new Map();

/**
 * Log security related events
 * @param {string} level - Log level (info, warn, error, debug)
 * @param {string} message - Log message
 * @param {Object} data - Additional data to log
 */
function securityLog(level, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logData = JSON.stringify(data);
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message} ${logData}\n`;
  
  // Write to security log file
  securityLogStream.write(logMessage);
  
  // Also log to console based on level
  if (level === 'error' || level === 'warn') {
    console.error(logMessage.trim());
  } else if (config.logging.securityLevel === 'debug' || level === 'info') {
    console.log(logMessage.trim());
  }
  
  // Track security violations for potential automated responses
  if (level === 'warn' || level === 'error') {
    if (data.ip) {
      recordSecurityViolation(data.ip, message);
    }
  }
}

/**
 * Record a security violation for an IP
 * @param {string} ip - IP address
 * @param {string} reason - Reason for violation
 */
function recordSecurityViolation(ip, reason) {
  if (!securityViolations.has(ip)) {
    securityViolations.set(ip, {
      count: 0,
      reasons: [],
      firstViolation: new Date(),
      lastViolation: new Date()
    });
  }
  
  const violation = securityViolations.get(ip);
  violation.count++;
  violation.reasons.push({ reason, timestamp: new Date() });
  violation.lastViolation = new Date();
  
  // Cleanup old reasons to avoid memory leaks
  if (violation.reasons.length > 20) {
    violation.reasons = violation.reasons.slice(-20);
  }
  
  securityViolations.set(ip, violation);
  
  // Check if we need to auto-blacklist this IP
  if (config.security.autoBlacklist && 
      violation.count >= config.security.blacklistThreshold) {
    blacklistIP(ip, `Automatic blacklist after ${violation.count} violations`, config.security.blacklistDuration);
  }
}

/**
 * Blacklist an IP address
 * @param {string} ip - IP address to blacklist
 * @param {string} reason - Reason for blacklisting
 * @param {number} duration - Duration in milliseconds, or null for permanent
 */
function blacklistIP(ip, reason, duration = null) {
  const expiresAt = duration ? new Date(Date.now() + duration) : null;
  
  ipBlacklist.set(ip, {
    reason,
    blacklistedAt: new Date(),
    expiresAt,
    permanent: !expiresAt
  });
  
  // Save blacklist to disk
  db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
  
  securityLog('warn', `IP ${ip} has been blacklisted`, { 
    ip, 
    reason, 
    expiresAt: expiresAt ? expiresAt.toISOString() : 'never',
    violations: securityViolations.has(ip) ? securityViolations.get(ip).count : 0
  });
}

/**
 * Check if an IP is blacklisted
 * @param {string} ip - IP address to check
 * @returns {Object|null} Blacklist info or null if not blacklisted
 */
function checkIPBlacklist(ip) {
  if (!ipBlacklist.has(ip)) {
    return null;
  }
  
  const blacklistInfo = ipBlacklist.get(ip);
  
  // Check if the blacklist has expired
  if (blacklistInfo.expiresAt && new Date() > new Date(blacklistInfo.expiresAt)) {
    // Expired, remove from blacklist
    ipBlacklist.delete(ip);
    db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
    return null;
  }
  
  return blacklistInfo;
}

/**
 * Check connection rate limit for an IP
 * @param {string} ip - IP address to check
 * @returns {boolean} true if rate limit exceeded, false otherwise
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const rateWindow = config.security.rateWindowMs;
  const limit = config.security.connectionRateLimit;
  
  if (!connectionAttempts.has(ip)) {
    connectionAttempts.set(ip, []);
  }
  
  // Get connection attempts and filter old ones
  let attempts = connectionAttempts.get(ip);
  attempts = attempts.filter(time => now - time < rateWindow);
  
  // Add current attempt
  attempts.push(now);
  connectionAttempts.set(ip, attempts);
  
  // Check if limit exceeded
  if (attempts.length > limit) {
    securityLog('warn', `Rate limit exceeded for IP ${ip}`, { 
      ip, 
      attempts: attempts.length, 
      limit, 
      window: rateWindow 
    });
    return true;
  }
  
  return false;
}

/**
 * Check if total connections or connections per IP exceed limits
 * @param {string} ip - IP address
 * @param {number} totalConnections - Total active connections
 * @param {number} ipConnections - Connections from this IP
 * @returns {boolean} true if connection should be allowed, false otherwise
 */
function checkConnectionLimits(ip, totalConnections, ipConnections) {
  // Check total connection limit
  if (totalConnections >= config.security.maxConnectionsTotal) {
    securityLog('warn', `Total connection limit reached`, { 
      ip, 
      total: totalConnections, 
      limit: config.security.maxConnectionsTotal 
    });
    return false;
  }
  
  // Check per-IP connection limit
  if (ipConnections >= config.security.maxConnectionsPerIP) {
    securityLog('warn', `Per-IP connection limit reached for ${ip}`, { 
      ip, 
      connections: ipConnections, 
      limit: config.security.maxConnectionsPerIP 
    });
    return false;
  }
  
  return true;
}

/**
 * Track and validate user agents
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent string
 * @returns {boolean} true if user agent is acceptable, false otherwise
 */
function trackUserAgent(ip, userAgent) {
  if (!config.security.trackUserAgents) {
    return true;
  }
  
  if (!userAgent && config.security.blockUnknownUserAgents) {
    securityLog('warn', `Connection with no User-Agent blocked`, { ip });
    return false;
  }
  
  if (userAgent) {
    if (!userAgents.has(userAgent)) {
      userAgents.set(userAgent, { 
        firstSeen: new Date(),
        lastSeen: new Date(),
        count: 0,
        ips: new Set()
      });
    }
    
    const agent = userAgents.get(userAgent);
    agent.lastSeen = new Date();
    agent.count++;
    agent.ips.add(ip);
    userAgents.set(userAgent, agent);
  }
  
  return true;
}

/**
 * Check for suspicious data rates
 * @param {string} ip - IP address
 * @param {number} bytesPerSecond - Current data rate in bytes per second
 * @returns {boolean} true if suspicious, false otherwise
 */
function checkSuspiciousDataRate(ip, bytesPerSecond) {
  if (bytesPerSecond > config.security.suspiciousDataRateThreshold) {
    securityLog('warn', `Suspicious data rate detected for IP ${ip}`, {
      ip,
      bytesPerSecond,
      thresholdBytes: config.security.suspiciousDataRateThreshold
    });
    return true;
  }
  return false;
}

/**
 * Log full HTTP headers if enabled
 * @param {string} ip - IP address
 * @param {string} headers - Raw HTTP headers
 */
function logHeaders(ip, headers) {
  if (config.security.logFullHeaders) {
    securityLog('debug', `Headers from ${ip}`, { ip, headers });
  }
}

/**
 * Clean up expired entries from various maps to prevent memory leaks
 */
function cleanupExpiredData() {
  const now = Date.now();
  
  // Cleanup old connection attempts
  connectionAttempts.forEach((attempts, ip) => {
    const filtered = attempts.filter(time => now - time < config.security.rateWindowMs * 2);
    if (filtered.length === 0) {
      connectionAttempts.delete(ip);
    } else {
      connectionAttempts.set(ip, filtered);
    }
  });
  
  // Cleanup old security violations (older than 7 days)
  securityViolations.forEach((violation, ip) => {
    if (now - violation.lastViolation.getTime() > 7 * 24 * 60 * 60 * 1000) {
      securityViolations.delete(ip);
    }
  });
  
  // Cleanup expired blacklisted IPs
  ipBlacklist.forEach((info, ip) => {
    if (info.expiresAt && new Date() > new Date(info.expiresAt)) {
      ipBlacklist.delete(ip);
    }
  });
  
  // Save blacklist to disk after cleanup
  db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
}

// Set up periodic cleanup
setInterval(cleanupExpiredData, 3600000); // Run every hour

// Export security module functions
module.exports = {
  securityLog,
  checkIPBlacklist,
  blacklistIP,
  checkRateLimit,
  checkConnectionLimits,
  trackUserAgent,
  checkSuspiciousDataRate,
  logHeaders,
  getBlacklist: () => ipBlacklist,
  getSecurityViolations: () => securityViolations,
  getUserAgents: () => userAgents
}; 