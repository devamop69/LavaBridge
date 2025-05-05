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

// Load IP whitelist from storage
let ipWhitelist = db.objectToMap(
  db.loadData(config.database.ipWhitelistDb, {})
);

// Keep track of connection attempts by IP
let connectionAttempts = new Map();
let securityViolations = new Map();
let userAgents = new Map();

// Flag to prevent recursive logging
let isLogging = false;

// Connection burst tracking (to detect potential DDoS)
let connectionBursts = new Map();
let lastConnectionTime = new Map();

// Keep track of trusted active users
let activeTrustedUsers = new Map();

/**
 * Log security related events
 * @param {string} level - Log level (info, warn, error, debug)
 * @param {string} message - Log message
 * @param {Object} data - Additional data to log
 */
function securityLog(level, message, data = {}) {
  // Prevent recursive logging
  if (isLogging) {
    console.error(`Prevented recursive security logging: ${message}`);
    return;
  }
  
  isLogging = true;
  
  try {
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
    if ((level === 'warn' || level === 'error') && data.ip) {
      // Don't call recordSecurityViolation from a blacklist operation to avoid circular calls
      if (!message.includes('has been blacklisted')) {
        recordSecurityViolation(data.ip, message);
      }
    }
  } finally {
    isLogging = false;
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
  // Check if IP is already blacklisted to avoid recursive operations
  if (ipBlacklist.has(ip)) {
    console.warn(`IP ${ip} is already blacklisted, skipping duplicate blacklist operation`);
    return;
  }
  
  const expiresAt = duration ? new Date(Date.now() + duration) : null;
  
  ipBlacklist.set(ip, {
    reason,
    blacklistedAt: new Date(),
    expiresAt,
    permanent: !expiresAt
  });
  
  // Save blacklist to disk
  db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
  
  // Log without triggering recordSecurityViolation again
  const timestamp = new Date().toISOString();
  const logData = JSON.stringify({ 
    ip, 
    reason, 
    expiresAt: expiresAt ? expiresAt.toISOString() : 'never',
    violations: securityViolations.has(ip) ? securityViolations.get(ip).count : 0
  });
  const logMessage = `[${timestamp}] [WARN] IP ${ip} has been blacklisted ${logData}\n`;
  
  // Write directly to log file and console
  securityLogStream.write(logMessage);
  console.warn(logMessage.trim());
}

/**
 * Check if an IP is whitelisted
 * @param {string} ip - IP address to check
 * @returns {boolean} true if the IP is whitelisted
 */
function isWhitelisted(ip) {
  return ipWhitelist.has(ip);
}

/**
 * Add an IP to the whitelist
 * @param {string} ip - IP address to whitelist
 * @param {string} reason - Reason for whitelisting
 * @param {string} addedBy - Who added this IP to the whitelist
 */
function whitelistIP(ip, reason, addedBy) {
  // Don't add if already whitelisted
  if (ipWhitelist.has(ip)) {
    console.log(`IP ${ip} is already whitelisted, updating information`);
  }
  
  // Add to whitelist
  ipWhitelist.set(ip, {
    reason: reason || 'Manual whitelist',
    addedBy: addedBy || 'admin',
    whitelistedAt: new Date()
  });
  
  // Save whitelist to disk
  db.saveData(config.database.ipWhitelistDb, db.mapToObject(ipWhitelist));
  
  // Log the whitelist addition
  securityLog('info', `IP ${ip} has been whitelisted`, { 
    ip, 
    reason: reason || 'Manual whitelist',
    addedBy: addedBy || 'admin'
  });
  
  // If the IP was blacklisted, remove it from blacklist
  if (ipBlacklist.has(ip)) {
    ipBlacklist.delete(ip);
    db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
    securityLog('info', `IP ${ip} removed from blacklist due to whitelisting`, { ip });
  }
}

/**
 * Remove an IP from the whitelist
 * @param {string} ip - IP address to remove from whitelist
 * @returns {boolean} true if removal was successful
 */
function removeFromWhitelist(ip) {
  if (!ipWhitelist.has(ip)) {
    return false;
  }
  
  ipWhitelist.delete(ip);
  db.saveData(config.database.ipWhitelistDb, db.mapToObject(ipWhitelist));
  securityLog('info', `IP ${ip} removed from whitelist`, { ip });
  return true;
}

/**
 * Check if an IP is blacklisted
 * @param {string} ip - IP address to check
 * @returns {Object|null} Blacklist info or null if not blacklisted
 */
function checkIPBlacklist(ip) {
  // If IP is whitelisted, it cannot be blacklisted
  if (isWhitelisted(ip)) {
    return null;
  }
  
  // Active trusted users bypass blacklist checks
  if (isActiveTrustedUser(ip)) {
    return null;
  }

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
  // Whitelisted IPs bypass rate limits
  if (isWhitelisted(ip)) {
    return false;
  }
  
  // Active trusted users also bypass rate limits
  if (isActiveTrustedUser(ip)) {
    return false;
  }

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
  // Whitelisted IPs bypass connection limits
  if (isWhitelisted(ip)) {
    return true;
  }
  
  // Active trusted users also bypass connection limits
  if (isActiveTrustedUser(ip)) {
    return true;
  }

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
 * Track connection burst patterns
 * @param {string} ip - IP address
 * @returns {boolean} true if burst detected, false otherwise
 */
function trackConnectionBurst(ip) {
  // Skip if DDoS protection is disabled
  if (!config.security.ddosProtection || !config.security.ddosProtection.enabled) {
    return false;
  }
  
  // Skip for whitelisted IPs
  if (isWhitelisted(ip)) {
    return false;
  }
  
  // Skip for trusted active users - their connection patterns are legitimate
  if (isActiveTrustedUser(ip)) {
    return false;
  }
  
  const now = Date.now();
  
  // Initialize tracking for new IPs
  if (!connectionBursts.has(ip)) {
    connectionBursts.set(ip, {
      burstCount: 0,
      detectionTime: null
    });
  }
  
  if (!lastConnectionTime.has(ip)) {
    lastConnectionTime.set(ip, now);
    return false;
  }
  
  const burst = connectionBursts.get(ip);
  const lastTime = lastConnectionTime.get(ip);
  const timeDiff = now - lastTime;
  
  // If connections come too fast, count as burst
  if (timeDiff < config.security.ddosProtection.burstIntervalMs) {
    burst.burstCount++;
    
    // If we've detected multiple bursts in short succession, consider it a potential attack
    if (burst.burstCount > config.security.ddosProtection.burstThreshold) {
      if (!burst.detectionTime) {
        burst.detectionTime = now;
        securityLog('warn', `Connection burst detected from IP ${ip}`, { 
          ip, 
          burstCount: burst.burstCount, 
          timeBetweenConnections: timeDiff 
        });
      }
      
      // If sustained bursting, consider blacklisting
      if (burst.burstCount > config.security.ddosProtection.burstBlacklistThreshold && config.security.autoBlacklist) {
        blacklistIP(ip, `Automatic blacklist due to connection burst (${burst.burstCount} connections)`, 
                  config.security.ddosProtection.temporaryBlockDuration || config.security.blacklistDuration);
      }
      
      connectionBursts.set(ip, burst);
      lastConnectionTime.set(ip, now);
      return true;
    }
  } else {
    // Reset burst counter if connections are spread out
    if (timeDiff > 1000) {
      burst.burstCount = Math.max(0, burst.burstCount - 1);
      
      // Clear detection after a longer period of normal behavior
      if (timeDiff > config.security.ddosProtection.burstResetMs) {
        burst.detectionTime = null;
      }
    }
  }
  
  connectionBursts.set(ip, burst);
  lastConnectionTime.set(ip, now);
  return false;
}

/**
 * Add an IP to the active trusted users list
 * This prevents packet dropping for legitimate users during DDoS attacks
 * @param {string} ip - IP address to add to trusted list
 */
function addTrustedActiveUser(ip) {
  // Only add if we're not already tracking this IP
  if (!activeTrustedUsers.has(ip)) {
    activeTrustedUsers.set(ip, {
      firstSeen: new Date(),
      lastActivity: new Date(),
      successfulConnections: 1
    });
  } else {
    // Update existing record
    const record = activeTrustedUsers.get(ip);
    record.lastActivity = new Date();
    record.successfulConnections++;
    activeTrustedUsers.set(ip, record);
  }
}

/**
 * Check if an IP is in the trusted active users list
 * @param {string} ip - IP address to check
 * @returns {boolean} true if the IP is trusted
 */
function isActiveTrustedUser(ip) {
  if (!activeTrustedUsers.has(ip)) {
    return false;
  }
  
  const record = activeTrustedUsers.get(ip);
  const now = Date.now();
  
  // Check if the user has been active recently (within last 10 minutes)
  const isRecentlyActive = (now - record.lastActivity.getTime()) < 10 * 60 * 1000;
  
  // Check if user has established multiple successful connections
  const hasMultipleConnections = record.successfulConnections >= 2;
  
  return isRecentlyActive && hasMultipleConnections;
}

/**
 * Update activity timestamp for a trusted active user
 * @param {string} ip - IP address to update
 */
function updateTrustedUserActivity(ip) {
  if (activeTrustedUsers.has(ip)) {
    const record = activeTrustedUsers.get(ip);
    record.lastActivity = new Date();
    activeTrustedUsers.set(ip, record);
  }
}

/**
 * Clean up expired trusted active users
 * Called during the regular cleanup intervals
 */
function cleanupTrustedActiveUsers() {
  const now = Date.now();
  
  activeTrustedUsers.forEach((record, ip) => {
    // Remove users inactive for more than 30 minutes
    if (now - record.lastActivity.getTime() > 30 * 60 * 1000) {
      activeTrustedUsers.delete(ip);
    }
  });
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
  
  // Cleanup old connection bursts tracking (older than 10 minutes)
  connectionBursts.forEach((burst, ip) => {
    if (!burst.detectionTime || now - burst.detectionTime > 10 * 60 * 1000) {
      connectionBursts.delete(ip);
    }
  });
  
  // Cleanup old connection times (older than 10 minutes)
  lastConnectionTime.forEach((time, ip) => {
    if (now - time > 10 * 60 * 1000) {
      lastConnectionTime.delete(ip);
    }
  });
  
  // Cleanup expired trusted active users
  cleanupTrustedActiveUsers();
  
  // Save blacklist to disk after cleanup
  db.saveData(config.database.ipBlacklistDb, db.mapToObject(ipBlacklist));
}

// Set up periodic cleanup
setInterval(cleanupExpiredData, 3600000); // Run every hour

/**
 * Check if an IP is currently under a suspected DDoS burst pattern
 * @param {string} ip - IP address to check
 * @returns {boolean} true if packets should be dropped, false otherwise
 */
function checkActiveAttack(ip) {
  // Skip if DDoS protection is disabled
  if (!config.security.ddosProtection || !config.security.ddosProtection.enabled) {
    return false;
  }
  
  // Skip if aggressive packet dropping is disabled
  if (!config.security.ddosProtection.aggressivePacketDropping) {
    return false;
  }
  
  // Whitelisted IPs are never considered under attack
  if (isWhitelisted(ip)) {
    return false;
  }
  
  // Always allow trusted active users to connect, even during attacks
  if (isActiveTrustedUser(ip)) {
    return false;
  }
  
  // If IP is not being tracked for bursts, it's not under attack
  if (!connectionBursts.has(ip)) {
    return false;
  }
  
  const burst = connectionBursts.get(ip);
  const now = Date.now();
  
  // More aggressive packet dropping based on burst count
  // If we've exceeded the DDoS threshold, drop all packets for the configured duration
  if (burst.detectionTime && burst.burstCount > config.security.ddosProtection.burstThreshold) {
    // Check if detection was recent (within configured packet drop duration)
    if (now - burst.detectionTime < config.security.ddosProtection.packetDropDuration) {
      securityLog('warn', `Active DDoS attack detected from IP ${ip}, dropping packet`, { 
        ip, 
        burstCount: burst.burstCount,
        remainingBlockTime: Math.floor((burst.detectionTime + config.security.ddosProtection.packetDropDuration - now) / 1000) + 's'
      });
      return true;
    }
  }
  
  // Progressive packet dropping if enabled
  if (config.security.ddosProtection.progressiveDropping) {
    // Only apply if burst count is above the minimum threshold
    if (burst.burstCount >= config.security.ddosProtection.minimumBurstForDropping) {
      // Calculate drop probability based on burst count
      // Higher burst count = higher chance of packet dropping
      const dropProbability = Math.min(0.95, burst.burstCount / 
                             (config.security.ddosProtection.burstThreshold * 1.5));
      
      if (Math.random() < dropProbability) {
        securityLog('warn', `Preventive packet dropping for potential DDoS from IP ${ip}`, { 
          ip, 
          burstCount: burst.burstCount,
          dropProbability: dropProbability.toFixed(2)
        });
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Verify the whitelist entries and reload them from the database
 * Does basic validation of whitelist entries and logs the current whitelist status
 */
function verifyWhitelist() {
  // Reload whitelist from storage
  const freshWhitelist = db.objectToMap(
    db.loadData(config.database.ipWhitelistDb, {})
  );
  
  // Validate and clean entries
  let invalidEntries = 0;
  
  freshWhitelist.forEach((info, ip) => {
    // Basic IP format validation (simple check)
    if (!ip || !ip.match(/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/)) {
      securityLog('warn', `Invalid IP format in whitelist`, { ip });
      freshWhitelist.delete(ip);
      invalidEntries++;
      return;
    }
    
    // Ensure all required fields exist
    if (!info.reason) info.reason = 'No reason provided';
    if (!info.addedBy) info.addedBy = 'unknown';
    if (!info.whitelistedAt) info.whitelistedAt = new Date().toISOString();
    
    // Update the entry
    freshWhitelist.set(ip, info);
  });
  
  // If there were invalid entries, save the cleaned whitelist
  if (invalidEntries > 0) {
    securityLog('warn', `Removed ${invalidEntries} invalid whitelist entries during verification`);
    db.saveData(config.database.ipWhitelistDb, db.mapToObject(freshWhitelist));
  }
  
  // Update the active whitelist
  ipWhitelist = freshWhitelist;
  
  securityLog('info', `Whitelist verification complete`, { 
    count: ipWhitelist.size,
    invalidRemoved: invalidEntries
  });
  
  return ipWhitelist.size;
}

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
  trackConnectionBurst,
  checkActiveAttack,
  addTrustedActiveUser,
  updateTrustedUserActivity,
  isActiveTrustedUser,
  isWhitelisted,
  whitelistIP,
  removeFromWhitelist,
  getWhitelist: () => ipWhitelist,
  getBlacklist: () => ipBlacklist,
  getSecurityViolations: () => securityViolations,
  getUserAgents: () => userAgents,
  verifyWhitelist
}; 