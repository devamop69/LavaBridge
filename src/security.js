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
  if (!ip) {
    return false;
  }

  // Make sure whitelist is loaded
  if (!ipWhitelist || ipWhitelist.size === 0) {
    // Reload whitelist from storage if it's empty
    ipWhitelist = db.objectToMap(
      db.loadData(config.database.ipWhitelistDb, {})
    );
  }

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
    updateTrustedUserActivity(ip); // Update activity timestamp
    return false;
  }
  
  const now = Date.now();
  
  // Get server load
  const cpuUsage = process.cpuUsage();
  const totalCpuTime = cpuUsage.user + cpuUsage.system;
  // Calculate CPU load percentage since last call (rough approximation)
  const cpuLoad = global.lastCpuTime ? (totalCpuTime - global.lastCpuTime) / 1000000 * 100 : 0;
  global.lastCpuTime = totalCpuTime;
  
  // Under high CPU load, be more aggressive with burst detection
  const highLoad = cpuLoad > 70; // CPU usage above 70%
  
  // Initialize tracking for new IPs
  if (!connectionBursts.has(ip)) {
    connectionBursts.set(ip, {
      burstCount: 0,
      detectionTime: null,
      cpuLoad: cpuLoad
    });
  }
  
  if (!lastConnectionTime.has(ip)) {
    lastConnectionTime.set(ip, now);
    return false;
  }
  
  const burst = connectionBursts.get(ip);
  const lastTime = lastConnectionTime.get(ip);
  const timeDiff = now - lastTime;
  
  // Store current CPU load for this IP
  burst.cpuLoad = cpuLoad;
  
  // Adjust burst interval threshold based on CPU load
  const burstIntervalThreshold = highLoad 
    ? config.security.ddosProtection.burstIntervalMs * 1.5 // More aggressive under high load
    : config.security.ddosProtection.burstIntervalMs;
  
  // If connections come too fast, count as burst
  if (timeDiff < burstIntervalThreshold) {
    burst.burstCount++;
    
    // If we've detected multiple bursts in short succession, consider it a potential attack
    // Adjust threshold based on load
    const burstThreshold = highLoad 
      ? Math.max(2, config.security.ddosProtection.burstThreshold * 0.7) // Lower threshold under high load
      : config.security.ddosProtection.burstThreshold;
      
    if (burst.burstCount > burstThreshold) {
      if (!burst.detectionTime) {
        burst.detectionTime = now;
        securityLog('warn', `Connection burst detected from IP ${ip}`, { 
          ip, 
          burstCount: burst.burstCount, 
          timeBetweenConnections: timeDiff,
          cpuLoad: cpuLoad.toFixed(2) + '%'
        });
      }
      
      // If sustained bursting, consider blacklisting
      // Adjust blacklist threshold based on load
      const blacklistThreshold = highLoad
        ? config.security.ddosProtection.burstBlacklistThreshold * 0.7
        : config.security.ddosProtection.burstBlacklistThreshold;
        
      if (burst.burstCount > blacklistThreshold && config.security.autoBlacklist) {
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
      successfulConnections: 1,
      connectionIds: new Set(), // Track unique connection IDs
      priority: 0 // Priority level for this user
    });
  } else {
    // Update existing record
    const record = activeTrustedUsers.get(ip);
    record.lastActivity = new Date();
    record.successfulConnections++;
    
    // Increase priority for users with more connections
    if (record.successfulConnections > 5) {
      record.priority = Math.min(10, Math.floor(record.successfulConnections / 5));
    }
    
    activeTrustedUsers.set(ip, record);
  }
  
  // Immediately persist trusted users to disk for recovery after restart
  if (activeTrustedUsers.size % 10 === 0) { // Don't write too frequently
    persistTrustedUsers();
  }
}

/**
 * Persist trusted users to disk for recovery after restart
 */
function persistTrustedUsers() {
  try {
    // Convert to a format that can be serialized (remove Set objects)
    const persistableUsers = {};
    activeTrustedUsers.forEach((user, ip) => {
      persistableUsers[ip] = {
        firstSeen: user.firstSeen,
        lastActivity: user.lastActivity,
        successfulConnections: user.successfulConnections,
        priority: user.priority || 0
      };
    });
    
    // Save to disk using configured path
    db.saveData(config.database.trustedUsersDb, persistableUsers);
  } catch (err) {
    console.error('Failed to persist trusted users:', err);
  }
}

/**
 * Load trusted users from disk on startup
 */
function loadTrustedUsers() {
  try {
    const savedUsers = db.loadData(config.database.trustedUsersDb, {});
    
    // Convert to Map and restore properties
    Object.entries(savedUsers).forEach(([ip, userData]) => {
      activeTrustedUsers.set(ip, {
        firstSeen: new Date(userData.firstSeen),
        lastActivity: new Date(userData.lastActivity),
        successfulConnections: userData.successfulConnections,
        connectionIds: new Set(),
        priority: userData.priority || 0
      });
    });
    
    console.log(`Loaded ${activeTrustedUsers.size} trusted users from disk`);
  } catch (err) {
    console.error('Failed to load trusted users:', err);
  }
}

// Load trusted users on startup
loadTrustedUsers();

/**
 * Add a specific connection ID to a trusted user
 * @param {string} ip - IP address
 * @param {string} connectionId - Unique connection identifier
 */
function addConnectionToTrustedUser(ip, connectionId) {
  if (!activeTrustedUsers.has(ip)) {
    addTrustedActiveUser(ip);
  }
  
  const record = activeTrustedUsers.get(ip);
  record.connectionIds.add(connectionId);
  activeTrustedUsers.set(ip, record);
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
  
  // Higher priority users get longer activity window
  const activityWindow = 10 * 60 * 1000 * (1 + (record.priority || 0) * 0.5);
  
  // Check if the user has been active recently (within activity window)
  const isRecentlyActive = (now - record.lastActivity.getTime()) < activityWindow;
  
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
  let removed = 0;
  
  activeTrustedUsers.forEach((record, ip) => {
    // Priority users get longer lifetime
    const inactivityThreshold = 30 * 60 * 1000 * (1 + (record.priority || 0) * 0.5);
    
    // Remove users inactive for more than their threshold period
    if (now - record.lastActivity.getTime() > inactivityThreshold) {
      activeTrustedUsers.delete(ip);
      removed++;
    }
  });
  
  if (removed > 0) {
    console.log(`Cleaned up ${removed} inactive trusted users`);
    persistTrustedUsers();
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
    // Update activity timestamp to keep user active
    updateTrustedUserActivity(ip);
    return false;
  }
  
  // If IP is not being tracked for bursts, it's not under attack
  if (!connectionBursts.has(ip)) {
    return false;
  }
  
  const burst = connectionBursts.get(ip);
  const now = Date.now();
  
  // Get CPU load from the burst data
  const cpuLoad = burst.cpuLoad || 0;
  const highLoad = cpuLoad > 70;
  
  // More aggressive packet dropping based on burst count and CPU load
  // If we've exceeded the DDoS threshold, drop all packets for the configured duration
  if (burst.detectionTime && burst.burstCount > config.security.ddosProtection.burstThreshold) {
    // Under high load, extend packet drop duration
    const dropDuration = highLoad 
      ? config.security.ddosProtection.packetDropDuration * 1.5
      : config.security.ddosProtection.packetDropDuration;
      
    // Check if detection was recent (within configured packet drop duration)
    if (now - burst.detectionTime < dropDuration) {
      securityLog('warn', `Active DDoS attack detected from IP ${ip}, dropping packet`, { 
        ip, 
        burstCount: burst.burstCount,
        cpuLoad: cpuLoad.toFixed(2) + '%',
        remainingBlockTime: Math.floor((burst.detectionTime + dropDuration - now) / 1000) + 's'
      });
      return true;
    }
  }
  
  // Progressive packet dropping if enabled
  if (config.security.ddosProtection.progressiveDropping) {
    // Adjust minimum threshold based on CPU load
    const minBurstThreshold = highLoad
      ? Math.max(1, config.security.ddosProtection.minimumBurstForDropping * 0.7)
      : config.security.ddosProtection.minimumBurstForDropping;
      
    // Only apply if burst count is above the minimum threshold
    if (burst.burstCount >= minBurstThreshold) {
      // Calculate drop probability based on burst count and CPU load
      // Higher burst count and CPU load = higher chance of packet dropping
      const loadFactor = highLoad ? 1.5 : 1;
      const dropProbability = Math.min(0.95, (burst.burstCount / 
                             (config.security.ddosProtection.burstThreshold * 1.5)) * loadFactor);
      
      if (Math.random() < dropProbability) {
        securityLog('warn', `Preventive packet dropping for potential DDoS from IP ${ip}`, { 
          ip, 
          burstCount: burst.burstCount,
          cpuLoad: cpuLoad.toFixed(2) + '%',
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
  
  // Check all entries
  if (ipWhitelist.size > 0) {
    securityLog('info', 'Current whitelist entries:', { count: ipWhitelist.size });
    ipWhitelist.forEach((info, ip) => {
      securityLog('info', `Whitelisted IP: ${ip}`, { reason: info.reason, addedBy: info.addedBy });
    });
  }
  
  securityLog('info', `Whitelist verification complete`, { 
    count: ipWhitelist.size,
    invalidRemoved: invalidEntries
  });
  
  return ipWhitelist.size;
}

// Initialize global CPU tracking
global.lastCpuTime = null;

// Monitor CPU usage periodically to detect high load situations
let lastCpuMonitorTime = Date.now();
setInterval(() => {
  const cpuUsage = process.cpuUsage();
  const totalCpuTime = cpuUsage.user + cpuUsage.system;
  const cpuLoad = global.lastCpuTime ? (totalCpuTime - global.lastCpuTime) / 1000000 * 100 : 0;
  global.lastCpuTime = totalCpuTime;
  
  // Calculate time since last check
  const now = Date.now();
  const elapsed = now - lastCpuMonitorTime;
  lastCpuMonitorTime = now;
  
  // Log CPU usage if it's high
  if (cpuLoad > 70) {
    securityLog('warn', `High CPU usage detected`, { 
      cpuLoad: cpuLoad.toFixed(2) + '%',
      interval: elapsed + 'ms',
      activeConnections: activeTrustedUsers.size
    });
    
    // Under extreme CPU load, be more aggressive with burst detection and packet dropping
    if (cpuLoad > 90) {
      securityLog('error', `Extreme CPU usage detected - enabling emergency protection measures`, {
        cpuLoad: cpuLoad.toFixed(2) + '%'
      });
      
      // Temporarily reduce burst thresholds to protect the server
      config.security.ddosProtection.burstThreshold = Math.max(2, Math.floor(config.security.ddosProtection.burstThreshold * 0.5));
      config.security.ddosProtection.minimumBurstForDropping = 1;
    }
  }
}, 5000); // Check every 5 seconds

/**
 * Simple check if a connection should be accepted, optimized for performance
 * @param {string} ip - IP address to check
 * @returns {boolean} true if connection should be accepted, false otherwise
 */
function shouldAcceptConnection(ip) {
  // Handle undefined/invalid IPs (can happen during high-volume attacks)
  if (!ip || ip === 'undefined') {
    return false;
  }

  try {
    // Whitelist check (fastest path)
    if (isWhitelisted(ip)) {
      return true;
    }
    
    // Blacklist check (second fastest)
    const blacklistInfo = checkIPBlacklist(ip);
    if (blacklistInfo) {
      return false;
    }
  
    // Trusted user check (allows legitimate users during attacks)
    if (isActiveTrustedUser(ip)) {
      updateTrustedUserActivity(ip);
      return true;
    }
    
    // Server overload protection
    try {
      // Only check CPU under high load
      if (global.lastCpuTime) {
        const cpuUsage = process.cpuUsage();
        const totalCpuTime = cpuUsage.user + cpuUsage.system;
        const cpuLoad = (totalCpuTime - global.lastCpuTime) / 1000000 * 100;
        
        // Under extreme load, only accept trusted/whitelisted users
        if (cpuLoad > 90) {
          return false;
        }
      }
      
      // Check overall connection count - simple threshold for server capacity
      // This helps prevent memory exhaustion during attacks
      if (global.activeConnections > 200) { // This requires the global to be set in index.js
        return false;
      }
    } catch (err) {
      // If any error in CPU check, fall back to connection burst check
      console.error('Error checking server load:', err);
    }
    
    // Connection burst check (for DDoS prevention)
    const now = Date.now();
    
    try {
      // Initialize tracking for new IPs
      if (!connectionBursts.has(ip)) {
        connectionBursts.set(ip, {
          burstCount: 0,
          detectionTime: null
        });
      }
      
      if (!lastConnectionTime.has(ip)) {
        lastConnectionTime.set(ip, now);
        return true;
      }
      
      const burst = connectionBursts.get(ip);
      const lastTime = lastConnectionTime.get(ip);
      const timeDiff = now - lastTime;
      
      // If connections come too fast, count as burst
      if (timeDiff < config.security.ddosProtection.burstIntervalMs) {
        burst.burstCount++;
        
        // If we've detected multiple bursts in short succession, reject connection
        if (burst.burstCount > config.security.ddosProtection.burstThreshold) {
          connectionBursts.set(ip, burst);
          lastConnectionTime.set(ip, now);
          return false;
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
    } catch (err) {
      // In case of any error with data structures, err on the side of caution
      console.error('Error in connection burst check:', err);
      return false;
    }
    
    return true;
  } catch (err) {
    // Global catch for any errors in the function
    console.error(`Error in shouldAcceptConnection for IP ${ip}:`, err);
    // If anything unexpected happens, reject the connection
    return false;
  }
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
  addConnectionToTrustedUser,
  persistTrustedUsers,
  loadTrustedUsers,
  shouldAcceptConnection,
  isWhitelisted,
  whitelistIP,
  removeFromWhitelist,
  getWhitelist: () => ipWhitelist,
  getBlacklist: () => ipBlacklist,
  getSecurityViolations: () => securityViolations,
  getUserAgents: () => userAgents,
  verifyWhitelist
}; 