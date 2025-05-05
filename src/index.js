// External dependencies
const net = require('net');
const fs = require('fs');
const path = require('path');
const express = require('express');
const http = require('http');

// Internal modules
const config = require('./config');
const db = require('./database');
const security = require('./security');

// Setup logging
const logDir = path.join(__dirname, '..', config.logging.dir);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logStream = fs.createWriteStream(
  path.join(logDir, `proxy-${new Date().toISOString().split('T')[0]}.log`), 
  { flags: 'a' }
);

function log(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  console.log(message);
  logStream.write(logMessage);
}

function logError(message, error) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ERROR: ${message}\n${error ? error.stack || error : 'No error details'}\n\n`;
  console.error(logMessage);
  logStream.write(logMessage);
}

// Near the beginning of the file, add a global error handler for uncaught errors

// Set up global error handler for uncaught exceptions
process.on('uncaughtException', (err) => {
  logError(`Uncaught Exception: ${err.message}`, err);
  // Don't exit the process, just log the error
});

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  logError(`Unhandled Rejection: ${reason}`, reason);
});

// Keep track of active connections
let activeConnections = 0;
// Expose activeConnections to the global scope for the security module
global.activeConnections = 0;

// Load stored data or initialize new Maps
let connectionDetails = db.objectToMap(
  db.loadData(config.database.connectionDb, {})
);

let ipDataUsage = db.objectToMap(
  db.loadData(config.database.ipUsageDb, {})
);

// Load backend status if available
const backendStatus = db.loadData(config.database.backendStatusDb, {});
if (backendStatus.v3) {
  config.lavalink.v3.status = backendStatus.v3.status || "unknown";
  config.lavalink.v3.lastChecked = backendStatus.v3.lastChecked ? new Date(backendStatus.v3.lastChecked) : null;
  config.lavalink.v3.responseTime = backendStatus.v3.responseTime || null;
}

if (backendStatus.v4) {
  config.lavalink.v4.status = backendStatus.v4.status || "unknown";
  config.lavalink.v4.lastChecked = backendStatus.v4.lastChecked ? new Date(backendStatus.v4.lastChecked) : null;
  config.lavalink.v4.responseTime = backendStatus.v4.responseTime || null;
}

// Data rate tracking constants
const RATE_TRACKING_INTERVAL = config.rateTracking.interval;
const RATE_HISTORY_LENGTH = config.rateTracking.historyLength;

// Helper function to update IP data usage
function updateIpDataUsage(ip, bytesIn, bytesOut) {
  if (!ipDataUsage.has(ip)) {
    ipDataUsage.set(ip, {
      bytesIn: 0,
      bytesOut: 0,
      connections: 0,
      lastActive: new Date(),
      // Add data rate tracking
      bytesInLast: 0,
      bytesOutLast: 0,
      bytesInRate: 0,
      bytesOutRate: 0,
      rateHistory: []
    });
  }
  
  const usage = ipDataUsage.get(ip);
  usage.bytesIn += bytesIn || 0;
  usage.bytesOut += bytesOut || 0;
  usage.bytesInLast += bytesIn || 0;
  usage.bytesOutLast += bytesOut || 0;
  usage.lastActive = new Date();
  
  ipDataUsage.set(ip, usage);
  
  // Save IP usage data to disk
  saveIpUsageData();
}

// Helper function to format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Helper function to format bytes/second rate
function formatBytesRate(bytesPerSecond, decimals = 2) {
  return formatBytes(bytesPerSecond, decimals) + '/s';
}

function updateConnectionCounter(change) {
  activeConnections += change;
  global.activeConnections = activeConnections; // Update global counter
  
  // Only log the count to console, not the details
  log(`Active connections: ${activeConnections}`);
  
  // Full details are logged to file only
  let details = '';
  connectionDetails.forEach((info, id) => {
    details += `\n  - ${id}: ${info.clientAddress} → ${info.backend} (${info.version})`;
  });
  
  if (details) {
    logStream.write(`[${new Date().toISOString()}] Connection details:${details}\n`);
  }
  
  // Save connection data to disk
  saveConnectionData();
}

// Calculate data rates for all connections and IPs
function calculateDataRates() {
  const now = Date.now();
  let connectionUpdated = false;
  let ipUsageUpdated = false;
  
  // Update data rates for each connection
  connectionDetails.forEach((info, id) => {
    const bytesInDelta = info.bytesIn - (info.bytesInLast || 0);
    const bytesOutDelta = info.bytesOut - (info.bytesOutLast || 0);
    
    // Calculate rates (bytes per second)
    const secondsElapsed = (now - (info.lastRateUpdate || info.startTime.getTime())) / 1000;
    info.bytesInRate = secondsElapsed > 0 ? Math.round(bytesInDelta / secondsElapsed) : 0;
    info.bytesOutRate = secondsElapsed > 0 ? Math.round(bytesOutDelta / secondsElapsed) : 0;
    
    // Store current values for next calculation
    info.bytesInLast = info.bytesIn;
    info.bytesOutLast = info.bytesOut;
    info.lastRateUpdate = now;
    
    // Add to rate history
    if (!info.rateHistory) info.rateHistory = [];
    info.rateHistory.push({
      timestamp: new Date(now),
      bytesInRate: info.bytesInRate,
      bytesOutRate: info.bytesOutRate
    });
    
    // Keep only the last N history items
    if (info.rateHistory.length > RATE_HISTORY_LENGTH) {
      info.rateHistory = info.rateHistory.slice(-RATE_HISTORY_LENGTH);
    }
    
    connectionDetails.set(id, info);
    connectionUpdated = true;
  });
  
  // Update data rates for each IP
  ipDataUsage.forEach((usage, ip) => {
    const bytesInDelta = usage.bytesInLast || 0;
    const bytesOutDelta = usage.bytesOutLast || 0;
    
    // Calculate rates (bytes per second)
    const secondsElapsed = RATE_TRACKING_INTERVAL / 1000; // Time interval in seconds
    usage.bytesInRate = Math.round(bytesInDelta / secondsElapsed);
    usage.bytesOutRate = Math.round(bytesOutDelta / secondsElapsed);
    
    // Add to rate history
    if (!usage.rateHistory) usage.rateHistory = [];
    usage.rateHistory.push({
      timestamp: new Date(now),
      bytesInRate: usage.bytesInRate,
      bytesOutRate: usage.bytesOutRate
    });
    
    // Keep only the last N history items
    if (usage.rateHistory.length > RATE_HISTORY_LENGTH) {
      usage.rateHistory = usage.rateHistory.slice(-RATE_HISTORY_LENGTH);
    }
    
    // Reset counters for next interval
    usage.bytesInLast = 0;
    usage.bytesOutLast = 0;
    
    ipDataUsage.set(ip, usage);
    ipUsageUpdated = true;
  });
  
  // Save data to disk after calculation
  if (connectionUpdated) {
    saveConnectionData();
  }
  
  if (ipUsageUpdated) {
    saveIpUsageData();
  }
}

// Helper functions to save data to JSON files
function saveConnectionData() {
  db.saveData(config.database.connectionDb, db.mapToObject(connectionDetails));
}

function saveIpUsageData() {
  db.saveData(config.database.ipUsageDb, db.mapToObject(ipDataUsage));
}

function saveBackendStatus() {
  const backendStatus = {
    v3: {
      status: config.lavalink.v3.status,
      lastChecked: config.lavalink.v3.lastChecked,
      responseTime: config.lavalink.v3.responseTime
    },
    v4: {
      status: config.lavalink.v4.status,
      lastChecked: config.lavalink.v4.lastChecked,
      responseTime: config.lavalink.v4.responseTime
    }
  };
  
  db.saveData(config.database.backendStatusDb, backendStatus);
}

// Clean up connection details on server restart
log("Cleaning connection database on startup...");
connectionDetails.clear();  // Clear all existing connections
activeConnections = 0;      // Reset active connection counter
saveConnectionData();       // Save the empty connection database
log("Connection database cleared. Starting with 0 active connections.");

// Verify whitelist entries
log("Verifying IP whitelist...");
security.verifyWhitelist();
const whitelist = security.getWhitelist();

// Log whitelist entries
if (whitelist.size > 0) {
  log(`Found ${whitelist.size} whitelisted IP(s):`);
  whitelist.forEach((info, ip) => {
    log(`- ${ip}: ${info.reason} (added by ${info.addedBy} on ${new Date(info.whitelistedAt).toLocaleString()})`);
  });
} else {
  log("No whitelisted IPs found.");
}

// Set up interval for data rate calculations
setInterval(calculateDataRates, RATE_TRACKING_INTERVAL);

// Memory optimization: Periodically clean up data structures during high load
setInterval(() => {
  // Only run aggressive cleanup if we have many connections or during high load
  if (activeConnections > 50) {
    log(`Running aggressive memory cleanup (${activeConnections} active connections)`);
    
    // Clean up old IP usage data
    let cleanupCount = 0;
    const now = Date.now();
    
    ipDataUsage.forEach((usage, ip) => {
      // If IP has no connections and was last active more than 5 minutes ago, remove it
      if (usage.connections <= 0 && (now - usage.lastActive) > 5 * 60 * 1000) {
        ipDataUsage.delete(ip);
        cleanupCount++;
      }
    });
    
    if (cleanupCount > 0) {
      log(`Cleaned up ${cleanupCount} inactive IP usage records`);
    }
    
    // Clear old connection history if memory usage is high
    try {
      const memoryUsage = process.memoryUsage();
      // If using more than 80% of heap, force garbage collection through more cleanup
      if (memoryUsage.heapUsed / memoryUsage.heapTotal > 0.8) {
        global.gc && global.gc(); // Try to force garbage collection if available
        log(`High memory usage: ${Math.round(memoryUsage.rss / 1024 / 1024)}MB - forcing cleanup`);
      }
    } catch (err) {
      // Ignore errors for memory checks
    }
  }
}, 60000); // Run every minute

// Save data periodically instead of on every change
setInterval(() => {
  saveConnectionData();
  saveIpUsageData();
  saveBackendStatus();
}, 300000); // Every 5 minutes

// Function to check backend server health
function checkBackendHealth(version) {
  const backend = config.lavalink[version];
  const startTime = Date.now();
  
  return new Promise((resolve) => {
    const socket = net.connect({
      host: backend.host,
      port: backend.port
    });
    
    // Set a timeout for the connection attempt
    const timeout = setTimeout(() => {
      socket.destroy();
      backend.status = "timeout";
      backend.lastChecked = new Date();
      backend.responseTime = null;
      resolve(backend);
    }, config.healthCheck.timeout); // Use configured timeout
    
    socket.on('connect', () => {
      clearTimeout(timeout);
      const responseTime = Date.now() - startTime;
      backend.status = "online";
      backend.lastChecked = new Date();
      backend.responseTime = responseTime;
      socket.destroy();
      resolve(backend);
    });
    
    socket.on('error', (err) => {
      clearTimeout(timeout);
      backend.status = "offline";
      backend.lastChecked = new Date();
      backend.responseTime = null;
      resolve(backend);
    });
  });
}

// Function to check all backend servers health
async function checkAllBackendsHealth() {
  try {
    await Promise.all([
      checkBackendHealth('v3'),
      checkBackendHealth('v4')
    ]);
    
    // Save the backend status to disk
    saveBackendStatus();
    
    log('Backend health check completed');
  } catch (error) {
    logError('Error during backend health check', error);
  }
}

// Run initial health check
checkAllBackendsHealth();

// Schedule health checks at the configured interval
setInterval(checkAllBackendsHealth, config.healthCheck.interval);

// Create Express app for web interface
const app = express();

// Add body parser for JSON
app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, '../public')));

// Set up simple session using a Map
const sessions = new Map();
const SESSION_DURATION = 5 * 60 * 1000; // 5 minutes

// Function to create a new session
function createSession(ip) {
  const sessionId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  const expires = Date.now() + SESSION_DURATION;
  
  sessions.set(sessionId, {
    ip,
    expires,
    lastActive: Date.now()
  });
  
  return sessionId;
}

// Function to validate session
function validateSession(sessionId) {
  if (!sessions.has(sessionId)) {
    return false;
  }
  
  const session = sessions.get(sessionId);
  
  // Check if expired
  if (Date.now() > session.expires) {
    sessions.delete(sessionId);
    return false;
  }
  
  // Update last active time and extend expiration
  session.lastActive = Date.now();
  session.expires = Date.now() + SESSION_DURATION;
  sessions.set(sessionId, session);
  
  return true;
}

// Clear expired sessions every minute
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (now > session.expires) {
      sessions.delete(sessionId);
    }
  }
}, 60 * 1000);

// Authentication middleware for security endpoints
function requireAuth(req, res, next) {
  const sessionId = req.headers.authorization;
  
  if (validateSession(sessionId)) {
    return next();
  }
  
  res.status(401).json({ message: 'Authentication required' });
}

// API endpoint to get connection information
app.get('/api/connections', (req, res) => {
  const connections = [];
  
  connectionDetails.forEach((info, id) => {
    connections.push({
      id,
      clientAddress: info.clientAddress,
      backend: info.backend,
      version: info.version,
      startTime: info.startTime,
      uptime: Math.floor((new Date() - info.startTime) / 1000), // in seconds
      bytesIn: info.bytesIn || 0,
      bytesOut: info.bytesOut || 0,
      // Add data rates
      bytesInRate: info.bytesInRate || 0,
      bytesOutRate: info.bytesOutRate || 0,
      formattedBytesInRate: formatBytesRate(info.bytesInRate || 0),
      formattedBytesOutRate: formatBytesRate(info.bytesOutRate || 0),
      rateHistory: info.rateHistory || []
    });
  });
  
  res.json({
    activeConnections,
    connections
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  const startTime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    status: 'ok',
    version: require('../package.json').version,
    uptime: startTime,
    connections: {
      active: activeConnections,
      v3: Array.from(connectionDetails.values()).filter(conn => conn.version === 'v3').length,
      v4: Array.from(connectionDetails.values()).filter(conn => conn.version === 'v4').length
    },
    memory: {
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB',
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB',
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB'
    },
    backends: {
      v3: {
        url: `${config.lavalink.v3.host}:${config.lavalink.v3.port}`,
        status: config.lavalink.v3.status,
        lastChecked: config.lavalink.v3.lastChecked,
        responseTime: config.lavalink.v3.responseTime
      },
      v4: {
        url: `${config.lavalink.v4.host}:${config.lavalink.v4.port}`,
        status: config.lavalink.v4.status,
        lastChecked: config.lavalink.v4.lastChecked,
        responseTime: config.lavalink.v4.responseTime
      }
    }
  });
});

// Backend health check endpoint
app.get('/api/backend-health', async (req, res) => {
  // Force a fresh health check
  await checkAllBackendsHealth();
  
  res.json({
    v3: {
      url: `${config.lavalink.v3.host}:${config.lavalink.v3.port}`,
      status: config.lavalink.v3.status,
      lastChecked: config.lavalink.v3.lastChecked,
      responseTime: config.lavalink.v3.responseTime
    },
    v4: {
      url: `${config.lavalink.v4.host}:${config.lavalink.v4.port}`,
      status: config.lavalink.v4.status,
      lastChecked: config.lavalink.v4.lastChecked,
      responseTime: config.lavalink.v4.responseTime
    }
  });
});

// Data usage endpoint
app.get('/api/data-usage', (req, res) => {
  const ipUsage = [];
  
  ipDataUsage.forEach((usage, ip) => {
    ipUsage.push({
      ip,
      bytesIn: usage.bytesIn,
      bytesOut: usage.bytesOut,
      totalBytes: usage.bytesIn + usage.bytesOut,
      formattedBytesIn: formatBytes(usage.bytesIn),
      formattedBytesOut: formatBytes(usage.bytesOut),
      formattedTotal: formatBytes(usage.bytesIn + usage.bytesOut),
      // Add data rates
      bytesInRate: usage.bytesInRate || 0,
      bytesOutRate: usage.bytesOutRate || 0,
      totalRate: (usage.bytesInRate || 0) + (usage.bytesOutRate || 0),
      formattedBytesInRate: formatBytesRate(usage.bytesInRate || 0),
      formattedBytesOutRate: formatBytesRate(usage.bytesOutRate || 0),
      formattedTotalRate: formatBytesRate((usage.bytesInRate || 0) + (usage.bytesOutRate || 0)),
      rateHistory: usage.rateHistory || [],
      activeConnections: Array.from(connectionDetails.values())
        .filter(conn => conn.clientAddress.startsWith(ip)).length,
      lastActive: usage.lastActive
    });
  });
  
  // Sort by total traffic (descending)
  ipUsage.sort((a, b) => b.totalBytes - a.totalBytes);
  
  res.json({
    totalIps: ipUsage.length,
    ipUsage
  });
});

// Serve the HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/health', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/health.html'));
});

app.get('/data-usage', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/data-usage.html'));
});

// Add a link to the health page
app.get('/api/version', (req, res) => {
  res.json({
    version: '1.0.0',
    name: 'LavaBridge',
    description: 'A TCP tunneling proxy for Lavalink v3 and v4 servers'
  });
});

// Add connection information endpoint for the frontend
app.get('/api/connection-info', (req, res) => {
  const host = config.proxy.host;
  const port = config.proxy.port;
  // Include the actual password
  const password = config.proxy.password;
  const passwordLength = password.length;
  
  // Get the public URL if configured, otherwise generate from host
  let publicUrl = config.proxy.publicUrl;
  
  // If no public URL is configured, generate one based on request
  if (!publicUrl) {
    // If binding to all interfaces (0.0.0.0), use the incoming request's host
    const serverHost = host === '0.0.0.0' ? req.headers.host.split(':')[0] : host;
    publicUrl = `${serverHost}:${port}`;
  }
  
  res.json({
    host,
    port,
    publicUrl,
    passwordLength,
    password
  });
});

// Add security page
app.get('/security', (req, res) => {
  // Clear session when the security page is loaded
  const sessionId = req.headers.authorization;
  if (sessionId && sessions.has(sessionId)) {
    sessions.delete(sessionId);
  }
  
  res.sendFile(path.join(__dirname, '../public/security.html'));
});

// Authentication endpoints
app.post('/api/security/auth', (req, res) => {
  const { password } = req.body;
  
  // Check if password matches the security password
  if (password === config.security.securityPassword) {
    const sessionId = createSession(req.ip);
    res.json({ sessionId });
  } else {
    res.status(401).json({ message: 'Invalid password' });
  }
});

app.get('/api/security/check-auth', (req, res) => {
  const sessionId = req.headers.authorization;
  
  if (validateSession(sessionId)) {
    res.json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

// Security API endpoints
app.get('/api/security', requireAuth, (req, res) => {
  const blacklist = [];
  const whitelist = [];
  const violations = [];
  const userAgents = [];
  
  // Process blacklist
  security.getBlacklist().forEach((info, ip) => {
    blacklist.push({
      ip,
      ...info
    });
  });
  
  // Process whitelist
  security.getWhitelist().forEach((info, ip) => {
    // Ensure whitelistedAt is a proper ISO string
    if (info.whitelistedAt && !(info.whitelistedAt instanceof Date) && typeof info.whitelistedAt === 'object') {
      info.whitelistedAt = new Date(info.whitelistedAt).toISOString();
    } else if (info.whitelistedAt && info.whitelistedAt instanceof Date) {
      info.whitelistedAt = info.whitelistedAt.toISOString();
    } else if (!info.whitelistedAt) {
      info.whitelistedAt = new Date().toISOString();
    }
    
    whitelist.push({
      ip,
      ...info
    });
  });
  
  // Process violations
  security.getSecurityViolations().forEach((info, ip) => {
    violations.push({
      ip,
      ...info
    });
  });
  
  // Process user agents
  security.getUserAgents().forEach((info, userAgent) => {
    userAgents.push({
      userAgent,
      firstSeen: info.firstSeen,
      lastSeen: info.lastSeen,
      count: info.count,
      uniqueIps: info.ips.size
    });
  });
  
  // Sort by most recent violations
  violations.sort((a, b) => new Date(b.lastViolation) - new Date(a.lastViolation));
  
  // Sort by most frequently used user agents
  userAgents.sort((a, b) => b.count - a.count);
  
  res.json({
    blacklistedIPs: blacklist.length,
    whitelistedIPs: whitelist.length,
    totalViolations: violations.length,
    userAgentsCount: userAgents.length,
    blacklist,
    whitelist,
    violations,
    userAgents
  });
});

// Blacklist an IP
app.post('/api/security/blacklist', requireAuth, (req, res) => {
  const { ip, reason, duration } = req.body;
  
  if (!ip) {
    return res.status(400).json({ message: 'IP address is required' });
  }
  
  try {
    // Duration of 0 means permanent blacklist
    const actualDuration = duration === 0 ? null : duration;
    security.blacklistIP(ip, reason || 'Manual blacklist', actualDuration);
    res.json({ message: `IP ${ip} has been blacklisted` });
  } catch (error) {
    logError(`Error blacklisting IP ${ip}`, error);
    res.status(500).json({ message: error.message });
  }
});

// Remove IP from blacklist
app.post('/api/security/unblacklist', requireAuth, (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ message: 'IP address is required' });
  }
  
  try {
    const blacklist = security.getBlacklist();
    if (blacklist.has(ip)) {
      blacklist.delete(ip);
      db.saveData(config.database.ipBlacklistDb, db.mapToObject(blacklist));
      res.json({ message: `IP ${ip} has been removed from blacklist` });
    } else {
      res.status(404).json({ message: `IP ${ip} is not blacklisted` });
    }
  } catch (error) {
    logError(`Error removing IP ${ip} from blacklist`, error);
    res.status(500).json({ message: error.message });
  }
});

// Add IP to whitelist
app.post('/api/security/whitelist', requireAuth, (req, res) => {
  const { ip, reason } = req.body;
  
  if (!ip) {
    return res.status(400).json({ message: 'IP address is required' });
  }
  
  try {
    security.whitelistIP(ip, reason || 'Manual whitelist', req.ip);
    res.json({ message: `IP ${ip} has been whitelisted` });
  } catch (error) {
    logError(`Error whitelisting IP ${ip}`, error);
    res.status(500).json({ message: error.message });
  }
});

// Remove IP from whitelist
app.post('/api/security/unwhitelist', requireAuth, (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ message: 'IP address is required' });
  }
  
  try {
    if (security.removeFromWhitelist(ip)) {
      res.json({ message: `IP ${ip} has been removed from whitelist` });
    } else {
      res.status(404).json({ message: `IP ${ip} is not whitelisted` });
    }
  } catch (error) {
    logError(`Error removing IP ${ip} from whitelist`, error);
    res.status(500).json({ message: error.message });
  }
});

// Get whitelist
app.get('/api/security/whitelist', requireAuth, (req, res) => {
  try {
    const whitelist = [];
    security.getWhitelist().forEach((info, ip) => {
      // Ensure whitelistedAt is a proper ISO string
      if (info.whitelistedAt && !(info.whitelistedAt instanceof Date) && typeof info.whitelistedAt === 'object') {
        info.whitelistedAt = new Date(info.whitelistedAt).toISOString();
      } else if (info.whitelistedAt && info.whitelistedAt instanceof Date) {
        info.whitelistedAt = info.whitelistedAt.toISOString();
      } else if (!info.whitelistedAt) {
        info.whitelistedAt = new Date().toISOString();
      }
      
      whitelist.push({
        ip,
        ...info
      });
    });
    
    console.log("Whitelist API response:", whitelist);
    res.json({ whitelist });
  } catch (error) {
    logError('Error fetching whitelist', error);
    res.status(500).json({ message: error.message });
  }
});

/**
 * Parse PROXY protocol header
 * PROXY protocol format: "PROXY" + TCP4/TCP6 + client-ip + proxy-ip + client-port + proxy-port + CRLF
 * @param {Buffer} data - Buffer containing potential PROXY protocol header
 * @returns {Object} Parsed proxy information
 */
function parseProxyProtocol(data) {
  // Check for PROXY protocol signature
  const dataStr = data.toString('utf8', 0, Math.min(data.length, 108)); // Max PROXY header is 107 bytes
  
  if (!dataStr.startsWith('PROXY ')) {
    return { isProxy: false };
  }
  
  try {
    // Extract parts from PROXY protocol line
    const endOfLine = dataStr.indexOf('\r\n');
    if (endOfLine === -1) {
      return { isProxy: true, complete: false }; // Incomplete header
    }
    
    const parts = dataStr.substring(0, endOfLine).split(' ');
    
    if (parts.length < 6) {
      log(`Invalid PROXY protocol header format`);
      return { isProxy: false };
    }
    
    const [, proto, srcIp, destIp, srcPort, destPort] = parts;
    
    if (proto !== 'TCP4' && proto !== 'TCP6') {
      log(`Unsupported PROXY protocol: ${proto}`);
      return { isProxy: false };
    }
    
    log(`Detected PROXY protocol: ${srcIp}:${srcPort} via ${destIp}:${destPort}`);
    
    // Return parsed information with remaining data
    return {
      isProxy: true,
      complete: true,
      originalIp: srcIp,
      originalPort: parseInt(srcPort, 10),
      remainingData: data.slice(endOfLine + 2) // +2 for CRLF
    };
  } catch (err) {
    logError(`Error parsing PROXY protocol: ${err.message}`, err);
    return { isProxy: false };
  }
}

// Start the HTTP server
const httpServer = http.createServer(app);
httpServer.listen(config.proxy.webPort, config.proxy.host, () => {
  log(`Web interface running on http://${config.proxy.host === '0.0.0.0' ? 'localhost' : config.proxy.host}:${config.proxy.webPort}`);
});

// Create a pure TCP server
const server = net.createServer((clientSocket) => {
  let buffer = Buffer.alloc(0);
  let backendSocket = null;
  let version = null;
  let authenticated = false;
  const clientId = `conn_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  let clientAddress = `${clientSocket.remoteAddress}:${clientSocket.remotePort}`;
  let clientIp = clientSocket.remoteAddress;
  let proxyProtocolComplete = false;
  let socketClosed = false; // Track if socket is already closed
  
  // Initialize data counters
  let bytesFromClient = 0;
  let bytesToClient = 0;
  
  // Safely close socket function to prevent duplicate close attempts
  const safelyCloseSocket = (socket, reason) => {
    if (socket && !socket.destroyed) {
      try {
        socket.end();
      } catch (err) {
        // Ignore any errors during socket closing
      }
    }
  };
  
  log(`New connection from ${clientAddress} (ID: ${clientId})`);
  
  // Fast path: Simple check if we should accept this connection
  if (!security.shouldAcceptConnection(clientIp)) {
    security.securityLog('warn', `Fast rejection of connection from ${clientIp}`, { ip: clientIp, id: clientId });
    safelyCloseSocket(clientSocket, 'rejected');
    return;
  }
  
  // Track the new connection for this IP
  if (ipDataUsage.has(clientIp)) {
    const usage = ipDataUsage.get(clientIp);
    usage.connections++;
    ipDataUsage.set(clientIp, usage);
  } else {
    ipDataUsage.set(clientIp, {
      bytesIn: 0, 
      bytesOut: 0, 
      connections: 1,
      lastActive: new Date(),
      bytesInLast: 0,
      bytesOutLast: 0,
      bytesInRate: 0,
      bytesOutRate: 0,
      rateHistory: []
    });
  }
  
  // Handle data from client
  clientSocket.on('data', (data) => {
    // Skip processing if socket is already being closed
    if (socketClosed) return;
    
    try {
      // Quick check if the connection is still valid
      if (security.checkIPBlacklist(clientIp) && !security.isWhitelisted(clientIp) && !security.isActiveTrustedUser(clientIp)) {
        safelyCloseSocket(clientSocket, 'blacklisted');
        return;
      }
      
      // Track bytes from client
      bytesFromClient += data.length;
      updateIpDataUsage(clientIp, data.length, 0);
      
      // If we already have a backend connection, just forward the data
      if (backendSocket) {
        backendSocket.write(data);
        return;
      }
      
      // Collect the data
      buffer = Buffer.concat([buffer, data]);
      
      // Check if we have a complete HTTP header
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        // Not enough data yet
        return;
      }
      
      // Extract the HTTP header
      const header = buffer.slice(0, headerEnd).toString();
      
      // Extract User-Agent if present (for tracking only)
      const userAgentMatch = header.match(/User-Agent:\s+([^\r\n]+)/i);
      const userAgent = userAgentMatch ? userAgentMatch[1] : null;
      security.trackUserAgent(clientIp, userAgent);
      
      // Check for version
      if (!version) {
        // Check URL path for version
        if (header.includes('/v4')) {
          version = 'v4';
        } else if (header.includes('/v3')) {
          version = 'v3';
        } else {
          version = 'v3'; // Default to v3
        }
        
        log(`Detected version: ${version} for connection ${clientId}`);
      }
      
      // Check authentication
      if (!authenticated) {
        const authMatch = header.match(/Authorization:\s+([^\r\n]+)/i);
        const password = authMatch ? authMatch[1].replace('Bearer ', '') : null;
        
        if (!password || password !== config.proxy.password) {
          log(`Invalid authentication from ${clientSocket.remoteAddress}, closing`);
          const response = 'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n';
          clientSocket.write(response);
          clientSocket.end();
          return;
        }
        
        authenticated = true;
        log(`Client authenticated, establishing tunnel to ${version} backend`);
        
        // Add this IP to trusted active users since they've successfully authenticated
        security.addTrustedActiveUser(clientIp);
      }
      
      // Create connection to backend
      const backend = config.lavalink[version];
      const backendAddress = `${backend.host}:${backend.port}`;
      
      backendSocket = net.createConnection({
        host: backend.host,
        port: backend.port
      }, () => {
        log(`TCP tunnel established to ${backendAddress} for connection ${clientId}`);
        
        // Add to connection tracking
        connectionDetails.set(clientId, {
          clientAddress,
          clientIp,
          backend: backendAddress,
          version,
          startTime: new Date(),
          bytesIn: bytesFromClient,
          bytesOut: 0
        });
        
        // Increment active connections counter
        updateConnectionCounter(1);
        
        // Send the buffered data to the backend safely
        try {
          backendSocket.write(buffer);
        } catch (err) {
          logError(`Error sending initial data to backend for ${clientId}: ${err.message}`, err);
          safelyCloseSocket(backendSocket, 'initial write error');
          safelyCloseSocket(clientSocket, 'initial backend error');
        }
      });
      
      // Set timeout for backend socket too
      backendSocket.setTimeout(120000); // 2 minutes timeout
      backendSocket.on('timeout', () => {
        log(`Backend connection timeout for ${clientId}`);
        safelyCloseSocket(backendSocket, 'backend timeout');
      });
      
      // Handle data flowing from backend to client with better error handling
      backendSocket.on('data', (data) => {
        try {
          // Skip if client socket is closed
          if (socketClosed || clientSocket.destroyed) return;
          
          bytesToClient += data.length;
          
          // Update connection details
          if (connectionDetails.has(clientId)) {
            const info = connectionDetails.get(clientId);
            info.bytesOut += data.length;
            connectionDetails.set(clientId, info);
          }
          
          // Update IP usage data
          updateIpDataUsage(clientIp, 0, data.length);
          
          // Send data to client safely
          if (!clientSocket.destroyed) {
            try {
              clientSocket.write(data);
            } catch (err) {
              // If we can't write to the client, close both sockets
              logError(`Error sending backend data to client for ${clientId}: ${err.message}`, err);
              safelyCloseSocket(clientSocket, 'client write error');
              safelyCloseSocket(backendSocket, 'client write failed');
            }
          }
        } catch (err) {
          // Catch any other errors in backend data handling
          logError(`Error handling backend data for ${clientId}: ${err.message}`, err);
          safelyCloseSocket(backendSocket, 'backend data error');
          safelyCloseSocket(clientSocket, 'backend data error');
        }
      });
      
      // Handle errors with the backend connection with better handling
      backendSocket.on('error', (err) => {
        // Log but don't crash for common errors
        if (err.code === 'ECONNRESET' || err.code === 'EPIPE') {
          log(`Backend connection reset for ${clientId}`);
        } else {
          logError(`Backend connection error for ${clientId}: ${err.message}`, err);
        }
        
        // Safely close both sockets
        safelyCloseSocket(backendSocket, 'backend error');
        if (!socketClosed) {
          safelyCloseSocket(clientSocket, 'backend failure');
        }
      });
      
      // Handle backend connection close
      backendSocket.on('close', () => {
        log(`Backend connection closed for ${clientId}`);
        
        // Update connection tracking
        if (connectionDetails.has(clientId)) {
          connectionDetails.delete(clientId);
          
          // Update the connection counter
          updateConnectionCounter(-1);
        }
        
        // Safely close client socket if it's still open
        if (!socketClosed) {
          safelyCloseSocket(clientSocket, 'backend closed');
        }
      });
    } catch (err) {
      // Catch any errors in the data handling
      logError(`Error handling client data for ${clientId}: ${err.message}`, err);
      safelyCloseSocket(clientSocket, 'data handling error');
    }
  });
  
  // Handle client errors - modified with safe socket handling
  clientSocket.on('error', (err) => {
    // Ignore ECONNRESET errors - these are normal during DDoS
    if (err.code === 'ECONNRESET') {
      log(`Client connection reset for ${clientId}`);
    } else {
      logError(`Client connection error for ${clientId}: ${err.message}`, err);
    }
    
    socketClosed = true;
    
    // Safely end backend socket
    if (backendSocket && !backendSocket.destroyed) {
      safelyCloseSocket(backendSocket, 'client error');
    }
  });
  
  // Handle client close
  clientSocket.on('close', () => {
    log(`Client connection closed for ${clientId}`);
    socketClosed = true;
    
    // Check if we need to update the counter
    if (connectionDetails.has(clientId)) {
      connectionDetails.delete(clientId);
      updateConnectionCounter(-1);
    }
    
    // Safely close backend socket
    if (backendSocket && !backendSocket.destroyed) {
      safelyCloseSocket(backendSocket, 'client closed');
    }
    
    // Update IP usage statistics for closed connections
    if (ipDataUsage.has(clientIp)) {
      const usage = ipDataUsage.get(clientIp);
      usage.connections = Math.max(0, usage.connections - 1);
      ipDataUsage.set(clientIp, usage);
    }
  });
  
  // Add timeout to automatically close idle connections
  clientSocket.setTimeout(60000); // 1 minute timeout
  clientSocket.on('timeout', () => {
    log(`Client connection timeout for ${clientId}`);
    safelyCloseSocket(clientSocket, 'timeout');
  });
});

// Handle server errors
server.on('error', (err) => {
  logError(`Server error: ${err.message}`, err);
});

// Start the server
server.listen(config.proxy.port, config.proxy.host, () => {
  log(`Lavalink TCP Proxy running on ${config.proxy.host}:${config.proxy.port}`);
  log(`Backend v3: ${config.lavalink.v3.host}:${config.lavalink.v3.port}`);
  log(`Backend v4: ${config.lavalink.v4.host}:${config.lavalink.v4.port}`);
});

// Add an emergency recovery function that can be called periodically
function emergencyRecovery() {
  try {
    const memoryUsage = process.memoryUsage();
    const heapUsedMB = Math.round(memoryUsage.heapUsed / 1024 / 1024);
    const rssMB = Math.round(memoryUsage.rss / 1024 / 1024);
    
    log(`System status check - Memory: ${heapUsedMB}MB (heap) / ${rssMB}MB (total) - Active connections: ${activeConnections}`);
    
    // Check for memory issues - adjusted for 1GB heap
    if (heapUsedMB > 800 || rssMB > 1500) { // 80% of 1GB heap or 1.5GB total memory
      log(`CRITICAL: High memory usage detected - forcing aggressive cleanup`);
      
      // Force close some connections if we have too many
      if (activeConnections > 100) {
        log(`Closing excess connections to recover resources`);
        let closed = 0;
        const maxToClose = Math.floor(activeConnections * 0.2); // Close up to 20% of connections
        
        // Find non-whitelisted connections to close
        connectionDetails.forEach((info, id) => {
          if (closed >= maxToClose) return;
          
          const ip = info.clientIp;
          // Don't close whitelisted or trusted connections
          if (!security.isWhitelisted(ip) && !security.isActiveTrustedUser(ip)) {
            // Find and close the corresponding socket (this is approximate as we don't store the socket)
            server.getConnections((err, count) => {
              if (err) return;
              log(`Emergency closing connection ${id} from ${ip} to free resources`);
            });
            
            // Remove from tracking
            connectionDetails.delete(id);
            updateConnectionCounter(-1);
            closed++;
          }
        });
        
        log(`Emergency closed ${closed} connections`);
      }
      
      // Try to force garbage collection
      if (global.gc) {
        log(`Forcing garbage collection`);
        global.gc();
      }
    }
  } catch (err) {
    logError(`Error in emergency recovery: ${err.message}`, err);
  }
}

// Run the emergency recovery every 30 seconds
setInterval(emergencyRecovery, 30000);

// Add a connection rate limiter to the server
let connectionCounter = 0;
let lastConnectionReset = Date.now();
const MAX_CONNECTIONS_PER_SECOND = 50; // Adjust based on your server capacity

// Add a connection rate limiter to the server itself
const originalCreateServer = server.on;
server.on = function(event, listener) {
  if (event === 'connection') {
    const wrappedListener = function(socket) {
      // Rate limit new connections during high load
      const now = Date.now();
      
      // Reset counter every second
      if (now - lastConnectionReset > 1000) {
        connectionCounter = 0;
        lastConnectionReset = now;
      }
      
      // Increment counter
      connectionCounter++;
      
      // If we're over the limit and not in the first second of operation
      if (connectionCounter > MAX_CONNECTIONS_PER_SECOND && process.uptime() > 1) {
        // Drop connection immediately to preserve resources
        socket.destroy();
        return;
      }
      
      // Call original listener
      listener.call(this, socket);
    };
    
    return originalCreateServer.call(this, event, wrappedListener);
  }
  
  return originalCreateServer.call(this, event, listener);
};

// Define app version
const APP_VERSION = '2.0.0'; 