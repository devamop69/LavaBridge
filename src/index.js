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

// Keep track of active connections
let activeConnections = 0;

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

// Set up interval for data rate calculations
setInterval(calculateDataRates, RATE_TRACKING_INTERVAL);

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
    name: 'Lavalink Proxy',
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
  const violations = [];
  const userAgents = [];
  
  // Process blacklist
  security.getBlacklist().forEach((info, ip) => {
    blacklist.push({
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
    totalViolations: violations.length,
    userAgentsCount: userAgents.length,
    blacklist,
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
  
  // Initialize data counters
  let bytesFromClient = 0;
  let bytesToClient = 0;
  
  log(`New connection from ${clientAddress} (ID: ${clientId})`);
  security.securityLog('info', `New connection`, { ip: clientIp, id: clientId });
  
  // Check for connection bursts (potential DDoS)
  if (security.trackConnectionBurst(clientIp)) {
    security.securityLog('warn', `Rejected connection due to burst pattern detection`, { ip: clientIp, id: clientId });
    clientSocket.end();
    return;
  }
  
  // Function to parse PROXY protocol header
  // PROXY protocol format: "PROXY" + TCP4/TCP6 + client-ip + proxy-ip + client-port + proxy-port + CRLF
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
  
  // Check if IP is blacklisted
  const blacklistInfo = security.checkIPBlacklist(clientIp);
  if (blacklistInfo) {
    security.securityLog('warn', `Rejected blacklisted IP connection`, { 
      ip: clientIp, 
      id: clientId,
      reason: blacklistInfo.reason
    });
    
    clientSocket.end();
    return;
  }
  
  // Check connection rate limit
  if (security.checkRateLimit(clientIp)) {
    security.securityLog('warn', `Rejected rate-limited IP connection`, { ip: clientIp, id: clientId });
    clientSocket.end();
    return;
  }
  
  // Get number of connections from this IP
  const ipConnections = Array.from(connectionDetails.values())
    .filter(conn => conn.clientIp === clientIp).length;
  
  // Check connection limits
  if (!security.checkConnectionLimits(clientIp, activeConnections, ipConnections)) {
    clientSocket.end();
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
  
  // Save IP usage data after any change
  saveIpUsageData();
  
  // Handle data from client
  clientSocket.on('data', (data) => {
    // Check for PROXY protocol header on first data packet
    if (!proxyProtocolComplete && buffer.length === 0) {
      // Only process PROXY protocol if it's enabled in config
      if (config.proxy.enableProxyProtocol) {
        const proxyResult = parseProxyProtocol(data);
        
        if (proxyResult.isProxy) {
          if (!proxyResult.complete) {
            // Incomplete PROXY header, wait for more data
            buffer = Buffer.concat([buffer, data]);
            return;
          }
          
          // Update client information with the original client IP
          const originalIp = proxyResult.originalIp;
          const originalPort = proxyResult.originalPort;
          
          log(`PROXY protocol: Original client IP: ${originalIp}:${originalPort}`);
          
          // Update tracking variables with original client information
          clientIp = originalIp;
          clientAddress = `${originalIp}:${originalPort}`;
          
          // Replace data with remaining data after PROXY header
          data = proxyResult.remainingData;
          
          // Check if the original IP is blacklisted
          const blacklistInfo = security.checkIPBlacklist(clientIp);
          if (blacklistInfo) {
            security.securityLog('warn', `Rejected blacklisted IP connection (via PROXY)`, { 
              ip: clientIp, 
              id: clientId,
              reason: blacklistInfo.reason
            });
            
            clientSocket.end();
            return;
          }
        }
      }
      
      proxyProtocolComplete = true;
    }
    
    // Track bytes from client
    bytesFromClient += data.length;
    updateIpDataUsage(clientIp, data.length, 0);
    
    // Check payload size limits
    if (config.security.ddosProtection && config.security.ddosProtection.enabled) {
      const maxSize = config.security.ddosProtection.maxPayloadSize;
      if (buffer.length + data.length > maxSize) {
        security.securityLog('warn', `Payload size exceeded for IP ${clientIp}`, { 
          ip: clientIp, 
          id: clientId,
          size: buffer.length + data.length,
          maxSize: maxSize
        });
        
        // Close the connection
        clientSocket.end();
        return;
      }
    }
    
    // If connection details exist, update the bytesIn counter and check for suspicious data rates
    if (connectionDetails.has(clientId)) {
      const info = connectionDetails.get(clientId);
      info.bytesIn += data.length;
      
      // Check for suspicious data rates (only if we have enough history)
      if (info.bytesInRate > 0) {
        security.checkSuspiciousDataRate(clientIp, info.bytesInRate);
      }
      
      connectionDetails.set(clientId, info);
    }
    
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
    
    // Log headers if configured
    security.logHeaders(clientIp, header);
    
    // Extract User-Agent if present
    const userAgentMatch = header.match(/User-Agent:\s+([^\r\n]+)/i);
    const userAgent = userAgentMatch ? userAgentMatch[1] : null;
    
    // Track and validate user agent
    if (!security.trackUserAgent(clientIp, userAgent)) {
      clientSocket.end();
      return;
    }
    
    // Check for version and authentication
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
      security.securityLog('debug', `Version detection`, { ip: clientIp, id: clientId, version });
    }
    
    // Check authentication
    if (!authenticated) {
      const authMatch = header.match(/Authorization:\s+([^\r\n]+)/i);
      const password = authMatch ? authMatch[1].replace('Bearer ', '') : null;
      
      if (!password || password !== config.proxy.password) {
        log(`Invalid authentication from ${clientSocket.remoteAddress}, closing`);
        security.securityLog('warn', `Invalid authentication attempt`, { 
          ip: clientIp, 
          id: clientId,
          providedPassword: password ? '(encrypted)' : '(none)' 
        });
        
        // Send 401 Unauthorized and close
        const response = 'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n';
        clientSocket.write(response);
        clientSocket.end();
        return;
      }
      
      authenticated = true;
      log(`Client authenticated, establishing tunnel to ${version} backend`);
      security.securityLog('info', `Client authenticated`, { ip: clientIp, id: clientId, version });
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
        bytesIn: bytesFromClient, // Initial bytes from client
        bytesOut: 0, // No bytes sent to client yet
        bytesInLast: bytesFromClient,
        bytesOutLast: 0,
        bytesInRate: 0,
        bytesOutRate: 0,
        rateHistory: []
      });
      
      // Save the connection data to disk
      saveConnectionData();
      
      // Increment active connections counter
      updateConnectionCounter(1);
      
      // Send the buffered data to the backend
      backendSocket.write(buffer);
    });
    
    // Handle data flowing between pipes
    backendSocket.on('data', (data) => {
      bytesToClient += data.length;
      
      // Update connection details
      if (connectionDetails.has(clientId)) {
        const info = connectionDetails.get(clientId);
        info.bytesOut += data.length;
        connectionDetails.set(clientId, info);
      }
      
      // Update IP usage data
      updateIpDataUsage(clientIp, 0, data.length);
      
      // Send data to client
      if (!clientSocket.destroyed) {
        clientSocket.write(data);
      }
    });
    
    // Handle errors with the backend connection
    backendSocket.on('error', (err) => {
      logError(`Backend connection error for ${clientId}: ${err.message}`, err);
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });
    
    // Handle backend connection close
    backendSocket.on('close', () => {
      log(`Backend connection closed for ${clientId}`);
      
      // Update connection tracking
      if (connectionDetails.has(clientId)) {
        connectionDetails.delete(clientId);
        
        // Save connection data after removal
        saveConnectionData();
        
        // Update the connection counter
        updateConnectionCounter(-1);
      }
      
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });
  });
  
  // Handle client errors
  clientSocket.on('error', (err) => {
    logError(`Client connection error for ${clientId}: ${err.message}`, err);
    if (backendSocket && !backendSocket.destroyed) {
      backendSocket.end();
    }
  });
  
  // Handle client close
  clientSocket.on('close', () => {
    log(`Client connection closed for ${clientId}`);
    
    // Check if we need to update the counter
    // (if backend socket was never established, we didn't increment the counter)
    if (connectionDetails.has(clientId)) {
      connectionDetails.delete(clientId);
      
      // Save connection data after removal
      saveConnectionData();
      
      updateConnectionCounter(-1);
    }
    
    if (backendSocket && !backendSocket.destroyed) {
      backendSocket.end();
    }
    
    // Update IP usage statistics for closed connections
    if (ipDataUsage.has(clientIp)) {
      const usage = ipDataUsage.get(clientIp);
      usage.connections = Math.max(0, usage.connections - 1);
      ipDataUsage.set(clientIp, usage);
      saveIpUsageData();
    }
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