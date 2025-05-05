// Load environment variables
require('dotenv').config();

// Configuration object
const config = {
  proxy: {
    host: process.env.PROXY_HOST || '0.0.0.0',
    port: parseInt(process.env.PROXY_PORT || '2345', 10),
    webPort: parseInt(process.env.WEB_PORT || '2346', 10),
    password: process.env.PROXY_PASSWORD || 'DevamOP',
  },
  // Backend server configuration
  lavalink: {
    v3: {
      host: process.env.LAVALINK_V3_HOST || '127.0.0.1',
      port: parseInt(process.env.LAVALINK_V3_PORT || '8806', 10),
      status: "unknown",      // Status of the backend
      lastChecked: null,      // Last health check time
      responseTime: null      // Response time in ms
    },
    v4: {
      host: process.env.LAVALINK_V4_HOST || '127.0.0.1',
      port: parseInt(process.env.LAVALINK_V4_PORT || '8807', 10),
      status: "unknown",      // Status of the backend
      lastChecked: null,      // Last health check time
      responseTime: null      // Response time in ms
    }
  },
  // Database configuration
  database: {
    dir: process.env.DATABASE_DIR || './database',
    connectionDb: process.env.CONNECTION_DB || 'connections.json',
    ipUsageDb: process.env.IP_USAGE_DB || 'ip_usage.json',
    backendStatusDb: process.env.BACKEND_STATUS_DB || 'backend_status.json',
    securityLogDb: process.env.SECURITY_LOG_DB || 'security_log.json',
    ipBlacklistDb: process.env.IP_BLACKLIST_DB || 'ip_blacklist.json'
  },
  // Rate tracking configuration
  rateTracking: {
    interval: parseInt(process.env.RATE_TRACKING_INTERVAL || '5000', 10),
    historyLength: parseInt(process.env.RATE_HISTORY_LENGTH || '12', 10)
  },
  // Logging configuration
  logging: {
    dir: process.env.LOG_DIR || './logs',
    level: process.env.LOG_LEVEL || 'info',
    securityLevel: process.env.SECURITY_LOG_LEVEL || 'debug',
    maxLogs: parseInt(process.env.MAX_LOG_FILES || '30', 10), // Maximum number of log files to keep
    maxSize: parseInt(process.env.MAX_LOG_SIZE || '10', 10) * 1024 * 1024, // Maximum log size in MB
    rotateDaily: process.env.ROTATE_LOGS_DAILY === 'true' || true,
    formatTimestamps: process.env.FORMAT_TIMESTAMPS === 'true' || true
  },
  // Health check configuration
  healthCheck: {
    interval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '60000', 10),
    timeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT || '3000', 10)
  },
  // Security configuration
  security: {
    maxConnectionsPerIP: parseInt(process.env.MAX_CONNECTIONS_PER_IP || '10', 10),
    maxConnectionsTotal: parseInt(process.env.MAX_CONNECTIONS_TOTAL || '100', 10),
    connectionRateLimit: parseInt(process.env.CONNECTION_RATE_LIMIT || '5', 10), // Connections per second
    rateWindowMs: parseInt(process.env.RATE_WINDOW_MS || '10000', 10), // 10 seconds window for rate limiting
    autoBlacklist: process.env.AUTO_BLACKLIST === 'true' || false,
    blacklistThreshold: parseInt(process.env.BLACKLIST_THRESHOLD || '5', 10), // Number of violations before blacklisting
    blacklistDuration: parseInt(process.env.BLACKLIST_DURATION || '86400', 10) * 1000, // Duration in ms (default 24h)
    trackUserAgents: process.env.TRACK_USER_AGENTS === 'true' || true,
    blockUnknownUserAgents: process.env.BLOCK_UNKNOWN_USER_AGENTS === 'true' || false,
    logFullHeaders: process.env.LOG_FULL_HEADERS === 'true' || false,
    suspiciousDataRateThreshold: parseInt(process.env.SUSPICIOUS_DATA_RATE || '10', 10) * 1024 * 1024, // 10 MB/s
    securityPassword: process.env.SECURITY_PASSWORD || 'AdminSecure123' // Separate password for security dashboard
  }
};

module.exports = config; 