// Load environment variables
require('dotenv').config();

// Environment detection
const isProd = process.env.NODE_ENV === 'production';
const isDev = process.env.NODE_ENV === 'development';

// Configuration object
const config = {
  proxy: {
    host: process.env.PROXY_HOST || '0.0.0.0',
    port: parseInt(process.env.PROXY_PORT || '6923', 10),
    publicUrl: process.env.PUBLIC_URL || '',
    webPort: parseInt(process.env.WEB_PORT || '6980', 10),
    password: process.env.PROXY_PASSWORD || 'DevamOP',
    enableProxyProtocol: process.env.ENABLE_PROXY_PROTOCOL === 'true' || false,
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
    ipBlacklistDb: process.env.IP_BLACKLIST_DB || 'ip_blacklist.json',
    ipWhitelistDb: process.env.IP_WHITELIST_DB || 'ip_whitelist.json',
    trustedUsersDb: process.env.TRUSTED_USERS_DB || 'trusted_users.json'
  },
  // Rate tracking configuration
  rateTracking: {
    interval: parseInt(process.env.RATE_TRACKING_INTERVAL || '5000', 10),
    historyLength: parseInt(process.env.RATE_HISTORY_LENGTH || '12', 10)
  },
  // Logging configuration
  logging: {
    dir: process.env.LOG_DIR || './logs',
    level: isDev ? 'debug' : (process.env.LOG_LEVEL || 'info'),
    securityLevel: isDev ? 'debug' : (process.env.SECURITY_LOG_LEVEL || 'info'),
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
    maxConnectionsTotal: process.env.MAX_CONNECTIONS_TOTAL === 'unlimited' ? Infinity : parseInt(process.env.MAX_CONNECTIONS_TOTAL || '200', 10),
    connectionRateLimit: parseInt(process.env.CONNECTION_RATE_LIMIT || '5', 10), // Connections per second
    rateWindowMs: parseInt(process.env.RATE_WINDOW_MS || '10000', 10), // 10 seconds window for rate limiting
    autoBlacklist: process.env.AUTO_BLACKLIST === 'true' || (isProd ? true : false), // Enable in production by default
    blacklistThreshold: parseInt(process.env.BLACKLIST_THRESHOLD || '5', 10), // Number of violations before blacklisting
    blacklistDuration: parseInt(process.env.BLACKLIST_DURATION || '86400', 10) * 1000, // Duration in ms (default 24h)
    trackUserAgents: process.env.TRACK_USER_AGENTS === 'true' || true,
    blockUnknownUserAgents: process.env.BLOCK_UNKNOWN_USER_AGENTS === 'true' || false,
    logFullHeaders: process.env.LOG_FULL_HEADERS === 'true' || isDev,
    suspiciousDataRateThreshold: parseInt(process.env.SUSPICIOUS_DATA_RATE || '10', 10) * 1024 * 1024, // 10 MB/s
    securityPassword: process.env.SECURITY_PASSWORD || 'AdminSecure123', // Separate password for security dashboard
    
    // DDoS protection settings
    ddosProtection: {
      enabled: process.env.DDOS_PROTECTION === 'true' || true, // Enable by default
      burstThreshold: parseInt(process.env.BURST_THRESHOLD || '5', 10), // Number of rapid connections to consider a burst
      burstBlacklistThreshold: parseInt(process.env.BURST_BLACKLIST_THRESHOLD || '15', 10), // Burst size to trigger blacklist
      burstIntervalMs: parseInt(process.env.BURST_INTERVAL_MS || '200', 10), // Time in ms to consider connections part of a burst
      burstResetMs: parseInt(process.env.BURST_RESET_MS || '5000', 10), // Time in ms to reset burst counter after normal behavior
      temporaryBlockDuration: parseInt(process.env.TEMP_BLOCK_DURATION || '300', 10) * 1000, // 5 minutes by default
      maxPayloadSize: parseInt(process.env.MAX_PAYLOAD_SIZE || '1', 10) * 1024 * 1024, // 1MB max payload size
      validateWebSocketFrames: process.env.VALIDATE_WS_FRAMES === 'true' || true, // Validate websocket frames by default
      // Advanced packet dropping options to prevent TCP jamming
      aggressivePacketDropping: process.env.AGGRESSIVE_PACKET_DROPPING === 'true' || true, // Enable by default
      packetDropDuration: parseInt(process.env.PACKET_DROP_DURATION || '30', 10) * 1000, // Duration to continue dropping packets
      progressiveDropping: process.env.PROGRESSIVE_DROPPING === 'true' || true, // Progressive dropping based on burst intensity
      minimumBurstForDropping: parseInt(process.env.MIN_BURST_FOR_DROPPING || '2', 10), // Start dropping packets after this many bursts
      
      // New CPU protection settings
      cpuProtection: {
        enabled: process.env.CPU_PROTECTION === 'true' || true, // Enable by default
        highLoadThreshold: parseInt(process.env.HIGH_LOAD_THRESHOLD || '70', 10), // CPU percentage considered high load
        extremeLoadThreshold: parseInt(process.env.EXTREME_LOAD_THRESHOLD || '90', 10), // CPU percentage considered extreme load
        sampleIntervalMs: parseInt(process.env.CPU_SAMPLE_INTERVAL || '5000', 10), // How often to sample CPU usage
        adaptiveThrottling: process.env.ADAPTIVE_THROTTLING === 'true' || true, // Adjust throttling based on load
        minConnAcceptProbability: parseFloat(process.env.MIN_ACCEPT_PROBABILITY || '0.1') // Minimum probability of accepting connection under load
      },
      
      // Trusted user settings
      trustedUsers: {
        activityWindowMinutes: parseInt(process.env.TRUSTED_ACTIVITY_WINDOW || '10', 10), // Minutes before trusted user becomes inactive
        connectionThreshold: parseInt(process.env.TRUSTED_CONNECTION_THRESHOLD || '2', 10), // Connections needed to become trusted
        priorityLevels: parseInt(process.env.TRUSTED_PRIORITY_LEVELS || '10', 10), // Maximum priority level for trusted users
        persistToDisk: process.env.PERSIST_TRUSTED_USERS === 'true' || true // Save trusted users between restarts
      }
    }
  },
  // Runtime environment info
  runtime: {
    startTime: new Date(),
    isProd: isProd,
    isDev: isDev
  }
};

module.exports = config; 