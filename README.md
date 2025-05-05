# LavaBridge v2.0

A TCP tunneling proxy that routes clients to the appropriate Lavalink v3 or v4 server based on request headers or URL path.

## Features

- Simple authentication layer
- Automatic routing to Lavalink v3 or v4 backends
- Low-level TCP tunneling for minimal overhead
- Health check endpoint
- Detailed logging
- Web interface for connection monitoring
- TCP data usage tracking and visualization
- Real-time data rate (bytes/second) monitoring
- JSON-based persistent storage
- Configuration via environment variables
- Security monitoring with IP blacklisting
- Search and sort functionality for connection tables
- Multiple data rate display formats (bytes/s, bits/s, packets/s)
- Modern UI with connection URL display and copy functionality
- Enhanced DDoS protection:
  - Connection burst detection
  - Payload size limiting
  - Automatic temporary blocking for suspicious behavior
  - Recursive loop protection in security logging
  - Configurable thresholds and limits
  - Improved error handling for "write after end" and ECONNRESET errors
  - Memory optimization with 1GB heap limit by default
- Connection management:
  - Automatic connection cleanup on restart
  - Active user protection during DDoS attacks
  - Never drops packets from active trusted users
  - Whitelist verification and validation on startup

## How It Works

This proxy creates a direct TCP tunnel between clients and backend Lavalink servers:

1. Client connects to the proxy
2. Proxy authenticates the connection using a password
3. Proxy determines whether to route to v3 or v4 backend based on:
   - Path in URL (e.g., `/v3/` or `/v4/`)
   - Lavalink-Version header (if present)
   - Default fallback to v3
4. Proxy establishes a direct TCP tunnel to the appropriate backend
5. Data flows directly between client and backend with minimal overhead
6. Connection, data usage, and data rate statistics are tracked and displayed in the web interface
7. Stats are persisted to JSON files for data retention between restarts
8. Security module monitors for suspicious activities and enforces rate limiting
9. DDoS protection detects and mitigates connection bursts and malicious patterns

The proxy also supports the HAProxy PROXY protocol, allowing it to receive connections through a load balancer or reverse proxy while preserving the original client IP addresses.

## Requirements

- Node.js 14.x or higher
- Access to Lavalink v3 and v4 servers

## Installation

1. Clone this repository
   ```
   git clone https://github.com/devamop69/LavaBridge.git
   cd LavaBridge
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Create a `.env` file with your configuration (see env.sample for all available options):
   ```
   # Copy the sample environment file
   cp env.sample .env
   
   # Edit the file with your preferred settings
   nano .env
   ```

## Usage

1. Start the proxy server
   ```
   npm start
   ```

2. For development with auto-restart:
   ```
   npm run dev
   ```

3. Connect your Lavalink clients to the proxy using this format:
   - For v3 clients: `ws://proxy-host:6923/v3`
   - For v4 clients: `ws://proxy-host:6923/v4`

4. Access the web interface at:
   ```
   http://proxy-host:6980
   ```

## Web Interface

The proxy includes a web interface that provides real-time monitoring of:

- **Connection Monitor** (`/`):
  - Connection URL display with copy functionality
  - Modern UI with DevamOP branding
  - Total active connections
  - Number of v3 and v4 connections
  - Detailed information for each connection
  - Data usage per connection (in/out)
  - Real-time data rates with color-coded indicators
  - Search functionality for filtering connections
  - Sortable columns for better data organization
  - Multiple data rate display formats (bytes/s, bits/s, packets/s)

- **Health Monitor** (`/health`):
  - System uptime and version
  - Memory usage statistics
  - Backend server configurations
  - Connection summary
  - Backend server health status with response times

- **Data Usage Monitor** (`/data-usage`):
  - Per-IP data usage statistics
  - Inbound and outbound traffic visualization
  - Total data transferred
  - Current data transfer rates
  - Color-coded indicators for high bandwidth usage
  - Last activity timestamps
  - Search and sort functionality for IP addresses

- **Security Dashboard** (`/security`):
  - Password-protected security controls
  - IP blacklist management with temporary or permanent bans
  - IP whitelist management for trusted addresses
  - Security violation monitoring
  - User agent tracking
  - Manual IP blacklisting controls
  - Connection burst patterns visualization

The web interface automatically refreshes every 5 seconds and can be manually refreshed as needed.

## Client Configuration Examples

### Discord.js with Erela.js (v3)
```js
// Initialize the Manager
const manager = new Manager({
  nodes: [
    {
      host: "your-proxy-host",
      port: 6923,
      password: "DevamOP",
      secure: false,
      identifier: "v3Node",
      retryAmount: 5,
      retryDelay: 1000,
    },
  ],
  send: (id, payload) => {
    const guild = client.guilds.cache.get(id);
    if (guild) guild.shard.send(payload);
  },
});
```

### Discord.js with Shoukaku (v4)
```js
const { Shoukaku, Connectors } = require('shoukaku');

// Initialize the Shoukaku instance
const shoukaku = new Shoukaku(new Connectors.DiscordJS(client), {
  servers: [
    {
      name: 'v4Node',
      url: 'your-proxy-host:6923/v4',  // Note the /v4 path
      auth: 'DevamOP',
      secure: false,
    }
  ],
  options: {
    // Your options
  }
});
```

## Configuration

The proxy can be configured entirely through environment variables:

### Proxy Settings
- `PROXY_HOST`: Host to bind the proxy server (default: 0.0.0.0)
- `PROXY_PORT`: Port for the proxy server (default: 6923)
- `PROXY_PASSWORD`: Password for the proxy server (default: DevamOP)
- `WEB_PORT`: Port for the web interface (default: 6980)
- `ENABLE_PROXY_PROTOCOL`: Enable support for HAProxy PROXY protocol (default: false)

### Backend Settings
- `LAVALINK_V3_HOST`: Hostname/IP for the Lavalink v3 server
- `LAVALINK_V3_PORT`: Port for the Lavalink v3 server
- `LAVALINK_V4_HOST`: Hostname/IP for the Lavalink v4 server
- `LAVALINK_V4_PORT`: Port for the Lavalink v4 server

### Data Storage Settings
- `DATABASE_DIR`: Directory to store the JSON database files (default: ./database)
- `CONNECTION_DB`: Filename for connection data (default: connections.json)
- `IP_USAGE_DB`: Filename for IP usage data (default: ip_usage.json)
- `BACKEND_STATUS_DB`: Filename for backend status data (default: backend_status.json)
- `SECURITY_LOG_DB`: Filename for security events (default: security_log.json)
- `IP_BLACKLIST_DB`: Filename for IP blacklist (default: ip_blacklist.json)
- `IP_WHITELIST_DB`: Filename for IP whitelist of trusted addresses (default: ip_whitelist.json)

### Rate Tracking Settings
- `RATE_TRACKING_INTERVAL`: Interval in ms to update data rates (default: 5000)
- `RATE_HISTORY_LENGTH`: Number of rate history points to keep (default: 12)

### Security Settings
- `MAX_CONNECTIONS_PER_IP`: Maximum allowed connections from a single IP (default: 10)
- `MAX_CONNECTIONS_TOTAL`: Maximum allowed total connections (default: 100). Set to 'unlimited' for no limit.
- `CONNECTION_RATE_LIMIT`: Maximum new connections per second per IP (default: 5)
- `RATE_WINDOW_MS`: Time window for rate limiting in milliseconds (default: 10000)
- `AUTO_BLACKLIST`: Whether to automatically blacklist IPs that violate security rules (default: false)
- `BLACKLIST_THRESHOLD`: Number of violations before auto-blacklisting (default: 5)
- `BLACKLIST_DURATION`: Duration of auto-blacklisting in seconds (default: 86400 - 24 hours)
- `TRACK_USER_AGENTS`: Whether to track client user agents (default: true)
- `BLOCK_UNKNOWN_USER_AGENTS`: Whether to block connections with no user agent (default: false)
- `LOG_FULL_HEADERS`: Whether to log complete HTTP headers (default: false)
- `SUSPICIOUS_DATA_RATE`: Threshold for suspicious data rate in MB/s (default: 10)
- `SECURITY_PASSWORD`: Password for accessing the security dashboard (default: AdminSecure123)

### DDoS Protection Settings
- `DDOS_PROTECTION`: Enable DDoS protection features (default: true)
- `BURST_THRESHOLD`: Number of rapid connections to consider a burst (default: 5)
- `BURST_BLACKLIST_THRESHOLD`: Burst size to trigger automatic blacklisting (default: 15)
- `BURST_INTERVAL_MS`: Time in ms to consider connections part of a burst (default: 200)
- `BURST_RESET_MS`: Time in ms to reset burst counter after normal behavior (default: 5000)
- `TEMP_BLOCK_DURATION`: Duration in seconds for temporary blocks (default: 300)
- `MAX_PAYLOAD_SIZE`: Maximum payload size in MB (default: 1)
- `VALIDATE_WS_FRAMES`: Validate WebSocket frames for protocol compliance (default: true)
- `AGGRESSIVE_PACKET_DROPPING`: Enable aggressive packet dropping to prevent TCP jamming (default: true)
- `PACKET_DROP_DURATION`: Duration in seconds to drop packets after attack detection (default: 30)
- `PROGRESSIVE_DROPPING`: Enable progressive packet dropping based on burst intensity (default: true)
- `MIN_BURST_FOR_DROPPING`: Minimum burst count before starting progressive packet dropping (default: 2)

## How Version Detection Works

The proxy determines which backend to route to based on these factors (in order):

1. URL path containing `/v3/` or `/v4/`
2. `Lavalink-Version` header with value `3` or `4`
3. Default fallback to v3 if version cannot be determined

## Data Usage Tracking

The proxy tracks and displays TCP data usage with the following features:

- Real-time monitoring of bytes transferred in both directions
- Per-connection data usage statistics
- Aggregated data usage by IP address
- Visual indicators for relative bandwidth consumption
- Human-readable formatting of data sizes
- Automatic refresh of statistics
- Persistence between restarts via JSON storage
- Search and sorting capabilities for data analysis

## Data Rate Monitoring

The proxy provides real-time data rate tracking with multiple display options:

- Current data transfer rates for each connection
- Aggregated rates by IP address
- Multiple data rate formats:
  - Bytes per second (KB/s, MB/s)
  - Bits per second (Kbps, Mbps)
  - Packets per second (pps, Kpps)
- Color-coded indicators for different bandwidth levels:
  - Normal rates (< 100 KB/s) displayed in default color
  - Medium rates (100 KB/s - 1 MB/s) highlighted in orange
  - High rates (> 1 MB/s) highlighted in red
- Historical rate tracking (last 60 seconds)
- Per-connection and per-IP rate statistics
- Automatic rate calculations every 5 seconds

## Security Features

The proxy includes comprehensive security features:

- Connection rate limiting to prevent abuse
- Per-IP connection limits
- Total connection limiting
- Automatic or manual IP blacklisting
- Permanent IP whitelisting for trusted addresses
- Packet dropping for blacklisted IPs (connections and data packets)
- Active user protection that ensures users who have successfully authenticated maintain connection during attacks:
  - Trusted active users are automatically tracked after successful authentication
  - Active users are exempt from blacklist checks once authenticated
  - Active users never have their packets dropped during DDoS attacks
  - Active users bypass rate limits and connection limits
  - Activity tracking keeps user status current (10 minute activity window)
- Connection database cleanup on server restart:
  - All connection tracking is reset on restart to prevent stale connections
  - Whitelist entries are verified on startup
  - Invalid whitelist entries are automatically cleaned and reported
- Anti-TCP jamming protection with progressive packet dropping
- Security violation monitoring and logging
- User agent tracking and analysis
- Suspicious data rate detection
- Password-protected security dashboard
- Blacklist management with temporary or permanent bans
- Detailed security logging
- DDoS protection mechanisms:
  - Connection burst detection and mitigation
  - Active attack packet dropping (silently discards packets during attack)
  - Progressive packet dropping based on attack intensity
  - Trusted active user whitelisting during attacks
  - Permanent IP whitelist that bypasses all packet dropping
  - Prevention of TCP connection jamming during active attacks
  - Automatic temporary blocking for suspicious patterns
  - Payload size limiting to prevent resource exhaustion
  - Recursive logging protection to prevent stack overflows
  - Configurable thresholds for different attack vectors
  - Optimized memory usage for tracking data

## UI Features

The web interface includes various user experience enhancements:

- Dark mode support across all pages
- Theme preference saved in browser
- System theme preference detection
- Sortable data tables
- Search functionality for connections and IPs
- Real-time data updates
- Visual indicators for important metrics
- Responsive design for desktop and mobile
- Multiple data rate display options
- Connection URL display with one-click copy feature
- Modern glass UI elements with gradient colors
- Animated hover effects for interactive elements

## DDoS Protection and High-Load Handling

LavaBridge includes comprehensive protection against DDoS attacks and mechanisms to handle high-load scenarios effectively.

### Protection Mechanisms

- **Connection Burst Detection**: Automatically identifies and blocks rapid connection attempts from the same IP
- **Trusted User System**: Legitimate users maintain access during attacks through behavior-based trust scoring
- **CPU Load Management**: Dynamically adjusts connection acceptance based on server load
- **Aggressive Packet Dropping**: Prevents TCP socket exhaustion during SYN flood attacks
- **Memory Optimization**: Periodic cleanup of data structures and emergency recovery during high load

### Handling "write after end" and ECONNRESET Errors

The proxy implements robust error handling for common issues during DDoS attacks:

1. **Socket Error Handling**: All socket operations are wrapped in try/catch blocks
2. **Safe Socket Closing**: Dedicated functions ensure sockets are closed properly even during attacks
3. **Error Logging**: Structured logging helps identify attack patterns
4. **Rate Limiting**: Reduces connection attempts from problematic sources

### Memory Optimization

To prevent memory-related crashes during prolonged attacks:

1. **Increased Heap Size**: Server starts with 1GB heap limit by default
2. **Garbage Collection**: Periodic garbage collection frees unused resources
3. **Data Structure Cleanup**: Automatically removes expired entries from tracking maps
4. **Connection Limiting**: Prevents memory exhaustion from too many simultaneous connections

### Quick Configuration Guide

For production environments facing frequent attacks:

```
# Essential DDoS protection settings
DDOS_PROTECTION=true
AUTO_BLACKLIST=true
AGGRESSIVE_PACKET_DROPPING=true
MAX_CONNECTIONS_TOTAL=200
HIGH_LOAD_THRESHOLD=70
```

For running with increased memory during attacks:

```bash
# 2GB heap allocation
NODE_OPTIONS="--max-old-space-size=2048 --expose-gc" node start.js
```

For monitoring during attacks:

```bash
# Check security logs
grep "Fast rejection" logs/security-*.log

# Monitor memory usage
ps -o pid,rss,command | grep node
```

### Advanced DDoS Protection Strategies

#### IP Reputation System

Enable the IP reputation system to track and score client behavior:

```
IP_REPUTATION_ENABLED=true
IP_REPUTATION_BAD_SCORE_THRESHOLD=-10
IP_REPUTATION_GOOD_SCORE_THRESHOLD=5
```

#### Multiple Layer Defense

For best protection, implement multiple layers:

1. **Cloud-level DDoS protection** (Cloudflare, AWS Shield)
2. **Hardware firewall** with connection rate limiting
3. **LavaBridge built-in protection**
4. **Application-level validation**

#### Performance Tuning

Fine-tune Node.js for high-performance scenarios:

```bash
# Production performance optimizations
NODE_ENV=production
NODE_OPTIONS="--max-old-space-size=4096 --expose-gc --max-http-header-size=16384 --no-warnings --max-semi-space-size=64"
```

## License

MIT 