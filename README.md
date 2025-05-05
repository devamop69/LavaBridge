# Lavalink Proxy

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

## Requirements

- Node.js 14.x or higher
- Access to Lavalink v3 and v4 servers

## Installation

1. Clone this repository
   ```
   git clone https://github.com/yourusername/lavalink-proxy.git
   cd lavalink-proxy
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Create a `.env` file with your configuration:
   ```
   # Proxy configuration
   PROXY_HOST=0.0.0.0
   PROXY_PORT=6923
   WEB_PORT=6980
   PROXY_PASSWORD=DevamOP

   # Backend server configuration
   LAVALINK_V3_HOST=192.168.1.72
   LAVALINK_V3_PORT=8806

   LAVALINK_V4_HOST=192.168.1.72
   LAVALINK_V4_PORT=8807

   # Data storage configuration
   DATABASE_DIR=./database
   CONNECTION_DB=connections.json
   IP_USAGE_DB=ip_usage.json
   BACKEND_STATUS_DB=backend_status.json
   SECURITY_LOG_DB=security_log.json
   IP_BLACKLIST_DB=ip_blacklist.json

   # Rate tracking configuration
   RATE_TRACKING_INTERVAL=5000
   RATE_HISTORY_LENGTH=12
   
   # Security configuration
   MAX_CONNECTIONS_PER_IP=10
   MAX_CONNECTIONS_TOTAL=100
   CONNECTION_RATE_LIMIT=5
   RATE_WINDOW_MS=10000
   AUTO_BLACKLIST=false
   BLACKLIST_THRESHOLD=5
   BLACKLIST_DURATION=86400
   TRACK_USER_AGENTS=true
   BLOCK_UNKNOWN_USER_AGENTS=false
   LOG_FULL_HEADERS=false
   SUSPICIOUS_DATA_RATE=10
   SECURITY_PASSWORD=AdminSecure123
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
  - Security violation monitoring
  - User agent tracking
  - Manual IP blacklisting controls

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

### Rate Tracking Settings
- `RATE_TRACKING_INTERVAL`: Interval in ms to update data rates (default: 5000)
- `RATE_HISTORY_LENGTH`: Number of rate history points to keep (default: 12)

### Security Settings
- `MAX_CONNECTIONS_PER_IP`: Maximum allowed connections from a single IP (default: 10)
- `MAX_CONNECTIONS_TOTAL`: Maximum allowed total connections (default: 100)
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
- Security violation monitoring and logging
- User agent tracking and analysis
- Suspicious data rate detection
- Password-protected security dashboard
- Blacklist management with temporary or permanent bans
- Detailed security logging

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

## License

ISC 