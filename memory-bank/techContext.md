# Technical Context: Lavalink Proxy

## Technology Stack

The Lavalink Proxy is built using the following technologies:

- **Node.js**: JavaScript runtime environment for the server
- **net (TCP)**: Native Node.js module for TCP connections
- **Express.js**: Web framework for web interface and API
- **dotenv**: Environment variable loading

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| net | native | TCP client and server implementation |
| express | ^4.18.2 | Web server framework for monitoring interface |
| dotenv | ^16.x | Environment variable loading |
| nodemon | ^3.x | Development auto-restart tool |

## Environment Configuration

All configuration is managed through environment variables:

- **Proxy Settings**:
  - PROXY_HOST: Host to bind the proxy server (default: 0.0.0.0)
  - PROXY_PORT: Port for the proxy server (default: 6923)
  - PROXY_PASSWORD: Password for authentication (default: DevamOP)
  - WEB_PORT: Port for the web interface (default: 6980)
- **Lavalink v3 Settings**: Configured in index.js for v3 backend
- **Lavalink v4 Settings**: Configured in index.js for v4 backend

## Protocol Version Detection

Version detection is based on examining the initial HTTP headers:
- Path containing `/v3/` routes to v3 backend
- Path containing `/v4/` routes to v4 backend
- Default to v3 if no version is specified

## Data Usage Tracking

The proxy implements TCP data tracking with the following features:
- Counts bytes transmitted in both directions for each connection
- Aggregates data usage by client IP address
- Provides human-readable formatting of data sizes
- Visualizes relative bandwidth usage with progress bars
- Maintains real-time statistics for active connections
- Preserves connection counts per IP even after disconnection
- Auto-refreshes visualizations for live monitoring

## Web Interface

The web interface provides:
- Connection statistics dashboard
- Real-time connection monitoring
- TCP data usage tracking and visualization
- Connection details table with:
  - Client address
  - Backend server
  - Version (v3/v4)
  - Connection time
  - Uptime
  - Data usage (inbound/outbound)

## Web Pages
- **/* (root)**: Connection monitor showing active connections
- **/health**: System health dashboard with memory and uptime information
- **/data-usage**: Data usage visualization by IP address

## Development Environment

- Node.js 14.x or higher
- NPM for package management
- Environment variables through .env file

## Deployment Considerations

- Can be deployed as a standalone Node.js application
- Compatible with Docker containerization
- Requires network access to both Lavalink v3 and v4 servers
- Web interface should be secured or restricted to trusted networks
- Low resource usage (CPU/memory)
- Data tracking introduces minimal overhead

## Performance Characteristics

- Minimal latency overhead (direct TCP tunneling)
- Lightweight memory footprint
- Connection tracking has negligible impact on performance
- Data usage tracking adds minimal overhead
- Web interface refreshes every 5-10 seconds by default 