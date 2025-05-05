# Active Context: Lavalink Proxy

## Current Focus

The Lavalink Proxy now includes data rate monitoring and backend health checks:

1. **Main Proxy Server**: TCP server that accepts client connections and handles authentication
2. **Protocol Detection**: Logic to analyze headers and determine protocol version (v3 or v4)
3. **Backend Routers**:
   - V3 Handler: Routes connections to Lavalink v3 servers
   - V4 Handler: Routes connections to Lavalink v4 servers
4. **Web Interface**: 
   - Displays active connection statistics
   - Shows detailed connection information
   - Auto-refreshes every 5 seconds
   - Tracks and displays TCP data usage by IP address
   - Monitors real-time data transfer rates
   - Provides backend health status monitoring
5. **Configuration**: Environment variable based configuration for all endpoints

## Recent Changes

- Added real-time data rate tracking per connection and IP address
- Implemented color-coded indicators for different bandwidth levels
- Created historical rate tracking (60 seconds window)
- Enhanced backend health monitoring with response times
- Added visual indicators for high bandwidth usage
- Improved the auto-refresh mechanism for consistent monitoring
- Maintained backwards compatibility with existing endpoints
- Added a "Check Now" button for manual backend health verification

## Current Decisions

1. **Protocol Detection Strategy**: 
   - Detection based on URL path in HTTP headers
   - Default to v3 if detection fails
   - Minimal protocol examination for maximum performance

2. **Error Handling**:
   - Graceful connection closure with appropriate error codes
   - Error logging for debugging
   - Automatic cleanup of resources on disconnection

3. **Connection Monitoring**:
   - Web interface on separate port (default: 2346)
   - Real-time connection stats with version breakdown
   - Detailed connection information with uptime tracking
   - Per-IP data usage tracking and visualization

4. **Data Usage Tracking**:
   - Track bytes sent/received for each connection
   - Aggregate usage statistics by IP address
   - Display data usage trends with visual indicators
   - Format data sizes for human readability

5. **Data Rate Monitoring**:
   - Calculate and display bytes/second for all connections
   - Color-coded indicators for different bandwidth levels:
     - Normal: < 100 KB/s (default color)
     - Medium: 100 KB/s - 1 MB/s (orange)
     - High: > 1 MB/s (red)
   - Store rate history for the last 60 seconds
   - Update rates every 5 seconds

6. **Backend Health Monitoring**:
   - TCP-based health checks for backend servers
   - Status indicators (online/offline/timeout)
   - Response time measurements
   - Scheduled automatic health checks every 60 seconds
   - Manual health check option

7. **Authentication**:
   - Simple password-based authentication
   - Password configured through environment variables

## Next Steps

1. **Testing**:
   - Test data rate monitoring accuracy
   - Verify proxy performance with all monitoring features enabled
   - Test with high-volume data transfer scenarios
   - Verify backend health monitoring reliability

2. **Enhancements**:
   - Implement historical data usage/rates tracking
   - Consider adding authentication to web interface
   - Add data usage alerts for unusual patterns
   - Create data visualization charts for rate history

3. **Documentation**:
   - Update README with all new monitoring features
   - Add screenshots of the updated monitoring interfaces
   - Document the bandwidth thresholds and color indicators 