# System Patterns: Lavalink Proxy

## Architecture Overview

The Lavalink Proxy follows a middleware proxy pattern with an added monitoring interface:

```
                           ┌─────────────────┐
                           │                 │
                           │ Web Browser     │
                           │ (Monitoring)    │
                           │                 │
                           └────────┬────────┘
                                    │
                                    │ HTTP
                                    ▼
┌─────────────────┐    TCP    ┌─────────────────┐    TCP    ┌─────────────────┐
│                 │           │                 │           │                 │
│ Lavalink Client ├──────────►│ Lavalink Proxy  ├──────────►│ Lavalink Server │
│                 │           │                 │           │ (v3 or v4)      │
└─────────────────┘           └─────────────────┘           └─────────────────┘
                                     │
                                     │ Records
                                     ▼
                              ┌─────────────────┐
                              │ Data Usage      │
                              │ Tracker         │
                              └─────────────────┘
```

## Core Components

### 1. TCP Proxy Server
- Accepts incoming TCP connections from clients
- Examines initial HTTP headers for:
  - Authentication verification
  - Version detection (v3 or v4)
- Creates direct TCP tunnel to appropriate backend
- Tracks data transmitted in both directions

### 2. Connection Router
- Routes connections to appropriate Lavalink server based on detected version
- **V3 Router**: Connects to Lavalink v3 servers
- **V4 Router**: Connects to Lavalink v4 servers
- Maintains direct TCP tunnel for minimal overhead

### 3. Connection Tracker
- Assigns unique IDs to each connection
- Monitors active connections
- Tracks connection details:
  - Client address
  - Backend server
  - Version
  - Connection start time
  - Connection status
  - Bytes sent and received

### 4. Data Usage Aggregator
- Collects TCP data usage statistics
- Aggregates usage by IP address
- Calculates inbound and outbound data volumes
- Formats data sizes for human readability
- Provides visual representation of usage patterns

### 5. Web Interface
- Provides real-time connection monitoring
- Displays connection statistics
- Shows detailed information for each active connection
- Visualizes TCP data usage per connection and per IP
- Auto-refreshes to show current state
- Runs on a separate port from the main proxy

## Design Patterns

1. **Proxy Pattern**: Core functionality acts as a transparent proxy between client and server
2. **Observer Pattern**: Connection events and data flows are tracked and exposed via web interface
3. **Factory Pattern**: Connection handlers are created based on detected protocol
4. **Adapter Pattern**: The proxy adapts client requests to appropriate backend version
5. **Aggregator Pattern**: Data usage is collected and aggregated by IP address

## Data Flow

1. Client connects to proxy TCP endpoint
2. Proxy authenticates the client using headers
3. Proxy analyzes HTTP headers to detect protocol version
4. Based on detection, proxy establishes connection to appropriate Lavalink server
5. All subsequent TCP data flows directly between client and server
6. Data volume is tracked in both directions
7. Connection details and data usage are exposed via web interface
8. Web interface periodically polls for updated information

## Error Handling Strategy

1. Authentication errors: Close connection with 401 Unauthorized
2. Protocol detection failures: Default to v3
3. Connection errors to backend: Close client connection with appropriate error
4. Client disconnection: Clean up backend connection and update tracking
5. Backend disconnection: Close client connection and update tracking 