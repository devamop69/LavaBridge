# LavaBridge 1.0 Release

The initial release of LavaBridge, a TCP tunneling proxy that routes Lavalink clients to either v3 or v4 backends based on version detection.

## Features

- Automatic routing to Lavalink v3 or v4 backends
- Low-level TCP tunneling for minimal overhead
- Modern dark-themed UI with responsive design
- Connection URL display with copy functionality
- Real-time connection monitoring
- Data usage tracking and visualization
- Security dashboard with IP blacklisting
- Health monitoring for backend servers
- Configuration via environment variables

## Configuration

See the env.sample file for all available configuration options.

## Client Connection Examples

### For v3 clients:
```
ws://your-server:6923/v3
```

### For v4 clients:
```
ws://your-server:6923/v4
```

## Project Links

- [GitHub Repository](https://github.com/devamop69/LavaBridge)
- [Documentation](https://github.com/devamop69/LavaBridge/blob/main/README.md) 