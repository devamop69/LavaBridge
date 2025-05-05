# Project Brief: Lavalink Proxy

## Project Overview

The Lavalink Proxy is a specialized WebSocket proxy server designed to intelligently route client connections to the appropriate Lavalink server version (v3 or v4) based on client protocol detection. This allows bot developers to maintain a single connection endpoint while supporting both Lavalink protocol versions simultaneously.

## Core Requirements

1. Automatically detect whether a connecting client is using Lavalink v3 or v4 protocol
2. Route the client to the corresponding Lavalink server backend based on protocol version
3. Transparently proxy all WebSocket messages between client and the appropriate Lavalink server
4. Provide configurable endpoints for both v3 and v4 Lavalink backends
5. Implement proper error handling and connection management

## Key Components

1. **WebSocket Server**: Accepts client connections and handles authentication
2. **Protocol Detection**: Analyzes initial client messages to determine protocol version
3. **Connection Routing**: Establishes connections to the appropriate backend Lavalink server
4. **Message Proxy**: Transparently forwards messages between clients and Lavalink servers
5. **Configuration System**: Environment-based configuration for all endpoints and credentials

## Technical Constraints

1. Built using Node.js with the ws library for WebSocket handling
2. Express.js for HTTP endpoints (health checks, status)
3. Configuration through environment variables
4. Logging of connection states and operations 