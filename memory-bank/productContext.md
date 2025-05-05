# Product Context: Lavalink Proxy

## Problem Statement

Lavalink has two major protocol versions (v3 and v4) that are incompatible with each other. Music bot developers face challenges when:
1. They want to support both protocol versions
2. They need to migrate from v3 to v4 without disrupting service
3. They have different library clients that use different Lavalink versions

Without a proxy solution, developers must either:
- Maintain separate connection logic for each protocol version
- Force all clients to upgrade simultaneously 
- Run multiple instances of their bots for different protocol versions

## Solution

The Lavalink Proxy serves as an intelligent bridge between Lavalink clients and Lavalink servers, automatically detecting the client's protocol version and routing to the appropriate backend server. This allows:

1. **Seamless Protocol Support**: Bot developers can use a single connection endpoint while supporting both protocol versions
2. **Graceful Migration**: Clients can gradually migrate from v3 to v4 without service disruption
3. **Simplified Architecture**: Developers can maintain a single connection endpoint while supporting diverse client libraries

## Target Users

1. Discord bot developers who use Lavalink for audio playback
2. Framework developers building audio solutions on top of Lavalink
3. Server administrators managing Lavalink infrastructure for multiple clients

## User Experience Goals

1. **Transparency**: The proxy should be completely transparent to clients - they should not need to modify their code to work with it
2. **Reliability**: Connections should be maintained stably with proper error handling
3. **Configurability**: Easy configuration of backend servers through environment variables
4. **Diagnostics**: Clear logging of connection events and routing decisions for troubleshooting 