const WebSocket = require('ws');
const { safeJsonParse } = require('../utils');

/**
 * Handle a v3 client connection by establishing a connection to a Lavalink v3 server
 * and proxying messages between them
 * 
 * @param {WebSocket} clientWs - The WebSocket connection from the client
 * @param {object} serverConfig - Configuration for the Lavalink v3 server
 */
function handleV3Connection(clientWs, serverConfig) {
  console.log(`Establishing connection to Lavalink v3 at ${serverConfig.host}:${serverConfig.port}${serverConfig.secure ? ' (WSS)' : ''}`);

  // Create connection to Lavalink v3 server
  const protocol = serverConfig.secure ? 'wss' : 'ws';
  const lavalinkWs = new WebSocket(`${protocol}://${serverConfig.host}:${serverConfig.port}`, {
    headers: {
      Authorization: serverConfig.password,
      'User-Id': '1',
      'Client-Name': 'LavalinkProxy/1.0.0'
    },
    followRedirects: true,
    rejectUnauthorized: false // Allow self-signed certificates
  });

  // Add additional error handling during connection phase
  lavalinkWs.on('unexpected-response', (request, response) => {
    console.error(`Unexpected response from Lavalink v3 server: ${response.statusCode} ${response.statusMessage}`);
    console.error(`Endpoint: ${protocol}://${serverConfig.host}:${serverConfig.port}`);
    console.error(`Headers: ${JSON.stringify(response.headers)}`);
    
    // Try to read response body for more details
    let body = '';
    response.on('data', (chunk) => {
      body += chunk;
    });
    
    response.on('end', () => {
      console.error(`Response body: ${body}`);
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.close(4000, `Lavalink v3 server returned: ${response.statusCode} ${response.statusMessage}`);
      }
    });
  });

  // Connection to Lavalink server established
  lavalinkWs.on('open', () => {
    console.log('Connected to Lavalink v3 server');
  });

  // Handle messages from Lavalink v3 server and forward to client
  lavalinkWs.on('message', (data) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      try {
        clientWs.send(data);
      } catch (error) {
        console.error('Error forwarding message from v3 server to client:', error);
      }
    }
  });

  // Handle messages from client and forward to Lavalink v3 server
  clientWs.on('message', (data) => {
    if (lavalinkWs.readyState === WebSocket.OPEN) {
      try {
        lavalinkWs.send(data);
      } catch (error) {
        console.error('Error forwarding message from client to v3 server:', error);
      }
    }
  });

  // Handle client disconnection
  clientWs.on('close', (code, reason) => {
    console.log(`V3 client disconnected: ${code} - ${reason}`);
    // Close the connection to Lavalink v3 server
    if (lavalinkWs.readyState === WebSocket.OPEN) {
      lavalinkWs.close();
    }
  });

  // Handle Lavalink server disconnection
  lavalinkWs.on('close', (code, reason) => {
    console.log(`Lavalink v3 server disconnected: ${code} - ${reason}`);
    // Close the connection to client
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close();
    }
  });

  // Handle errors
  clientWs.on('error', (error) => {
    console.error('V3 client error:', error);
  });

  lavalinkWs.on('error', (error) => {
    console.error('Lavalink v3 server error:', error);
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(4000, 'Lavalink v3 server error');
    }
  });
  
  return lavalinkWs;
}

module.exports = {
  handleV3Connection
}; 