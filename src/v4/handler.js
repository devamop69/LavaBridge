const WebSocket = require('ws');
const { safeJsonParse } = require('../utils');

/**
 * Handle a v4 client connection by establishing a connection to a Lavalink v4 server
 * and proxying messages between them
 * 
 * @param {WebSocket} clientWs - The WebSocket connection from the client
 * @param {object} serverConfig - Configuration for the Lavalink v4 server
 */
function handleV4Connection(clientWs, serverConfig) {
  console.log(`Establishing connection to Lavalink v4 at ${serverConfig.host}:${serverConfig.port}${serverConfig.secure ? ' (WSS)' : ''}`);

  // Create connection to Lavalink v4 server
  const protocol = serverConfig.secure ? 'wss' : 'ws';
  const lavalinkWs = new WebSocket(`${protocol}://${serverConfig.host}:${serverConfig.port}`, {
    headers: {
      Authorization: serverConfig.password,
      'User-Id': '1',
      'Client-Name': 'LavalinkProxy/1.0.0',
      'Protocol': '4'
    },
    followRedirects: true,
    rejectUnauthorized: false // Allow self-signed certificates
  });

  // Add additional error handling during connection phase
  lavalinkWs.on('unexpected-response', (request, response) => {
    console.error(`Unexpected response from Lavalink v4 server: ${response.statusCode} ${response.statusMessage}`);
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
        clientWs.close(4000, `Lavalink v4 server returned: ${response.statusCode} ${response.statusMessage}`);
      }
    });
  });

  // Connection to Lavalink server established
  lavalinkWs.on('open', () => {
    console.log('Connected to Lavalink v4 server');
  });

  // Handle messages from Lavalink v4 server and forward to client
  lavalinkWs.on('message', (data) => {
    if (clientWs.readyState === WebSocket.OPEN) {
      try {
        clientWs.send(data);
      } catch (error) {
        console.error('Error forwarding message from v4 server to client:', error);
      }
    }
  });

  // Handle messages from client and forward to Lavalink v4 server
  clientWs.on('message', (data) => {
    if (lavalinkWs.readyState === WebSocket.OPEN) {
      try {
        lavalinkWs.send(data);
      } catch (error) {
        console.error('Error forwarding message from client to v4 server:', error);
      }
    }
  });

  // Handle client disconnection
  clientWs.on('close', (code, reason) => {
    console.log(`V4 client disconnected: ${code} - ${reason}`);
    // Close the connection to Lavalink v4 server
    if (lavalinkWs.readyState === WebSocket.OPEN) {
      lavalinkWs.close();
    }
  });

  // Handle Lavalink server disconnection
  lavalinkWs.on('close', (code, reason) => {
    console.log(`Lavalink v4 server disconnected: ${code} - ${reason}`);
    // Close the connection to client
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close();
    }
  });

  // Handle errors
  clientWs.on('error', (error) => {
    console.error('V4 client error:', error);
  });

  lavalinkWs.on('error', (error) => {
    console.error('Lavalink v4 server error:', error);
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(4000, 'Lavalink v4 server error');
    }
  });
  
  return lavalinkWs;
}

module.exports = {
  handleV4Connection
}; 