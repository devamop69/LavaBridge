/**
 * Utility functions for the LavaBridge
 */

/**
 * Detects the Lavalink client version based on initial messages
 * Does not interfere with the client connection - just observes
 * @param {WebSocket} ws - The client WebSocket connection
 * @returns {Promise<string>} - 'v3' or 'v4' based on detected version
 */
async function detectClientVersion(ws) {
  return new Promise((resolve) => {
    console.log('Starting version detection (observation only)');
    
    // Track message count for diagnostic purposes
    let messageCount = 0;
    let detectionComplete = false;
    
    // Store the original onmessage handler
    const originalOnMessage = ws.onmessage;
    
    // Set up message handler to observe initial messages without interfering
    ws.onmessage = function(event) {
      // Always pass the message to the original handler first
      if (originalOnMessage) {
        originalOnMessage.call(ws, event);
      }
      
      // If we've already detected the version, don't process further
      if (detectionComplete) return;
      
      messageCount++;
      
      try {
        let message;
        
        try {
          message = JSON.parse(event.data);
        } catch (error) {
          // Non-JSON message, can't use for detection
          return;
        }
        
        console.log(`[Version Detection] Observing message #${messageCount}`);
        
        // V4 client detection
        if (
          // Protocol Version in headers
          (message.headers && message.headers.protocolVersion === '4') ||
          // V4 specific operations
          message.op === 'configureResuming' || 
          message.op === 'ready' ||
          // Field naming conventions
          (message.op === 'voiceUpdate' && message.guildId) || // V4 uses guildId (camelCase)
          (message.op === 'play' && message.track && message.guildId) // V4 naming pattern
        ) {
          console.log('Detected v4 client based on message pattern');
          detectionComplete = true;
          resolve('v4');
          return;
        }
        
        // V3 client detection
        if (
          // Protocol Version in headers
          (message.headers && message.headers.protocolVersion === '3') ||
          // V3 specific operations
          message.op === 'equalizer' || 
          // Field naming conventions
          (message.op === 'voiceUpdate' && message.guildID) || // V3 uses guildID (uppercase)
          // Many v3 clients send these pattern of fields
          (message.op === 'play' && message.track && message.guildID)
        ) {
          console.log('Detected v3 client based on message pattern');
          detectionComplete = true;
          resolve('v3');
          return;
        }
      } catch (error) {
        console.error('Error in version detection:', error);
      }
    };
    
    // Set a timeout to prevent hanging if no clear version can be determined
    setTimeout(() => {
      if (!detectionComplete) {
        console.warn('Timeout detecting client version, defaulting to v3');
        resolve('v3');
      }
    }, 5000);
  });
}

/**
 * Safely parse a JSON message or return null if invalid
 * @param {string} data - The data to parse
 * @returns {object|null} - Parsed object or null
 */
function safeJsonParse(data) {
  try {
    return JSON.parse(data);
  } catch (error) {
    return null;
  }
}

module.exports = {
  detectClientVersion,
  safeJsonParse
}; 