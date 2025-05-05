#!/usr/bin/env node
/**
 * LavaBridge Start Script with Error Handling
 * Production mode with 1GB memory limit and garbage collection
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Create logs directory if it doesn't exist
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Create log streams
const errorLogStream = fs.createWriteStream(
  path.join(logDir, `error-${new Date().toISOString().split('T')[0]}.log`), 
  { flags: 'a' }
);

const outputLogStream = fs.createWriteStream(
  path.join(logDir, `output-${new Date().toISOString().split('T')[0]}.log`), 
  { flags: 'a' }
);

console.log('Starting LavaBridge in production mode...');

// Start the proxy process with 1GB memory heap limit and enable garbage collection
const proxy = spawn('node', [
  '--max-old-space-size=1024',
  '--expose-gc',
  '--nouse-idle-notification', // Disable idle garbage collection
  'src/index.js'
], {
  stdio: ['inherit', 'pipe', 'pipe'],
  detached: false,
  env: { ...process.env, NODE_ENV: 'production' }
});

// Log proxy process ID
console.log(`Proxy started with PID: ${proxy.pid}`);

// Handle proxy output
proxy.stdout.on('data', (data) => {
  const output = data.toString().trim();
  console.log(output);
  outputLogStream.write(`[${new Date().toISOString()}] ${output}\n`);
});

// Handle proxy errors
proxy.stderr.on('data', (data) => {
  const error = data.toString().trim();
  console.error(`ERROR: ${error}`);
  errorLogStream.write(`[${new Date().toISOString()}] ${error}\n`);
});

// Handle proxy exit
proxy.on('exit', (code, signal) => {
  const message = `Proxy process exited with code ${code} and signal ${signal}`;
  console.log(message);
  outputLogStream.write(`[${new Date().toISOString()}] ${message}\n`);
  
  // Close log streams
  errorLogStream.end();
  outputLogStream.end();
  
  // Auto restart if crashed but not intentionally terminated
  if (code !== 0 && !['SIGINT', 'SIGTERM'].includes(signal)) {
    console.log('Process crashed. Automatically restarting in 5 seconds...');
    setTimeout(() => {
      console.log('Restarting...');
      require('./start.js');
    }, 5000);
  }
});

// Handle process signals
process.on('SIGINT', () => {
  console.log('Received SIGINT. Gracefully shutting down proxy...');
  proxy.kill('SIGINT');
  setTimeout(() => {
    process.exit(0);
  }, 1000);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Gracefully shutting down proxy...');
  proxy.kill('SIGTERM');
  setTimeout(() => {
    process.exit(0);
  }, 1000);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  errorLogStream.write(`[${new Date().toISOString()}] Uncaught Exception: ${error.stack || error}\n`);
  proxy.kill('SIGTERM');
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  errorLogStream.write(`[${new Date().toISOString()}] Unhandled Rejection: ${reason}\n`);
}); 