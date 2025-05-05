/**
 * LavaBridge Development Start Script
 * Uses nodemon for auto-restart on file changes
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
  path.join(logDir, `dev-error-${new Date().toISOString().split('T')[0]}.log`), 
  { flags: 'a' }
);

const outputLogStream = fs.createWriteStream(
  path.join(logDir, `dev-output-${new Date().toISOString().split('T')[0]}.log`), 
  { flags: 'a' }
);

console.log('Starting LavaBridge in development mode...');

// Start nodemon process
const nodemon = spawn('nodemon', ['src/index.js'], {
  stdio: 'pipe',
  detached: false
});

// Log proxy process ID
console.log(`Development server started with PID: ${nodemon.pid}`);

// Handle nodemon output
nodemon.stdout.on('data', (data) => {
  const output = data.toString().trim();
  console.log(output);
  outputLogStream.write(`[${new Date().toISOString()}] ${output}\n`);
});

// Handle nodemon errors
nodemon.stderr.on('data', (data) => {
  const error = data.toString().trim();
  console.error(`ERROR: ${error}`);
  errorLogStream.write(`[${new Date().toISOString()}] ${error}\n`);
});

// Handle nodemon exit
nodemon.on('exit', (code, signal) => {
  const message = `Development server exited with code ${code} and signal ${signal}`;
  console.log(message);
  outputLogStream.write(`[${new Date().toISOString()}] ${message}\n`);
  
  // Close log streams
  errorLogStream.end();
  outputLogStream.end();
});

// Handle process signals
process.on('SIGINT', () => {
  console.log('Received SIGINT. Gracefully shutting down development server...');
  nodemon.kill('SIGINT');
  setTimeout(() => {
    process.exit(0);
  }, 1000);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Gracefully shutting down development server...');
  nodemon.kill('SIGTERM');
  setTimeout(() => {
    process.exit(0);
  }, 1000);
}); 