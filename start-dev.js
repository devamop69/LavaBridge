#!/usr/bin/env node
/**
 * LavaBridge Development Start Script
 * Uses nodemon for auto-restart on file changes
 * Development mode with 1GB memory limit
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

// Create script to run with nodemon including GC and other options
const nodemonScript = `
require('dotenv').config();
process.env.NODE_ENV = 'development';
require('./src/index.js');
`;

const scriptPath = path.join(__dirname, 'nodemon-dev.js');
fs.writeFileSync(scriptPath, nodemonScript);

console.log('Starting LavaBridge in development mode with debugging enabled...');

// Start nodemon process with 1GB memory heap limit and garbage collection
const nodemon = spawn('nodemon', [
  '--exec',
  'node --max-old-space-size=1024 --expose-gc --inspect',
  scriptPath
], {
  stdio: 'pipe',
  detached: false,
  env: { ...process.env, NODE_ENV: 'development' }
});

// Log proxy process ID
console.log(`Development server started with PID: ${nodemon.pid}`);
console.log('Debug inspector available at chrome://inspect');

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
  
  // Clean up the temporary script file
  try {
    fs.unlinkSync(scriptPath);
  } catch (err) {
    // Ignore cleanup errors
  }
  
  // Close log streams
  errorLogStream.end();
  outputLogStream.end();
});

// Handle process signals
process.on('SIGINT', () => {
  console.log('Received SIGINT. Gracefully shutting down development server...');
  nodemon.kill('SIGINT');
  
  // Clean up the temporary script file
  try {
    fs.unlinkSync(scriptPath);
  } catch (err) {
    // Ignore cleanup errors
  }
  
  setTimeout(() => {
    process.exit(0);
  }, 1000);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Gracefully shutting down development server...');
  nodemon.kill('SIGTERM');
  
  // Clean up the temporary script file
  try {
    fs.unlinkSync(scriptPath);
  } catch (err) {
    // Ignore cleanup errors
  }
  
  setTimeout(() => {
    process.exit(0);
  }, 1000);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  errorLogStream.write(`[${new Date().toISOString()}] Uncaught Exception: ${error.stack || error}\n`);
}); 