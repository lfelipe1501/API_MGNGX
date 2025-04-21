// Script to run the application as a service in production mode
// Compatible with Bun

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import config from '../bun.config.js';

// Configure environment
process.env.NODE_ENV = 'production';

// Create logs directory if it doesn't exist
const logDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// Configure streams for logs
const outStream = fs.openSync(path.join(logDir, 'out.log'), 'a');
const errStream = fs.openSync(path.join(logDir, 'err.log'), 'a');

// Function to start the process
function startProcess() {
  console.log('Starting production service...');
  
  const serverProcess = spawn('bun', ['run', config.production.script], {
    env: {
      ...process.env,
      ...config.production.env
    },
    stdio: ['ignore', outStream, errStream],
    detached: true
  });
  
  serverProcess.unref();
  
  console.log(`Service started with PID: ${serverProcess.pid}`);
  
  // Save PID to stop the service later
  fs.writeFileSync(path.join(process.cwd(), 'app.pid'), serverProcess.pid.toString());
}

startProcess(); 