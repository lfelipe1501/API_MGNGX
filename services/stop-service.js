// Script to stop the application services
// Compatible with Bun

import fs from 'fs';
import path from 'path';

// Function to stop a service using its PID file
function stopService(pidFile) {
  try {
    if (fs.existsSync(pidFile)) {
      const pid = parseInt(fs.readFileSync(pidFile, 'utf8'), 10);
      
      console.log(`Stopping service with PID: ${pid}`);
      
      try {
        process.kill(pid, 'SIGTERM');
        console.log(`Service stopped successfully.`);
      } catch (error) {
        console.error(`Error stopping service: ${error.message}`);
      }
      
      // Remove the PID file
      fs.unlinkSync(pidFile);
    } else {
      console.log(`PID file not found: ${pidFile}`);
    }
  } catch (error) {
    console.error(`Error processing PID file: ${error.message}`);
  }
}

// Determine which services to stop based on arguments
const args = process.argv.slice(2);
const prodPidFile = path.join(process.cwd(), 'app.pid');
const devPidFile = path.join(process.cwd(), 'app-dev.pid');

if (args.includes('prod') || args.length === 0) {
  stopService(prodPidFile);
}

if (args.includes('dev') || args.length === 0) {
  stopService(devPidFile);
}

console.log('Operation completed.'); 