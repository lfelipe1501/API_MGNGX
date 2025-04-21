// Script to configure the environment on Windows
// Adapts package.json scripts to be compatible with Windows

import fs from 'fs';

console.log("Configuring for Windows environment...");

try {
  // Read the current package.json
  const packageJson = JSON.parse(fs.readFileSync('./package.json', 'utf8'));
  
  // Modify scripts to be compatible with Windows
  packageJson.scripts = {
    "start": "set NODE_ENV=production&&bun run server.js",
    "dev": "set NODE_ENV=development&&bun --hot run server.js",
    "bun:prod": "set NODE_ENV=production&&bun run server.js",
    "bun:dev": "set NODE_ENV=development&&bun --hot run server.js",
    "service:prod": "bun --smol run services/service-prod.js",
    "service:dev": "bun --smol run services/service-dev.js",
    "stop": "bun run services/stop-service.js",
    "verify": "bun run services/verify-bun.js",
    "test": "echo \"Verification Environment:\"&&bun run server.js --check-env&&echo \"\n\nVerification Environment: OK\"&&echo ''"
  };
  
  // Save the modified package.json
  fs.writeFileSync('./package.json', JSON.stringify(packageJson, null, 2));
  
  console.log("✅ Scripts adapted for Windows");
  console.log("To run in development mode: bun run dev");
  console.log("To run in production mode: bun run start");
  
} catch (error) {
  console.error(`❌ Error configuring for Windows: ${error.message}`);
} 