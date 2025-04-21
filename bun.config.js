// Configuration for Bun.js
// Equivalent to ecosystem.config.js but optimized for Bun

export default {
  // Configuration for production environment
  production: {
    script: "./server.js",
    env: {
      NODE_ENV: "production"
    },
    // Bun-specific options
    maxMemory: "1GB",
    maxRestarts: 3
  },
  
  // Configuration for development environment
  development: {
    script: "./server.js",
    env: {
      NODE_ENV: "development"
    },
    // Bun-specific options
    maxMemory: "1GB",
    maxRestarts: 3,
    watch: true // Automatically restart when changes occur
  }
}; 