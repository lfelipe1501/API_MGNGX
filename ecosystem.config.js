module.exports = {
  apps: [
    {
      name: "Login2FA-PROD",
      script: "./server.js",
      max_memory_restart: '1G',
      max_restarts: 3,
      env: {
        NODE_ENV: "production"
      }
    },
    {
      name: "Login2FA-DEV",
      script: "./server.js",
      max_memory_restart: '1G',
      max_restarts: 3,
      env: {
        NODE_ENV: "development"
      },
      watch: true // Reiniciar automáticamente en desarrollo cuando hay cambios
    }
  ]
}
