# Login APP with 2FA

Login application with two-factor authentication and subdomain management for Nginx.

## Requirements

- Node.js (v20 or higher)
- npm
- PM2 (optional, for production)

## Installation

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. For production, install PM2 globally:

```bash
npm install -g pm2
```

## Configuration

The project uses `.env` files for environment variable configuration:

- `.env`: Configuration for production environment
- `.env.development`: Configuration for development environment

## Execution

### Development Mode

To run the application in development mode:

```bash
npm run dev
```

This will load environment variables from `.env.development` and use the development port (default 3001).

username: admin
password: developer

![QR MFA Admin](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAAAAklEQVR4AewaftIAAAdQSURBVO3BQY4cSRLAQDLR//8yV0c/BZCoaq0m4Gb2B2td4mGtizysdZGHtS7ysNZFHta6yMNaF3lY6yIPa13kYa2LPKx1kYe1LvKw1kUe1rrIw1oXeVjrIj98SOVvqjhRmSreUDmpOFE5qZhU3qiYVE4qJpWTiknlb6r4xMNaF3lY6yIPa13khy+r+CaVb1KZKj6hclIxqUwVn6g4UZkqJpU3Kr5J5Zse1rrIw1oXeVjrIj/8MpU3Kt5QmSomlaniN1W8oXJScaIyVUwVk8o3qbxR8Zse1rrIw1oXeVjrIj9cRuVE5aTijYpJZap4o+KNiknljYqbPKx1kYe1LvKw1kV+uEzFpPKGyknFScUbFScqn6iYVCaVqeK/7GGtizysdZGHtS7ywy+r+JtUPlFxojJVnKhMFZPKVHFS8YbKb6r4lzysdZGHtS7ysNZFfvgylf+nikllqphUTlSmikllqvibVKaKk4pJ5Q2Vf9nDWhd5WOsiD2td5IcPVfxLVN6omFSmiknljYqTipOKk4rfVPFf8rDWRR7WusjDWhf54UMqU8Wk8k0VU8VvUjmpOFH5popJ5aTiEyrfVPGbHta6yMNaF3lY6yL2B1+kclIxqZxUvKEyVXyTyknFJ1SmijdUpopPqEwVk8pUMamcVHzTw1oXeVjrIg9rXcT+4C9SmSomlZOKSWWqmFSmijdUpooTlZOKSeWkYlL5popJZaqYVKaKN1ROKj7xsNZFHta6yMNaF/nhL6uYVE4qTipOKiaVb1KZKt6omFTeqDhR+aaKE5WpYqqYVL7pYa2LPKx1kYe1LvLDL1M5qThReaNiUvlExUnFpDJVvFHxhsobFScVk8pUMam8ofKbHta6yMNaF3lY6yI/fEhlqpgqJpUTlaliUnmj4hMqU8UbKicVk8pU8YmKT1ScVEwqJxWTyjc9rHWRh7Uu8rDWRX74UMWJyidUvkllqphUpopJ5Y2Kb6qYVE5UTiomlZOKSeVf8rDWRR7WusjDWhf54ZdVTConFd+k8kbFpPIJlU+oTBVvVEwqJxWTyhsVJypTxTc9rHWRh7Uu8rDWRX74kMpJxRsqJxUnKlPFGypTxYnKVHGiMlVMKlPFb1KZKk5UpopJ5Q2VqeITD2td5GGtizysdZEfPlQxqUwqn6iYVN5QOal4Q2WqOFGZKiaVqWJSmSpOKr6p4kTlpGJSmSq+6WGtizysdZGHtS5if/ABlanim1Q+UXGi8k0VJypTxaQyVZyovFFxojJVnKhMFScqJxWfeFjrIg9rXeRhrYv88MtUTipOKiaVqWJSmVROKk5UTio+ofJNFZPKpPJNFScqJxXf9LDWRR7WusjDWhf54R+jclIxqUwVJyqTyidUTipOKk5UpoqpYlL5JpX/koe1LvKw1kUe1rqI/cEXqZxUTCpTxYnKGxWTylRxojJVvKHyRsUnVKaKE5WTijdUpopJ5aTiEw9rXeRhrYs8rHWRHz6kclLxCZWp4kTlpOJEZaqYVKaKNyomlROVqWJSmSpOVKaKSWVSmSpOKv6fHta6yMNaF3lY6yL2B/8QlaliUpkqJpWpYlI5qZhU3qj4m1SmiknljYo3VKaKN1Smik88rHWRh7Uu8rDWRX74MpU3Kk5UpoqTiknlpOITFScq31QxVXyiYlKZKk4qTlT+poe1LvKw1kUe1rqI/cEHVL6p4ptUTiomlU9UfEJlqjhReaPiEypvVPxND2td5GGtizysdZEfvqziRGWqmFTeqDipmFROKj6hclIxqXyi4ptUPlFxonJS8YmHtS7ysNZFHta6yA//uIo3VP4mlanijYpJZVKZKiaVqWJSeaNiUnlDZar4mx7WusjDWhd5WOsiP/wylaliUpkqJpWTijcqJpWp4hMqU8UbFZPKScWk8gmVT1ScVPymh7Uu8rDWRR7WusgPH6o4qTipOKk4UZkqTlT+n1TeqPhExYnKVPGGyidUpopPPKx1kYe1LvKw1kV++JDK31QxVUwqU8UnVL6pYlL5TSpTxRsqU8W/7GGtizysdZGHtS7yw5dVfJPKicpU8UbFb1KZKt5QmSomlaliUvlExTep/KaHtS7ysNZFHta6yA+/TOWNit9UMamcVEwqJxUnKlPFpDJVnFRMKlPFpHKi8k0qU8Wk8k0Pa13kYa2LPKx1kR8uozJVTCpTxaTyRsWJylQxqZyoTBWfqJhU3qiYVCaVNyq+6WGtizysdZGHtS7yw2UqJpWp4ptU3lCZKiaVb1KZKk4qTlSmiknlDZWp4hMPa13kYa2LPKx1kR9+WcVvqphUTlSmik9UnKicqJxUnKhMFScqU8WJylTxRsXf9LDWRR7WusjDWhf54ctU/iaVNyomlaliUnlDZaqYVKaKE5VPqJyoTBVTxaQyVUwVk8rf9LDWRR7WusjDWhexP1jrEg9rXeRhrYs8rHWRh7Uu8rDWRR7WusjDWhd5WOsiD2td5GGtizysdZGHtS7ysNZFHta6yMNaF/kfli+6eUXVN+cAAAAASUVORK5CYII=)

MFA Code: OV2E2UCOMU7DYMRTEETDYJKMGQQTQJC6

### Production Mode

To run the application in production mode:

```bash
npm run start
```

This will load environment variables from `.env` and use the production port (default 5001).

### Running with PM2

To run the application with PM2, you can use the following scripts:

#### Production Mode

```bash
npm run pm2:prod
```

#### Development Mode

```bash
npm run pm2:dev
```

#### Managing all instances

```bash
# Start all instances
npm run pm2:start

# Stop all instances
npm run pm2:stop

# Restart all instances
npm run pm2:restart

# View logs
npm run pm2:logs
```

You can also use PM2 commands directly:

```bash
# Production Mode
pm2 start ecosystem.config.js --only Login2FA-PROD

# Development Mode
pm2 start ecosystem.config.js --only Login2FA-DEV

# Managing all instances
pm2 start ecosystem.config.js
pm2 stop ecosystem.config.js
pm2 restart ecosystem.config.js
pm2 logs
```

## Environment Verification

To verify which environment is configured without starting the server:

```bash
npm run test
```

## Features

- Authentication with username and password
- Two-factor authentication (2FA)
- User management (for administrators)
- Nginx subdomain creation
- Activity logging
- reCAPTCHA protection 
