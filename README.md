# Login APP with 2FA

Login application with two-factor authentication and subdomain management for Nginx.

## Requirements

- Node.js (v20 or higher)
- npm
- PM2 (optional, for production)

## Installation

To use it, simply follow the following steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/lfelipe1501/API_MGNGX.git
   ```
   
3. Install dependencies:

   ```bash
   npm install
   ```

4. Install PM2 globally to manage the project in a more professional way:

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

> [!important]
> _**IF YOU WISH** you can use this data to login with the database that is in the project
> the `.sqlite` file contains the following data to start testing the application:_

| Data | Value |
|-----|-------------|
|USERNAME|admin|
|PASSWORD|developer|
|QR-MFA|![QR-admin-MFA](https://github.com/user-attachments/assets/2eb12dfb-8127-42b6-843a-421d2c400b87)|
|MFA-MANUALLY|OV2E2UCOMU7DYMRTEETDYJKMGQQTQJC6|

### Production Mode

To run the application in production mode:

```bash
npm run start
```

This will load environment variables from `.env` and use the production port (default 5001).

> [!important]
> _**BEFORE RUNNING** the project you **MUST** delete the `.sqlite` database to create a new one
> when starting the project and be able to register your own users._
>
> _**IT IS IMPORTANT** that you put the application behind a reverse proxy so that it can use a domain or subdomain._
>
> _**AFTER THIS** you can edit the `.env` file to add the original keys of a domain or subdomain that has reCAPTCHA V3._

### Running with PM2

To run the application with PM2, you can use the following scripts:

#### Prod Mode

```bash
npm run pm2:prod
```

#### Dev Mode

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

### Contact / Social Media

*Get the latest News about Web Development, Open Source, Tooling, Server & Security*

[![Twitter](https://raw.githubusercontent.com/lfelipe1501/lfelipe-projects/master/icons/filled/twitter.svg)](https://twitter.com/lfelipe1501)
[![Facebook](https://raw.githubusercontent.com/lfelipe1501/lfelipe-projects/master/icons/filled/facebook.svg)](https://www.facebook.com/lfelipe1501)
[![Github](https://raw.githubusercontent.com/lfelipe1501/lfelipe-projects/master/icons/filled/github.svg)](https://github.com/lfelipe1501)

### Development by

Developer / Author: [Luis Felipe Sanchez](https://github.com/lfelipe1501)
Company: [lfsystems](https://www.lfsystems.com.co)
