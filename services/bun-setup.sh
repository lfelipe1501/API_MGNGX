#!/bin/bash

# Script to configure or reset the Bun environment
# This script verifies that everything is correctly configured

echo "Setting up environment for Bun v1.2.10..."

# Check if Bun is installed
if ! command -v bun &> /dev/null; then
    echo "Error: Bun is not installed. Please install it first."
    exit 1
fi

echo "Bun Version: $(bun --version)"

# Create necessary directories
mkdir -p logs

# Verify compatibility
echo "Verifying compatibility with Bun..."
bun run verify

# Final message
echo ""
echo "Setup completed!"
echo ""
echo "To start the application in development mode:"
echo "  bun run dev"
echo ""
echo "To start the application in production mode:"
echo "  bun run start"
echo ""
echo "To run as a service in development mode:"
echo "  bun run service:dev"
echo ""
echo "To run as a service in production mode:"
echo "  bun run service:prod"
echo ""
echo "To stop services:"
echo "  bun run stop"
echo "" 