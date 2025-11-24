#!/bin/bash
# Quick test runner for ProxySQL hostgroup backend credentials feature

set -e

echo "🚀 Starting ProxySQL Hostgroup Backend Credentials Test Environment"
echo ""

# Check if docker and docker-compose are available
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed. Aborting."; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "❌ Docker Compose is required but not installed. Aborting."; exit 1; }

# Clean up any previous runs
echo "🧹 Cleaning up previous test runs..."
docker compose down -v 2>/dev/null || true

echo ""
echo "🏗️  Building and starting test environment..."
echo "   This may take several minutes on first run..."
echo ""

# Build and run
docker compose up --build --abort-on-container-exit

# Capture exit code
EXIT_CODE=$?

echo ""
echo "🧹 Cleaning up..."
docker compose down -v

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✅ Tests completed successfully!"
    exit 0
else
    echo ""
    echo "❌ Tests failed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi


