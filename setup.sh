#!/bin/bash

# Sentery Setup Script
set -e

echo "🛡️  Setting up Sentery: Autonomous AI-driven Web PT Tool..."

# Check for Gemini API Key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  WARNING: GEMINI_API_KEY environment variable is not set."
    echo "AI reasoning will run in MOCK mode."
    echo "To use real AI, export GEMINI_API_KEY='your_key_here'"
fi

# Build and Start Services
echo "🚀 Building and starting Docker containers..."
docker-compose build
docker-compose up -d

echo "✅ Sentery is now running!"
echo "--------------------------------------------------"
echo "🌐 Admin Dashboard: http://localhost:3000"
echo "🤖 AI Orchestrator: http://localhost:8000"
echo "🔌 MITM Proxy:      http://localhost:8080"
echo "--------------------------------------------------"
echo "💡 Usage: Configure your browser/tool to use the proxy at localhost:8080"
echo "   Don't forget to trust the generated 'ca.crt' for HTTPS inspection."
echo ""
echo "📝 Use 'docker-compose logs -f' to monitor the system."
