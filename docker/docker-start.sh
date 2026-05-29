#!/bin/bash
# PhishGuard AI — Docker startup script
# Run this once to build and start everything

set -e

echo "╔══════════════════════════════════════╗"
echo "║      PhishGuard AI — Docker          ║"
echo "║  MSc Cybersecurity Research — FUTO   ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Start Docker Desktop first."
    exit 1
fi

# Check docker-compose
if ! docker compose version > /dev/null 2>&1; then
    echo "❌ Docker Compose not found."
    exit 1
fi

echo "🔨 Building containers..."
docker compose build

echo ""
echo "🚀 Starting PhishGuard AI..."
docker compose up -d

echo ""
echo "⏳ Waiting for backend health check..."
sleep 10

# Check backend health
HEALTH=$(curl -s http://localhost:8000/health | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" \
    2>/dev/null || echo "unreachable")

if [ "$HEALTH" = "healthy" ]; then
    echo "✅ Backend healthy"
else
    echo "⚠️  Backend status: $HEALTH (may still be starting)"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  PhishGuard AI is running!           ║"
echo "║                                      ║"
echo "║  Dashboard:  http://localhost:3000   ║"
echo "║  API docs:   http://localhost:8000   ║"
echo "║  n8n:        http://localhost:5678   ║"
echo "║                                      ║"
echo "║  Stop:  docker compose down          ║"
echo "║  Logs:  docker compose logs -f       ║"
echo "╚══════════════════════════════════════╝"
