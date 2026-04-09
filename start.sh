#!/usr/bin/env bash
# CyberSentinel - Quick Start

echo "🛡️  CyberSentinel Threat Monitor"
echo "================================"

# Check Python
if ! command -v python3 &> /dev/null; then
  echo "❌ python3 not found. Please install Python 3.8+"
  exit 1
fi

# Install deps
echo "📦 Installing dependencies..."
pip3 install flask numpy scikit-learn --break-system-packages -q 2>/dev/null || \
pip3 install flask numpy scikit-learn -q

# Start backend
echo "🚀 Starting backend on http://localhost:5000"
cd "$(dirname "$0")/backend"
python3 threat_monitor.py &
BACKEND_PID=$!

sleep 1.5

# Open frontend
echo "🌐 Opening frontend..."
if command -v xdg-open &> /dev/null; then
  xdg-open "$(dirname "$0")/frontend/index.html"
elif command -v open &> /dev/null; then
  open "$(dirname "$0")/frontend/index.html"
else
  echo "👉 Open frontend/index.html in your browser"
fi

echo ""
echo "Backend PID: $BACKEND_PID"
echo "Press Ctrl+C to stop."
wait $BACKEND_PID
