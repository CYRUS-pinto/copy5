#!/usr/bin/env bash
# Zenith — One command startup
# Usage: bash start.sh
set -e

echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║   ZENITH — AI Security Platform       ║"
echo "  ║   HACKFEST 2026 · NMIT Bangalore       ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

# 1. Setup virtualenv if needed
if [ ! -d ".venv" ]; then
  echo "  Setting up Python environment..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -q -r backend/requirements.txt
  echo "  Dependencies installed."
else
  source .venv/bin/activate
fi

# 2. Copy .env template if no .env exists
if [ ! -f "backend/.env" ]; then
  cp backend/.env.template backend/.env
  echo ""
  echo "  ⚠  Created backend/.env — fill in your Groq API keys before scanning"
  echo "     (The demo works without keys — uses mock responses)"
  echo ""
fi

# 3. Start FastAPI backend
echo "  Starting backend on http://localhost:8000 ..."
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
cd ..

# 4. Wait for backend
sleep 2

# 5. Open both sites
echo "  Opening frontend: http://localhost:8000"
echo "  Opening visualization: file://$(pwd)/visualization/zenith_visualization.html"
echo ""

# Open browser (cross-platform)
if command -v open &>/dev/null; then
  open visualization/zenith_visualization.html
  open frontend/index.html
elif command -v xdg-open &>/dev/null; then
  xdg-open visualization/zenith_visualization.html
  xdg-open frontend/index.html
fi

echo "  ════════════════════════════════════════"
echo "  ZENITH IS RUNNING"
echo "  Main app:       frontend/index.html"
echo "  Visualization:  visualization/zenith_visualization.html"
echo "  Backend API:    http://localhost:8000"
echo "  API docs:       http://localhost:8000/docs"
echo "  ════════════════════════════════════════"
echo ""
echo "  DEMO COMMANDS:"
echo "    Scan fixture:    python backend/main.py"
echo "    Health check:    curl http://localhost:8000/api/health"
echo ""
echo "  Press Ctrl+C to stop"
wait $BACKEND_PID
