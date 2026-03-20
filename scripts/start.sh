#!/usr/bin/env bash
set -e

echo "================================================"
echo "  AI Security Wrapper — Starting"
echo "================================================"

# Check .env exists
if [ ! -f ".env" ]; then
  echo "ERROR: .env file not found. Copy config/.env.example to .env and set JWT_SECRET."
  exit 1
fi

# Create logs directory
mkdir -p logs

# Run tests before starting
echo "[1/3] Running security layer tests..."
python3 -m pytest ai_security_wrapper/tests/ -v --tb=short
echo ""

echo "[2/3] Tests passed. Starting server..."
echo ""

# Start the server
echo "[3/3] Server starting on http://0.0.0.0:8000"
echo "      API docs: http://localhost:8000/docs"
echo ""
python3 -m ai_security_wrapper.main
