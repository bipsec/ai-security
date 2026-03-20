"""Launch all 3 processes for the AI Security demo.

Usage: python ui/start_demo.py
  - FastAPI backend on port 8000
  - Raw RAG Chatbot on port 8501
  - Secured RAG Chatbot on port 8502
"""

import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

# Activate venv if present
venv_python = os.path.join(ROOT, "venv", "Scripts", "python.exe")
if not os.path.exists(venv_python):
    venv_python = sys.executable

processes = []


def start(name, cmd):
    print(f"  [{name}] {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, cwd=ROOT)
    processes.append((name, proc))
    return proc


def cleanup(*_args):
    print("\nShutting down all processes...")
    for name, proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
            print(f"  [{name}] stopped")
        except Exception:
            proc.kill()
            print(f"  [{name}] killed")
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def main():
    print("=" * 56)
    print("  AI Security Demo — Starting all services")
    print("=" * 56)
    print()

    # 1. FastAPI backend
    start("FastAPI", [venv_python, "-m", "ai_security_wrapper.main"])
    print("  Waiting for backend to start...")
    time.sleep(4)

    # 2. Raw chatbot (port 8501)
    start("Raw Chatbot", [
        venv_python, "-m", "streamlit", "run", "ui/raw_chatbot.py",
        "--server.port", "8501",
        "--server.headless", "true",
    ])

    # 3. Secured chatbot (port 8502)
    start("Secured Chatbot", [
        venv_python, "-m", "streamlit", "run", "ui/secured_chatbot.py",
        "--server.port", "8502",
        "--server.headless", "true",
    ])

    print()
    print("=" * 56)
    print("  Demo is running!")
    print()
    print("  Raw Chatbot (no security):  http://localhost:8501")
    print("  Secured Chatbot (6 layers): http://localhost:8502")
    print("  FastAPI Backend (docs):     http://localhost:8000/docs")
    print()
    print("  Press Ctrl+C to stop all processes.")
    print("=" * 56)
    print()

    # Wait for any process to exit
    try:
        while True:
            for name, proc in processes:
                ret = proc.poll()
                if ret is not None:
                    print(f"  [{name}] exited with code {ret}")
            time.sleep(2)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
