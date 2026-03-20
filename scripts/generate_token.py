"""Quick CLI to generate a JWT for testing."""

import os
import sys

os.environ.setdefault("JWT_SECRET", open(".env").read().split("JWT_SECRET=")[1].split("\n")[0].strip()
                       if os.path.exists(".env") else "INSECURE_DEFAULT_CHANGE_ME")

from ai_security_wrapper.auth.middleware import generate_token

role = sys.argv[1] if len(sys.argv) > 1 else "agent_user"
user = sys.argv[2] if len(sys.argv) > 2 else "dev_user_001"

token = generate_token(user, role)
print(f"\nToken for user='{user}' role='{role}':")
print(f"\n  {token['access_token']}\n")
print(f"  Expires in: {token['expires_in']} seconds")
print(f"\nTest with:")
print(f"  curl -X POST http://localhost:8000/agent/query \\")
print(f"    -H 'Authorization: Bearer {token['access_token']}' \\")
print(f"    -H 'Content-Type: application/json' \\")
print(f"    -d '{{\"message\": \"Hello, agent!\"}}'")
