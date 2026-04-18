#!/usr/bin/env bash
# Zenith — One-command setup for all team members
# Run: bash setup.sh
set -e

echo "🔷 Setting up Zenith development environment..."

# Create __init__.py files for clean imports
touch src/__init__.py src/shared/__init__.py
touch src/dev1_ingress/__init__.py src/dev2_sast/__init__.py
touch src/dev3_clash/__init__.py src/dev4_verify/__init__.py
mkdir -p tests/fixtures results dashboard

# Virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install --upgrade pip
pip install \
  dspy-ai \
  groq \
  openai \
  anthropic \
  colorama \
  requests \
  websockets \
  pytest \
  semgrep \
  python-dotenv

# .env file template
if [ ! -f .env ]; then
  cat > .env << 'EOF'
# Zenith API Keys — DO NOT COMMIT THIS FILE
# Add your Groq keys here (rotate automatically):
GROQ_KEY_1=gsk_your_first_key_here
GROQ_KEY_2=gsk_your_second_key_here
GROQ_KEY_3=gsk_your_third_key_here
GROQ_KEY_4=gsk_your_fourth_key_here
GROQ_KEY_5=gsk_your_fifth_key_here
GROQ_KEY_6=gsk_your_sixth_key_here
GROQ_KEY_7=gsk_your_seventh_key_here
GROQ_KEY_8=gsk_your_eighth_key_here
# Optional fallbacks:
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
NVD_API_KEY=
EOF
  echo "✓ Created .env template — fill in your API keys"
fi

# Vulnerable fixture
cat > tests/fixtures/vulnerable.py << 'EOF'
"""Vulnerable Python file for Zenith demo."""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    return conn.execute(query).fetchall()

def login(username, password):
    if password == "admin123":  # Hardcoded credential
        return True
    return False

def eval_input(data):
    return eval(data)  # Code injection
EOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Fill in .env with your Groq API keys (revoke any exposed keys first!)"
echo "  2. source .venv/bin/activate"
echo "  3. python navigator.py          ← smoke test navigator"
echo "  4. python core_cli.py           ← run full demo"
echo "  5. Open dashboard/index.html    ← live dashboard"
