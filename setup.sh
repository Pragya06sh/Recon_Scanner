#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ReconScanner — One-Shot Setup Script
# Run this once on your machine to install everything
# Usage: bash setup.sh
# ─────────────────────────────────────────────────────────────

set -e  # exit on any error

echo ""
echo "⚡ ReconScanner — Setup"
echo "─────────────────────────────────────────"

# ── 1. Check Python version ──────────────────────────────────
echo "[1/5] Checking Python..."
python3 --version
PY_VER=$(python3 -c "import sys; print(sys.version_info >= (3,10))")
if [ "$PY_VER" = "False" ]; then
    echo "ERROR: Python 3.10+ is required"
    exit 1
fi
echo "      Python OK"

# ── 2. Install nmap (system package) ─────────────────────────
echo "[2/5] Installing nmap..."
if command -v nmap &>/dev/null; then
    echo "      nmap already installed: $(nmap --version | head -1)"
else
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y nmap
    elif command -v brew &>/dev/null; then
        brew install nmap
    elif command -v yum &>/dev/null; then
        sudo yum install -y nmap
    else
        echo "ERROR: Cannot install nmap automatically."
        echo "       Install manually: https://nmap.org/download.html"
        exit 1
    fi
    echo "      nmap installed"
fi

# ── 3. Install Python dependencies ───────────────────────────
echo "[3/5] Installing Python packages..."
pip3 install -r requirements.txt --quiet
echo "      Packages installed"

# ── 4. Create .env file ───────────────────────────────────────
echo "[4/5] Setting up .env..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "      Created .env — EDIT IT to add your API keys"
else
    echo "      .env already exists — skipping"
fi

# ── 5. Create reports directory ───────────────────────────────
echo "[5/5] Creating reports/ directory..."
mkdir -p reports
echo "      Done"

echo ""
echo "─────────────────────────────────────────"
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo ""
echo "  1. Edit .env and add your API keys (optional but recommended):"
echo "     SHODAN_API_KEY — free at https://account.shodan.io"
echo "     NVD_API_KEY    — free at https://nvd.nist.gov/developers/request-an-api-key"
echo ""
echo "  2. Run the offline demo (no root / no API keys needed):"
echo "     python3 demo.py"
echo ""
echo "  3. Scan your own lab VM (requires sudo):"
echo "     sudo python3 main.py 192.168.1.100"
echo ""
echo "  4. Full scan with all features:"
echo "     sudo python3 main.py 192.168.1.100 --profile full --shodan --html --topo"
echo ""
echo "  See README.md for full documentation."
echo "─────────────────────────────────────────"
