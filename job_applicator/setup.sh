#!/usr/bin/env bash
# One-time setup: install dependencies and Playwright browser

set -e

echo "==> Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "==> Installing Python packages..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "==> Installing Playwright Chromium browser..."
playwright install chromium

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Next steps:"
echo "  1. Edit config.yaml — fill in your name, email, resume path, credentials, and keywords"
echo "  2. Copy your resume PDF into this folder (or set the full path in config.yaml)"
echo "  3. Activate the venv:  source .venv/bin/activate"
echo "  4. Run a dry-run to see what jobs are found:"
echo "       python main.py"
echo "  5. When ready to actually apply:"
echo "       python main.py --apply"
echo ""
echo "Other useful commands:"
echo "  python main.py --report              # Show stats on found/applied jobs"
echo "  python main.py --platform linkedin   # Run only LinkedIn"
echo "  python main.py --platform pnet       # Run only PNet"
echo "  python main.py --platform govza      # Run only SA Government jobs"
