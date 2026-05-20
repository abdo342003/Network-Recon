#!/usr/bin/env sh
# Build single-file executable on Linux (also usable on WSL) with PyInstaller
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
SPEC="$ROOT/windows/network_recon.spec"
if [ ! -x "$PY" ]; then
  echo "Virtualenv not found; run ./install.sh first"
  exit 1
fi
"$PY" -m pip install --upgrade pyinstaller
cd "$ROOT"
"$PY" -m PyInstaller --noconfirm --clean "$SPEC"
echo "Build complete. See the dist/ folder."
