#!/bin/sh
# Starts UnoKey Vault on Linux. Needs python3 with tkinter and pyserial.
cd "$(dirname "$0")/.." || exit 1
if ! python3 -c "import tkinter, serial" 2>/dev/null; then
  echo "Missing packages. Install them first:"
  echo "  Debian/Ubuntu: sudo apt install python3-tk python3-serial"
  echo "  Fedora:        sudo dnf install python3-tkinter python3-pyserial"
  echo "  Arch:          sudo pacman -S tk python-pyserial"
  exit 1
fi
exec python3 unokey_app.py "$@"
