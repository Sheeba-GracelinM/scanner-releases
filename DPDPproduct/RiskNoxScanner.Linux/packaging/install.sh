#!/usr/bin/env bash
# Optional: add the scanner to the desktop's application menu for the current user.
# The executable also runs as-is from any folder (double-click or ./RiskNoxScanner).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"; APPS="$HOME/.local/share/applications"; ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"
mkdir -p "$BIN" "$APPS" "$ICONS"
install -m 755 "$HERE/RiskNoxScanner" "$BIN/RiskNoxScanner"
install -m 644 "$HERE/risknox.svg" "$ICONS/risknox.svg"
sed "s|^Exec=RiskNoxScanner|Exec=$BIN/RiskNoxScanner|" "$HERE/risknox-scanner.desktop" > "$APPS/risknox-scanner.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" || true
echo "Installed: $BIN/RiskNoxScanner (menu entry: Risknox PII Scanner)"
command -v tesseract >/dev/null || echo "Tip: install Tesseract for OCR of images/scanned PDFs (e.g. sudo apt install tesseract-ocr)."
