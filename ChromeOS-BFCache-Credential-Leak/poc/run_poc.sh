#!/bin/bash
# Reproduces: Blink sticky user-activation (navigator.userActivation.hasBeenActive)
# survives a genuine back-forward-cache (BFCache) restore, with a real OS-level
# trusted input event (xdotool -> X11 input stack) and a normal Chromium process
# (no --remote-debugging-*, no CDP attached -- CDP attachment disables BFCache).
#
# Requires: a local X display (DISPLAY set), xdotool, python3, /usr/bin/chromium
# (or edit CHROMIUM_BIN below).
set -euo pipefail
cd "$(dirname "$0")"

CHROMIUM_BIN="${CHROMIUM_BIN:-/usr/bin/chromium}"
PORT=8901
PROFILE=$(mktemp -d /tmp/chromium-bfcache-poc-profile.XXXXXX)
LOG="$(pwd)/server.log"
rm -f "$LOG"

echo "[*] Starting local static+report server on 127.0.0.1:${PORT}"
python3 server.py &
SERVER_PID=$!
sleep 1

cleanup() {
  kill -9 "$SERVER_PID" 2>/dev/null || true
  kill -9 "$CHROME_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Launching a real Chromium process (no CDP/remote-debugging) with a fresh profile"
DISPLAY="${DISPLAY:-:0.0}" "$CHROMIUM_BIN" \
  --user-data-dir="$PROFILE" \
  --no-first-run --no-default-browser-check \
  --window-size=1000,800 --window-position=0,0 \
  "http://127.0.0.1:${PORT}/pageA.html" &
CHROME_PID=$!
sleep 3

echo "[*] Sending a REAL trusted keyboard-activated click on the benign button"
DISPLAY="${DISPLAY:-:0.0}" xdotool key Return
sleep 1

echo "[*] Navigating to the neutral Page B (Tab to link, Enter to follow)"
DISPLAY="${DISPLAY:-:0.0}" xdotool key Tab
sleep 0.3
DISPLAY="${DISPLAY:-:0.0}" xdotool key Return
sleep 1.5

echo "[*] Navigating back (Alt+Left) -- this should restore Page A from BFCache"
DISPLAY="${DISPLAY:-:0.0}" xdotool key alt+Left
sleep 1.5

echo ""
echo "=== server.log (annotated) ==="
cat "$LOG"
echo ""

if grep -q 'event=pageshow&persisted=true&hasBeenActive=true' "$LOG"; then
  echo "[+] CONFIRMED: Page A was restored from BFCache (persisted=true) with"
  echo "    hasBeenActive still true from the PRE-navigation click -- zero fresh"
  echo "    gesture occurred on the restored page."
else
  echo "[-] Did not observe the expected pageshow line. See server.log above."
fi
