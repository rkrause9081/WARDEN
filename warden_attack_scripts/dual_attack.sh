#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-15}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[WARDEN] Dual MQTT + CoAP attack demo"
echo "Duration: $DURATION seconds"

if ! command -v timeout >/dev/null 2>&1; then
  echo "Error: timeout not found."
  exit 1
fi

timeout "$DURATION" "$SCRIPT_DIR/mqtt_sustained_flood.sh" localhost icu/test 0.01 WARDEN_DUAL_MQTT &
MQTT_PID=$!

timeout "$DURATION" python3 "$SCRIPT_DIR/coap_flood.py" --host 127.0.0.1 --port 5683 --delay 0.001 --forever &
COAP_PID=$!

wait "$MQTT_PID" 2>/dev/null || true
wait "$COAP_PID" 2>/dev/null || true

echo "[WARDEN] Dual attack demo complete."
