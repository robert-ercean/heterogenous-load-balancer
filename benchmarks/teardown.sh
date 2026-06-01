#!/usr/bin/env bash
set -euo pipefail

units=$(systemctl list-units 'backend-*.scope' --type=scope --all --no-legend --plain | awk '{print $1}')

for unit in $units; do
  echo "Killing $unit"
  systemctl kill "$unit" --kill-who=all --signal=TERM || true
done

sleep 2

for unit in $units; do
  if systemctl is-active --quiet "$unit"; then
    echo "Force killing $unit"
    systemctl kill "$unit" --kill-who=all --signal=KILL || true
  fi
done

systemctl reset-failed 'backend-*.scope' || true
rm -rf /tmp/agents/