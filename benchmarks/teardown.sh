#!/usr/bin/env bash
set -euo pipefail

# The '*backend-*.scope' wildcard elegantly catches both TCP and UDP agents
units=$(systemctl list-units '*backend-*.scope' --type=scope --all --no-legend --plain | awk '{print $1}')

if [ -z "$units" ]; then
  echo "No active backend agents found."
else
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
fi

# Reset failed states for any crashed scopes
systemctl reset-failed '*backend-*.scope' || true

# Clean up both TCP and UDP log directories
rm -rf /tmp/agents/
rm -rf /tmp/udp_agents/

echo "Teardown complete."
