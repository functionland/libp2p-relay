#!/usr/bin/env bash
# Install the discovery-API heartbeat on a libp2p-relay VM.
# Idempotent — safe to re-run.
#
# Run AFTER ../install.sh has set up the relay daemon itself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (use sudo)" >&2
    exit 1
fi

echo "==> Installing python3 + python3-cryptography"
apt-get update -qq
apt-get install -y python3 python3-cryptography

echo "==> Installing relay-heartbeat.py to /usr/local/bin/"
install -m 0755 "$SCRIPT_DIR/relay-heartbeat.py" /usr/local/bin/relay-heartbeat.py

echo "==> Installing systemd unit + timer"
install -m 0644 "$SCRIPT_DIR/relay-heartbeat.service" /etc/systemd/system/relay-heartbeat.service
install -m 0644 "$SCRIPT_DIR/relay-heartbeat.timer"   /etc/systemd/system/relay-heartbeat.timer

systemctl daemon-reload
systemctl enable --now relay-heartbeat.timer

echo "==> Testing the heartbeat (one immediate run)"
sudo -u libp2p-relay python3 /usr/local/bin/relay-heartbeat.py && \
    echo "Heartbeat OK" || \
    { echo "Heartbeat failed — check that the relay's KV entry has been seeded via wrangler"; exit 1; }

echo
echo "Done. Verify with:"
echo "  systemctl status relay-heartbeat.timer"
echo "  journalctl -u relay-heartbeat.service --since '5 minutes ago'"
