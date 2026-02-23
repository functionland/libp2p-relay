#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
KUBO_VERSION="v0.39.0"
IPFS_PATH="/var/lib/libp2p-relay"
SERVICE_USER="libp2p-relay"
EXPECTED_PEER_ID="12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Parse arguments ────────────────────────────────────────────────────────
IDENTITY_FILE=""
SSH_PUBKEY_FILE=""
SSH_USER=""

usage() {
    echo "Usage: $0 --identity /path/to/identity.key --ssh-pubkey /path/to/key.pub --ssh-user USERNAME"
    echo ""
    echo "Sets up a production libp2p circuit relay v2 server using Kubo."
    echo "Safe to re-run — idempotent. Updates config and restarts as needed."
    echo ""
    echo "Options:"
    echo "  --identity FILE     Path to the binary protobuf identity key file (required)"
    echo "                      (the .key file from go-libp2p-relay-daemon)"
    echo "  --ssh-pubkey FILE   Path to SSH public key (.pub) for key-only auth (required)"
    echo "                      (corresponds to your .pem private key)"
    echo "  --ssh-user USER     SSH user to configure key-based auth for (required)"
    echo "  --help              Show this help message"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity)
            IDENTITY_FILE="$2"
            shift 2
            ;;
        --ssh-pubkey)
            SSH_PUBKEY_FILE="$2"
            shift 2
            ;;
        --ssh-user)
            SSH_USER="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            echo "Error: Unknown option $1"
            usage
            ;;
    esac
done

if [[ -z "$IDENTITY_FILE" ]]; then
    echo "Error: --identity is required"
    usage
fi

if [[ ! -f "$IDENTITY_FILE" ]]; then
    echo "Error: Identity file not found: $IDENTITY_FILE"
    exit 1
fi

if [[ -z "$SSH_PUBKEY_FILE" ]]; then
    echo "Error: --ssh-pubkey is required"
    usage
fi

if [[ ! -f "$SSH_PUBKEY_FILE" ]]; then
    echo "Error: SSH public key file not found: $SSH_PUBKEY_FILE"
    exit 1
fi

if [[ -z "$SSH_USER" ]]; then
    echo "Error: --ssh-user is required"
    usage
fi

if ! id "$SSH_USER" &>/dev/null; then
    echo "Error: SSH user '$SSH_USER' does not exist on this system"
    exit 1
fi

# ─── Must run as root ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (or with sudo)"
    exit 1
fi

echo "==> Installing libp2p Relay v2 (Kubo ${KUBO_VERSION})"

# ─── 0. Ensure dependencies ─────────────────────────────────────────────────
if ! command -v jq &>/dev/null || ! command -v curl &>/dev/null; then
    echo "==> Installing dependencies (jq, curl)..."
    apt-get update -qq && apt-get install -y -qq jq curl >/dev/null
fi

# ─── 1. Stop existing service if running ─────────────────────────────────────
if systemctl is-active --quiet relay.service 2>/dev/null; then
    echo "==> Stopping existing relay service for update..."
    systemctl stop relay.service
fi

# ─── 2. Detect architecture and download Kubo ───────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    armv7l)  GOARCH="arm" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

TARBALL="kubo_${KUBO_VERSION}_linux-${GOARCH}.tar.gz"
DOWNLOAD_URL="https://dist.ipfs.tech/kubo/${KUBO_VERSION}/${TARBALL}"

NEED_DOWNLOAD=false
if command -v ipfs &>/dev/null; then
    INSTALLED_VERSION="$(ipfs version --number 2>/dev/null || true)"
    EXPECTED_VERSION="${KUBO_VERSION#v}"
    if [[ "$INSTALLED_VERSION" == "$EXPECTED_VERSION" ]]; then
        echo "    Kubo ${KUBO_VERSION} already installed, skipping download"
    else
        echo "    Upgrading Kubo from ${INSTALLED_VERSION} to ${KUBO_VERSION}"
        NEED_DOWNLOAD=true
    fi
else
    NEED_DOWNLOAD=true
fi

if [[ "$NEED_DOWNLOAD" == "true" ]]; then
    echo "==> Downloading Kubo ${KUBO_VERSION} for ${GOARCH}..."
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TARBALL}"
    tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"
    install -m 0755 "${TMP_DIR}/kubo/ipfs" /usr/local/bin/ipfs

    echo "    Installed: $(ipfs version)"
fi

# ─── 3. Create service user ─────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "==> Creating service user: $SERVICE_USER"
    useradd --system --shell /usr/sbin/nologin --home-dir "$IPFS_PATH" "$SERVICE_USER"
else
    echo "    Service user $SERVICE_USER already exists"
fi

# ─── 4. Initialize IPFS repo ────────────────────────────────────────────────
KUBO_CONFIG="${IPFS_PATH}/config"

if [[ ! -f "$KUBO_CONFIG" ]]; then
    echo "==> Initializing IPFS repo at $IPFS_PATH"
    mkdir -p "$IPFS_PATH"
    chown "$SERVICE_USER":"$SERVICE_USER" "$IPFS_PATH"
    sudo -u "$SERVICE_USER" IPFS_PATH="$IPFS_PATH" ipfs init --profile server
else
    echo "    IPFS repo already exists at $IPFS_PATH"
fi

# ─── 5. Import identity ─────────────────────────────────────────────────────
echo "==> Importing identity from $IDENTITY_FILE"

PRIVKEY_B64="$(base64 -w 0 < "$IDENTITY_FILE")"

# Check if identity already matches
CURRENT_PEER_ID="$(jq -r '.Identity.PeerID // empty' "$KUBO_CONFIG" 2>/dev/null || true)"
CURRENT_PRIVKEY="$(jq -r '.Identity.PrivKey // empty' "$KUBO_CONFIG" 2>/dev/null || true)"

if [[ "$CURRENT_PEER_ID" == "$EXPECTED_PEER_ID" && "$CURRENT_PRIVKEY" == "$PRIVKEY_B64" ]]; then
    echo "    Identity already up to date (PeerID: $EXPECTED_PEER_ID)"
else
    # Patch both PrivKey and PeerID into the config JSON.
    # Kubo does NOT re-derive PeerID from PrivKey — both must match.
    jq --arg key "$PRIVKEY_B64" --arg pid "$EXPECTED_PEER_ID" \
      '.Identity.PrivKey = $key | .Identity.PeerID = $pid' \
      "$KUBO_CONFIG" > "${KUBO_CONFIG}.tmp"
    mv "${KUBO_CONFIG}.tmp" "$KUBO_CONFIG"
    chown "$SERVICE_USER":"$SERVICE_USER" "$KUBO_CONFIG"
    echo "    Private key and PeerID ($EXPECTED_PEER_ID) injected into $KUBO_CONFIG"
fi

# ─── 6. Apply relay-optimized configuration ─────────────────────────────────
echo "==> Applying relay configuration..."

# Use jq to deep-merge all relay settings into the config JSON in one shot.
# This avoids issues with `ipfs config` refusing to create nested objects.
# Safe to re-run: overwrites the same keys with the same values.
jq '. * {
  "Swarm": {
    "RelayService": {
      "Enabled": true,
      "MaxReservations": 2048,
      "MaxCircuits": 512,
      "MaxReservationsPerIP": 32,
      "MaxReservationsPerASN": 256,
      "BufferSize": 16384,
      "ReservationTTL": "1h0m0s",
      "Limit": {
        "Duration": "5m0s",
        "Data": 1048576
      }
    },
    "RelayClient": {
      "Enabled": false
    },
    "DisableRelay": false,
    "ConnMgr": {
      "Type": "basic",
      "LowWater": 1024,
      "HighWater": 2048,
      "GracePeriod": "2m0s"
    }
  },
  "Addresses": {
    "Swarm": [
      "/ip4/0.0.0.0/tcp/4001",
      "/ip6/::/tcp/4001",
      "/ip4/0.0.0.0/udp/4001/quic-v1",
      "/ip6/::/udp/4001/quic-v1",
      "/ip4/0.0.0.0/udp/4001/quic-v1/webtransport",
      "/ip6/::/udp/4001/quic-v1/webtransport"
    ],
    "API": "/ip4/127.0.0.1/tcp/5001",
    "Gateway": "",
    "Announce": [
      "/dns/relay.dev.fx.land/tcp/4001",
      "/dns/relay.dev.fx.land/udp/4001/quic-v1",
      "/dns/relay.dev.fx.land/udp/4001/quic-v1/webtransport"
    ]
  },
  "Provide": {
    "Strategy": "",
    "DHT": {
      "Interval": "0"
    }
  }
}
| del(.Reprovider)
' "$KUBO_CONFIG" > "${KUBO_CONFIG}.tmp"
mv "${KUBO_CONFIG}.tmp" "$KUBO_CONFIG"
chown "$SERVICE_USER":"$SERVICE_USER" "$KUBO_CONFIG"

echo "    Configuration applied."

# ─── 7. SSH hardening ────────────────────────────────────────────────────────
echo "==> Hardening SSH..."

# Install the public key for the specified user
SSH_USER_HOME="$(eval echo "~${SSH_USER}")"
SSH_DIR="${SSH_USER_HOME}/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Append pubkey if not already present
PUBKEY_CONTENT="$(cat "$SSH_PUBKEY_FILE")"
if [[ -f "$AUTHORIZED_KEYS" ]] && grep -qF "$PUBKEY_CONTENT" "$AUTHORIZED_KEYS"; then
    echo "    Public key already in authorized_keys"
else
    echo "$PUBKEY_CONTENT" >> "$AUTHORIZED_KEYS"
    echo "    Public key added to $AUTHORIZED_KEYS"
fi

chmod 600 "$AUTHORIZED_KEYS"
chown -R "${SSH_USER}":"$(id -gn "$SSH_USER")" "$SSH_DIR"

# Back up sshd_config before modifying (only on first run)
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ ! -f "${SSHD_CONFIG}.bak.pre-relay" ]]; then
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.pre-relay"
    echo "    Backed up sshd_config to ${SSHD_CONFIG}.bak.pre-relay"
fi

# Apply hardened SSH settings via a drop-in to avoid clobbering the main config
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
mkdir -p "$SSHD_DROPIN_DIR"

# If SSH_USER is root, allow root login with key only; otherwise disable root login
if [[ "$SSH_USER" == "root" ]]; then
    ROOT_LOGIN_SETTING="PermitRootLogin prohibit-password"
else
    ROOT_LOGIN_SETTING="PermitRootLogin no"
fi

cat > "${SSHD_DROPIN_DIR}/50-relay-hardening.conf" <<SSHD
# Disable password authentication — key-only (.pem) access
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Root login policy (based on --ssh-user)
${ROOT_LOGIN_SETTING}

# Only allow pubkey auth
PubkeyAuthentication yes
AuthenticationMethods publickey

# Disable unused auth methods
GSSAPIAuthentication no
UsePAM yes

# Limit login attempts and sessions
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30

# Disable X11 and agent forwarding (not needed on a relay)
X11Forwarding no
AllowAgentForwarding no

# Disable TCP forwarding (not needed)
AllowTcpForwarding no
SSHD

echo "    SSH hardening drop-in written to ${SSHD_DROPIN_DIR}/50-relay-hardening.conf"

# Ensure the main sshd_config includes drop-ins (most modern distros do by default)
if ! grep -q "^Include.*/etc/ssh/sshd_config.d/" "$SSHD_CONFIG"; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONFIG"
    echo "    Added Include directive to sshd_config"
fi

# Validate config before restarting
if sshd -t 2>/dev/null; then
    systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
    echo "    SSH restarted with key-only authentication"
else
    echo "ERROR: sshd config validation failed! Reverting..."
    rm -f "${SSHD_DROPIN_DIR}/50-relay-hardening.conf"
    systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
    echo "    Reverted SSH changes. Please check sshd_config manually."
    exit 1
fi

# ─── 8. Firewall rules ──────────────────────────────────────────────────────
echo "==> Configuring firewall (ufw)..."
if command -v ufw &>/dev/null; then
    # All ufw commands are idempotent — safe to re-run
    ufw allow 4001/tcp comment "libp2p relay TCP"
    ufw allow 4001/udp comment "libp2p relay QUIC/WebTransport"
    ufw allow 22/tcp comment "SSH"
    ufw deny in on any to any port 5001 comment "Block external IPFS API"

    if ! ufw status | grep -q "Status: active"; then
        echo "y" | ufw enable
    fi

    ufw status verbose
else
    echo "    ufw not found — skipping firewall setup."
    echo "    Make sure ports 4001/tcp and 4001/udp are open, and 5001 is blocked externally."
fi

# ─── 9. Kernel tuning for high connection counts ────────────────────────────
echo "==> Applying sysctl tuning..."
SYSCTL_CONF="/etc/sysctl.d/99-libp2p-relay.conf"
cat > "$SYSCTL_CONF" <<'SYSCTL'
# libp2p relay — tuning for high connection counts
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000
SYSCTL
sysctl --system --quiet
echo "    Sysctl tuning applied."

# ─── 10. Install systemd service ────────────────────────────────────────────
echo "==> Installing systemd service..."
install -m 0644 "${SCRIPT_DIR}/relay.service" /etc/systemd/system/relay.service
systemctl daemon-reload

# ─── 11. Enable and start ───────────────────────────────────────────────────
echo "==> Enabling and starting relay service..."
systemctl enable relay.service
systemctl restart relay.service

# Wait a moment for startup
sleep 3

if systemctl is-active --quiet relay.service; then
    echo ""
    echo "==> Relay is running!"
    echo ""
    echo "Verify:"
    echo "  sudo -u $SERVICE_USER IPFS_PATH=$IPFS_PATH ipfs id"
    echo "  sudo -u $SERVICE_USER IPFS_PATH=$IPFS_PATH ipfs config Swarm.RelayService.Enabled"
    echo "  curl -s http://127.0.0.1:5001/debug/metrics/prometheus | grep relay"
    echo "  systemctl status relay.service"
else
    echo ""
    echo "WARNING: Service failed to start. Check logs:"
    echo "  journalctl -u relay.service -n 50 --no-pager"
    exit 1
fi
