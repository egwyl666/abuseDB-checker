#!/usr/bin/env bash
# Install or update abuse-checker. Safe to re-run: existing configuration,
# IP list and state are never overwritten.
#   sudo ./install.sh [--no-enable]
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="abusechecker"
BIN="/usr/local/bin/abuse-checker"
CONF_DIR="/etc/abuse-checker"
STATE_DIR="/var/lib/abuse-checker"
UNIT_DIR="/etc/systemd/system"
DOC_DIR="/usr/local/share/doc/abuse-checker"
ENABLE=true

for a in "$@"; do
    case "$a" in
        --no-enable) ENABLE=false ;;
        -h|--help) echo "Usage: sudo $0 [--no-enable]"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
for t in bash curl jq awk sed date mktemp find install; do
    command -v "$t" >/dev/null 2>&1 || die "missing dependency '$t' (e.g. apt install curl jq)"
done
for f in abuse-checker.sh systemd/abuse-checker.service systemd/abuse-checker.timer \
         config/secrets.conf.example config/ips.txt.example; do
    [[ -f "$SRC/$f" ]] || die "missing source file: $f"
done
bash -n "$SRC/abuse-checker.sh" || die "abuse-checker.sh has syntax errors; aborting"

if ! id "$USER_NAME" >/dev/null 2>&1; then
    say "creating system user $USER_NAME"
    nologin="$(command -v nologin || echo /usr/sbin/nologin)"
    useradd --system --no-create-home --home-dir "$STATE_DIR" --shell "$nologin" \
        --user-group "$USER_NAME"
fi

UPDATE=false
[[ -f "$BIN" ]] && UPDATE=true
say "installing $BIN"
install -o root -g root -m 0755 "$SRC/abuse-checker.sh" "$BIN.new"
mv -f "$BIN.new" "$BIN"

say "configuring $CONF_DIR"
install -d -o root -g root -m 0755 "$CONF_DIR"
if [[ ! -e "$CONF_DIR/secrets.conf" ]]; then
    install -o root -g root -m 0600 "$SRC/config/secrets.conf.example" "$CONF_DIR/secrets.conf"
    say "created $CONF_DIR/secrets.conf (edit it and add your API key)"
else
    chown root:root "$CONF_DIR/secrets.conf"; chmod 0600 "$CONF_DIR/secrets.conf"
fi
install -o root -g root -m 0644 "$SRC/config/secrets.conf.example" "$CONF_DIR/secrets.conf.example"
if [[ ! -e "$CONF_DIR/ips.txt" ]]; then
    install -o root -g "$USER_NAME" -m 0644 "$SRC/config/ips.txt.example" "$CONF_DIR/ips.txt"
    say "created $CONF_DIR/ips.txt (add your IPs/subnets)"
else
    chown root:"$USER_NAME" "$CONF_DIR/ips.txt"; chmod 0644 "$CONF_DIR/ips.txt"
fi

say "preparing $STATE_DIR"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$STATE_DIR" "$STATE_DIR/reports"
chown "$USER_NAME:$USER_NAME" "$STATE_DIR" "$STATE_DIR/reports"
chmod 0750 "$STATE_DIR" "$STATE_DIR/reports"
if [[ ! -e "$STATE_DIR/state.json" ]]; then
    echo '{"version":1,"lastRun":null,"ips":{}}' > "$STATE_DIR/state.json"
fi
find "$STATE_DIR" -maxdepth 1 -name 'state*.json' -exec chown "$USER_NAME:$USER_NAME" {} + -exec chmod 0640 {} +
find "$STATE_DIR/reports" -type f -exec chown "$USER_NAME:$USER_NAME" {} + -exec chmod 0640 {} +

say "installing systemd units"
install -o root -g root -m 0644 "$SRC/systemd/abuse-checker.service" "$UNIT_DIR/abuse-checker.service"
install -o root -g root -m 0644 "$SRC/systemd/abuse-checker.timer" "$UNIT_DIR/abuse-checker.timer"

if [[ -f "$SRC/README.md" ]]; then
    install -d -m 0755 "$DOC_DIR"
    install -m 0644 "$SRC/README.md" "$DOC_DIR/README.md"
    [[ -f "$SRC/README.uk.md" ]] && install -m 0644 "$SRC/README.uk.md" "$DOC_DIR/README.uk.md"
fi

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    if $ENABLE; then
        systemctl enable --now abuse-checker.timer
        say "timer enabled: $(systemctl show abuse-checker.timer -p NextElapseUSecRealtime --value)"
    fi
else
    say "systemd not running; units copied but not enabled"
fi

if $UPDATE; then say "update complete ($("$BIN" --version))"; else say "install complete ($("$BIN" --version))"; fi
cat <<MSG

Next steps:
  1. sudo editor $CONF_DIR/secrets.conf     # ABUSEIPDB_API_KEYS, Telegram/Slack/Email
  2. sudo editor $CONF_DIR/ips.txt          # IPs and CIDRs to monitor
  3. sudo -u $USER_NAME abuse-checker --dry-run   # or: sudo abuse-checker --test-notify
  4. sudo systemctl start abuse-checker.service && journalctl -u abuse-checker -n 50
MSG
