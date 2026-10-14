#!/usr/bin/env bash
# Install or update abuse-checker. Safe to re-run: existing configuration,
# IP list and state are never overwritten.
#   sudo ./install.sh [--no-enable] [--non-interactive]
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="abusechecker"
BIN="/usr/local/bin/abuse-checker"
CONF_DIR="/etc/abuse-checker"
STATE_DIR="/var/lib/abuse-checker"
UNIT_DIR="/etc/systemd/system"
DOC_DIR="/usr/local/share/doc/abuse-checker"
LIB_DIR="/usr/local/lib/abuse-checker"
ENABLE=true
INTERACTIVE=true

for a in "$@"; do
    case "$a" in
        --no-enable) ENABLE=false ;;
        --non-interactive|-n) INTERACTIVE=false ;;
        -h|--help) echo "Usage: sudo $0 [--no-enable] [--non-interactive]"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
for t in bash curl jq awk sed date mktemp find install openssl; do
    command -v "$t" >/dev/null 2>&1 || die "missing dependency '$t' (e.g. apt install curl jq)"
done
for f in abuse-checker.sh systemd/abuse-checker.service systemd/abuse-checker.timer \
         config/secrets.conf.example config/ips.txt.example \
         connectors/10-telegram.sh connectors/20-slack.sh connectors/30-email.sh; do
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
install -o root -g root -m 0644 "$SRC/config/secrets.conf.example" "$CONF_DIR/secrets.conf.example"
say "installing connectors to $LIB_DIR/connectors.d"
install -d -o root -g root -m 0755 "$LIB_DIR" "$LIB_DIR/connectors.d"
for f in "$SRC"/connectors/*.sh "$SRC"/connectors/*.example; do
    [[ -e "$f" ]] && install -o root -g root -m 0644 "$f" "$LIB_DIR/connectors.d/$(basename "$f")"
done

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

# Secrets: encrypted at rest. Fresh installs get an encrypted template;
# legacy plain-text files are left in place with a hint.
if [[ -e "$CONF_DIR/secrets.conf" ]]; then
    chown root:root "$CONF_DIR/secrets.conf"; chmod 0600 "$CONF_DIR/secrets.conf"
    say "plain-text $CONF_DIR/secrets.conf found; encrypt it with: sudo abuse-checker --encrypt-secrets"
elif [[ ! -e "$CONF_DIR/secrets.conf.enc" && ! -e "$CONF_DIR/secrets.cred" ]]; then
    say "creating encrypted secrets store"
    printf '%s' "" | "$BIN" --set-secret ABUSEIPDB_API_KEYS
fi
[[ -e "$CONF_DIR/secrets.conf.enc" ]] && { chown root:"$USER_NAME" "$CONF_DIR/secrets.conf.enc"; chmod 0640 "$CONF_DIR/secrets.conf.enc"; }
[[ -e "$CONF_DIR/.master.key" ]] && { chown root:root "$CONF_DIR/.master.key"; chmod 0400 "$CONF_DIR/.master.key"; }
[[ -e "$CONF_DIR/secrets.cred" ]] && { chown root:root "$CONF_DIR/secrets.cred"; chmod 0600 "$CONF_DIR/secrets.cred"; }
"$BIN" --refresh-unit

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
# ---------------------------------------------------------------------------
# Optional onboarding wizard
# ---------------------------------------------------------------------------
# ask VAR "prompt" [silent]: read one answer; Enter = skip.
ask() {
    local __v
    if [[ "${3:-}" == "silent" ]]; then read -r -s -p "    $2: " __v; echo; else read -r -p "    $2: " __v; fi
    printf -v "$1" '%s' "$__v"
}
# put KEY VALUE: store via stdin so the value never shows up in `ps`.
put() {
    [[ -n "$2" ]] || return 0
    if [[ "$2" == *"'"* ]]; then echo "    ! values may not contain single quotes; skipped $1"; return 0; fi
    printf '%s\n' "$2" | "$BIN" --set-secret "$1" >/dev/null 2>&1 && echo "    saved $1 (encrypted)"
}

wizard() {
    local reply v1 v2 v3 v4
    echo
    echo "Would you like to configure API keys and notification connectors now? [y/N]"
    read -r -p "(Tip: Press Enter or 'N' to skip and configure manually later via 'sudo abuse-checker --edit-secrets') " reply || reply=""
    [[ "$reply" =~ ^[Yy] ]] || { echo "Skipped. Configure later with: sudo abuse-checker --edit-secrets"; return 0; }
    echo "Every step is optional: press Enter to skip it."
    echo
    echo "  1/4 AbuseIPDB (https://www.abuseipdb.com/account/api)"
    ask v1 "API key(s), comma-separated" silent; put ABUSEIPDB_API_KEYS "$v1"
    echo "  2/4 Telegram connector"
    ask v1 "Bot token (from @BotFather)" silent
    if [[ -n "$v1" ]]; then ask v2 "Chat IDs, comma-separated (groups start with -100)"; put TELEGRAM_BOT_TOKEN "$v1"; put TELEGRAM_CHAT_IDS "$v2"; fi
    echo "  3/4 Slack connector"
    ask v1 "Incoming webhook URL(s), comma-separated" silent; put SLACK_WEBHOOK_URLS "$v1"
    echo "  4/4 Email connector"
    ask v1 "Recipients, comma-separated"
    if [[ -n "$v1" ]]; then
        put EMAIL_TO "$v1"
        ask v2 "SMTP URL (smtps://host:465 or smtp://host:587; Enter = local sendmail)"; put SMTP_URL "$v2"
        if [[ -n "$v2" ]]; then
            ask v3 "SMTP user"; put SMTP_USER "$v3"
            ask v4 "SMTP password" silent; put SMTP_PASS "$v4"
        fi
    fi
    echo
    echo "Configuration stored encrypted ($("$BIN" --status 2>/dev/null | sed -n 's/^Secrets *: //p'))."
    read -r -p "Send a test notification now (abuse-checker --test-notify)? [y/N] " reply || reply=""
    if [[ "$reply" =~ ^[Yy] ]]; then "$BIN" --test-notify || echo "test notification reported errors (see above)"; fi
}

if $INTERACTIVE && [[ -t 0 && -t 1 ]]; then
    wizard
fi

cat <<MSG

Next steps:
  sudo abuse-checker --edit-secrets           # API keys, Telegram/Slack/Email (encrypted)
  sudo editor $CONF_DIR/ips.txt               # IPs and CIDRs to monitor
  sudo abuse-checker --dry-run                # pipeline check with mock data
  sudo abuse-checker --test-notify            # test alert to every connector
  sudo systemctl start abuse-checker.service && journalctl -u abuse-checker -n 50
  sudo abuse-checker --uninstall              # remove (menu)
MSG
