#!/usr/bin/env bash
# Remove abuse-checker. Asks whether to keep configuration and state.
#   sudo ./uninstall.sh            interactive
#   sudo ./uninstall.sh --keep     keep /etc/abuse-checker and /var/lib/abuse-checker
#   sudo ./uninstall.sh --purge    remove everything, including the system user
set -euo pipefail

USER_NAME="abusechecker"
CONF_DIR="/etc/abuse-checker"
STATE_DIR="/var/lib/abuse-checker"
MODE="ask"

for a in "$@"; do
    case "$a" in
        --keep) MODE="keep" ;;
        --purge) MODE="purge" ;;
        -h|--help) echo "Usage: sudo $0 [--keep|--purge]"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
[[ $EUID -eq 0 ]] || { echo "error: run as root (sudo $0)" >&2; exit 1; }

# ask "question" -> 0 for yes. Default is "keep" (answer N to removal).
ask_remove() {
    local reply
    case "$MODE" in
        keep) return 1 ;;
        purge) return 0 ;;
    esac
    if [[ ! -t 0 ]]; then return 1; fi
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    say "stopping and disabling systemd units"
    systemctl disable --now abuse-checker.timer 2>/dev/null || true
    systemctl stop abuse-checker.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/abuse-checker.service /etc/systemd/system/abuse-checker.timer
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl reset-failed abuse-checker.service abuse-checker.timer 2>/dev/null || true
fi

say "removing /usr/local/bin/abuse-checker and docs"
rm -f /usr/local/bin/abuse-checker
rm -rf /usr/local/share/doc/abuse-checker

removed_conf=false removed_state=false
if [[ -d "$CONF_DIR" ]] && ask_remove "Remove configuration $CONF_DIR (API keys, IP list)?"; then
    rm -rf "$CONF_DIR"; removed_conf=true; say "removed $CONF_DIR"
else
    [[ -d "$CONF_DIR" ]] && say "kept $CONF_DIR"
fi
if [[ -d "$STATE_DIR" ]] && ask_remove "Remove state and reports $STATE_DIR?"; then
    rm -rf "$STATE_DIR"; removed_state=true; say "removed $STATE_DIR"
else
    [[ -d "$STATE_DIR" ]] && say "kept $STATE_DIR"
fi

if id "$USER_NAME" >/dev/null 2>&1; then
    if $removed_state && $removed_conf; then
        userdel "$USER_NAME" 2>/dev/null || true
        getent group "$USER_NAME" >/dev/null && groupdel "$USER_NAME" 2>/dev/null || true
        say "removed system user $USER_NAME"
    else
        say "kept system user $USER_NAME (owns retained files)"
    fi
fi
say "uninstall complete"
