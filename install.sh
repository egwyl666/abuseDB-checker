#!/usr/bin/env bash
# Install or update abuse-checker. Safe to re-run: existing configuration,
# IP list and state are never overwritten.
#
# Local mode (from a clone):
#   sudo ./install.sh [--no-enable] [--non-interactive|--no-wizard] [--upgrade-os]
# One-line mode (downloads the repository tarball itself):
#   curl -fsSL https://raw.githubusercontent.com/egwyl666/abuseDB-checker/main/install.sh | sudo bash
#   ... | sudo AC_BRANCH=<branch> bash        # install another branch
#
# The whole script is one { ... } block so bash parses it completely before
# running anything; with `curl | bash` nothing can then read the rest of the
# script from stdin by accident.
{
set -euo pipefail

REPO_SLUG="${AC_REPO:-egwyl666/abuseDB-checker}"
REPO_BRANCH="${AC_BRANCH:-main}"
ARCHIVE_URL="${ABUSE_CHECKER_GITHUB_ARCHIVE:-https://github.com/$REPO_SLUG/archive/refs/heads/$REPO_BRANCH.tar.gz}"
CURL="${ABUSE_CHECKER_CURL:-curl}"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd)" || SRC="$(pwd)"

# Bootstrap: no repository files next to us (piped from curl) -> download
# the tarball, verify it and run its install.sh with the same arguments.
if [[ ! -f "$SRC/abuse-checker.sh" || ! -d "$SRC/connectors" ]]; then
    [[ -z "${AC_BOOTSTRAPPED:-}" ]] || { echo "error: downloaded archive is incomplete" >&2; exit 1; }
    # tar/gzip are needed to unpack the archive; install them if absent.
    if ! command -v tar >/dev/null 2>&1 || ! command -v gzip >/dev/null 2>&1; then
        echo "==> installing tar/gzip"
        if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tar gzip
        elif command -v dnf >/dev/null; then dnf -q -y install tar gzip
        elif command -v yum >/dev/null; then yum -q -y install tar gzip
        elif command -v apk >/dev/null; then apk -q add --no-cache tar gzip
        elif command -v pacman >/dev/null; then pacman -Sy --needed --noconfirm tar gzip
        elif command -v zypper >/dev/null; then zypper --non-interactive --quiet install tar gzip
        fi </dev/null || true
    fi
    for t in curl tar gzip; do command -v "$t" >/dev/null 2>&1 || { echo "error: '$t' is required" >&2; exit 1; }; done
    BOOT="$(mktemp -d "${TMPDIR:-/tmp}/abuse-checker-install.XXXXXX")"
    trap 'rm -rf "$BOOT"' EXIT
    echo "==> downloading $REPO_SLUG@$REPO_BRANCH"
    printf 'url = "%s"\n' "$ARCHIVE_URL" \
        | "$CURL" --fail --silent --show-error --location --max-time 120 --config - -o "$BOOT/src.tar.gz" \
        || { echo "error: download failed: $ARCHIVE_URL" >&2; exit 1; }
    tar -xzf "$BOOT/src.tar.gz" -C "$BOOT" </dev/null || { echo "error: cannot extract archive" >&2; exit 1; }
    BOOT_SRC="$(find "$BOOT" -mindepth 2 -maxdepth 2 -name install.sh -printf '%h\n' | head -n1)"
    [[ -n "$BOOT_SRC" ]] || { echo "error: install.sh not found in archive" >&2; exit 1; }
    for f in "$BOOT_SRC"/install.sh "$BOOT_SRC"/abuse-checker.sh "$BOOT_SRC"/connectors/*.sh; do
        bash -n "$f" || { echo "error: syntax check failed for $(basename "$f"); aborting" >&2; exit 1; }
    done
    if [[ -n "${ABUSE_CHECKER_BOOTSTRAP_DRYRUN:-}" ]]; then
        echo "==> bootstrap verified: $BOOT_SRC"; exit 0
    fi
    AC_BOOTSTRAPPED=1 bash "$BOOT_SRC/install.sh" "$@"
    exit $?
fi
USER_NAME="abusechecker"
BIN="/usr/local/bin/abuse-checker"
CONF_DIR="/etc/abuse-checker"
STATE_DIR="/var/lib/abuse-checker"
UNIT_DIR="/etc/systemd/system"
DOC_DIR="/usr/local/share/doc/abuse-checker"
LIB_DIR="/usr/local/lib/abuse-checker"
ENABLE=true
INTERACTIVE=true
UPGRADE_OS=false

for a in "$@"; do
    case "$a" in
        --no-enable) ENABLE=false ;;
        --non-interactive|--no-wizard|-n) INTERACTIVE=false ;;
        --upgrade-os) UPGRADE_OS=true ;;
        -h|--help) echo "Usage: sudo $0 [--no-enable] [--non-interactive|--no-wizard] [--upgrade-os]"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"

# Interactive input: stdin when it is a terminal, otherwise /dev/tty (under
# `curl | sudo bash` stdin is the pipe). TTY_FD stays empty when there is
# no terminal at all or --non-interactive was given.
TTY_FD=""
if $INTERACTIVE && [[ -t 1 ]]; then
    if [[ -t 0 ]]; then TTY_FD=0
    elif { exec 3</dev/tty; } 2>/dev/null; then TTY_FD=3
    fi
fi

# System check: optional OS upgrade, then install any missing dependency
# (bash curl jq awk sed openssl flock coreutils findutils tar ca-certificates)
# with the detected package manager. The logic lives in abuse-checker.sh.
if ! $UPGRADE_OS && [[ -n "$TTY_FD" ]]; then
    read -r -u "$TTY_FD" -p "Would you like to update system packages (OS upgrade) before installing? [y/N] " reply || reply=""
    [[ "$reply" =~ ^[Yy] ]] && UPGRADE_OS=true
fi
say "checking system dependencies"
deps_args=(--install-deps)
$UPGRADE_OS && deps_args+=(--upgrade-os)
bash "$SRC/abuse-checker.sh" "${deps_args[@]}" </dev/null | sed 's/^/    /' \
    || die "required dependencies could not be installed (see above)"
command -v install >/dev/null 2>&1 || die "'install' (coreutils) is required"
for f in abuse-checker.sh systemd/abuse-checker.service systemd/abuse-checker.timer \
         systemd/abuse-checker-watchdog.service systemd/abuse-checker-watchdog.timer \
         config/secrets.conf.example config/ips.txt.example \
         connectors/10-telegram.sh connectors/20-slack.sh connectors/30-email.sh connectors/40-jira.sh; do
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
install -o root -g root -m 0644 "$SRC/systemd/abuse-checker-watchdog.service" "$UNIT_DIR/abuse-checker-watchdog.service"
install -o root -g root -m 0644 "$SRC/systemd/abuse-checker-watchdog.timer" "$UNIT_DIR/abuse-checker-watchdog.timer"

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
        systemctl enable --now abuse-checker-watchdog.timer
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
    if [[ "${3:-}" == "silent" ]]; then read -r -s -u "$TTY_FD" -p "    $2: " __v || __v=""; echo; else read -r -u "$TTY_FD" -p "    $2: " __v || __v=""; fi
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
    read -r -u "$TTY_FD" -p "(Tip: Press Enter or 'N' to skip and configure manually later via 'sudo abuse-checker --edit-secrets') " reply || reply=""
    [[ "$reply" =~ ^[Yy] ]] || { echo "Skipped. Configure later with: sudo abuse-checker --edit-secrets"; return 0; }
    echo "Every step is optional: press Enter to skip it."
    echo
    echo "  1/5 AbuseIPDB (https://www.abuseipdb.com/account/api)"
    ask v1 "API key(s), comma-separated" silent; put ABUSEIPDB_API_KEYS "$v1"
    echo "  2/5 Telegram connector"
    ask v1 "Bot token (from @BotFather)" silent
    if [[ -n "$v1" ]]; then ask v2 "Chat IDs, comma-separated (groups start with -100)"; put TELEGRAM_BOT_TOKEN "$v1"; put TELEGRAM_CHAT_IDS "$v2"; fi
    echo "  3/5 Slack connector"
    ask v1 "Incoming webhook URL(s), comma-separated" silent; put SLACK_WEBHOOK_URLS "$v1"
    echo "  4/5 Email connector"
    ask v1 "Recipients, comma-separated"
    if [[ -n "$v1" ]]; then
        put EMAIL_TO "$v1"
        ask v2 "SMTP URL (smtps://host:465 or smtp://host:587; Enter = local sendmail)"; put SMTP_URL "$v2"
        if [[ -n "$v2" ]]; then
            ask v3 "SMTP user"; put SMTP_USER "$v3"
            ask v4 "SMTP password" silent; put SMTP_PASS "$v4"
        fi
    fi
    echo "  5/5 Jira connector (creates/updates an issue per alert)"
    ask v1 "Jira base URL (e.g. https://company.atlassian.net)"
    if [[ -n "$v1" ]]; then
        put JIRA_BASE_URL "$v1"
        ask v2 "Project key (e.g. SEC)"; put JIRA_PROJECT_KEY "$v2"
        ask v3 "Account e-mail (Cloud; Enter = Server/DC personal access token)"; put JIRA_USER_EMAIL "$v3"
        ask v4 "API token" silent; put JIRA_API_TOKEN "$v4"
        ask v2 "Issue type (Enter = Task)"; put JIRA_ISSUE_TYPE "$v2"
    fi
    echo "  Check schedule"
    echo "    1) once a day at 06:00 (default)   2) twice a day (06:00, 18:00)"
    echo "    3) 4x a day (every 6h)              4) custom times, e.g. 07:30,19:30"
    read -r -u "$TTY_FD" -p "    Choose [1-4]: " v1 || v1=""
    case "$v1" in
        2) "$BIN" --schedule "06:00,18:00" | sed 's/^/    /' ;;
        3) "$BIN" --schedule "every 6h" | sed 's/^/    /' ;;
        4) read -r -u "$TTY_FD" -p "    Times (HH:MM,HH:MM,...) or OnCalendar expression: " v2 || v2=""
           if [[ -n "$v2" ]]; then "$BIN" --schedule "$v2" | sed 's/^/    /' || echo "    ! invalid schedule; keeping daily 06:00"; fi ;;
        *) echo "    keeping daily 06:00" ;;
    esac
    echo "  Automatic updates from GitHub ($REPO_SLUG)"
    read -r -u "$TTY_FD" -p "    Enable automatic updates from GitHub? [1=Notify only (default), 2=Auto-install, 3=Disabled] " v1 || v1=""
    case "$v1" in 2) v1=true ;; 3) v1=false ;; *) v1=notify ;; esac
    put AUTO_UPDATE "$v1"
    echo
    echo "Configuration stored encrypted ($("$BIN" --status 2>/dev/null | sed -n 's/^Secrets *: //p'))."
    read -r -u "$TTY_FD" -p "Send a test notification now (abuse-checker --test-notify)? [y/N] " reply || reply=""
    if [[ "$reply" =~ ^[Yy] ]]; then "$BIN" --test-notify || echo "test notification reported errors (see above)"; fi
}

# Under `curl | sudo bash` stdin is the pipe, so answers are read from the
# controlling terminal (/dev/tty) instead.
if [[ -n "$TTY_FD" ]]; then
    wizard
    [[ "$TTY_FD" == "3" ]] && exec 3<&-
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
exit 0
}
