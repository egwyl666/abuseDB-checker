# shellcheck shell=bash
# abuse-checker connector: Email
# Loaded by abuse-checker from /usr/local/lib/abuse-checker/connectors.d/ in a
# subshell. Interface: connector_enabled (return 0 when configured) and
# connector_send <classified.json> <report.html> <title>.
# Settings (EMAIL_TO, EMAIL_FROM, SMTP_URL, SMTP_USER, SMTP_PASS) come from the encrypted secrets store.

# shellcheck disable=SC2034  # read by abuse-checker
CONNECTOR_NAME="Email"

connector_enabled() { [[ -n "${EMAIL_TO:-}" ]]; }

connector_send() {
    local data="$1" report="$2" title="$3" msg boundary rcpt cfg to_hdr
    msg="$TMPD/mail.eml"; boundary="=_ac_$(date +%s)_$$"
    to_hdr="$(split_csv "$EMAIL_TO" | paste -sd, - | sed 's/,/, /g')"
    {
        printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n' \
            "$EMAIL_FROM" "$to_hdr" "$title" "$(date -R)"
        printf 'Content-Type: multipart/mixed; boundary="%s"\r\n\r\n' "$boundary"
        printf -- '--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n' "$boundary"
        plain_summary "$data" "$title" | sed 's/$/\r/'
        if [[ -f "$report" ]]; then
            printf '\r\n--%s\r\nContent-Type: text/html; charset=utf-8; name="%s"\r\n' "$boundary" "$(basename "$report")"
            printf 'Content-Disposition: attachment; filename="%s"\r\nContent-Transfer-Encoding: base64\r\n\r\n' "$(basename "$report")"
            base64 -w 76 "$report" | sed 's/$/\r/'
        fi
        printf '\r\n--%s--\r\n' "$boundary"
    } > "$msg"
    if [[ -n "${SMTP_URL:-}" ]]; then
        cfg="$(cfg_line url "$SMTP_URL")
$(cfg_line mail-from "${SMTP_FROM:-${EMAIL_FROM}}")
$(cfg_line upload-file "$msg")"
        [[ -n "${SMTP_USER:-}" ]] && cfg+=$'\n'"$(cfg_line user "${SMTP_USER}:${SMTP_PASS:-}")"
        [[ "$SMTP_URL" == smtp://* ]] && cfg+=$'\n'"ssl-reqd"
        while IFS= read -r rcpt; do cfg+=$'\n'"$(cfg_line mail-rcpt "$rcpt")"; done < <(split_csv "$EMAIL_TO")
        if secure_curl "$cfg" --max-time 60; then info "Email: sent to $to_hdr via SMTP"; else warn "Email via SMTP failed"; fi
    elif command -v sendmail >/dev/null 2>&1; then
        if sendmail -t < "$msg"; then info "Email: sent to $to_hdr via sendmail"; else warn "Email via sendmail failed"; fi
    else
        warn "EMAIL_TO is set but neither SMTP_URL nor sendmail is available"
    fi
}
