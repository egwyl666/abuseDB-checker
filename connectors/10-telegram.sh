# shellcheck shell=bash
# abuse-checker connector: Telegram
# Loaded by abuse-checker from /usr/local/lib/abuse-checker/connectors.d/ in a
# subshell. Interface: connector_enabled (return 0 when configured) and
# connector_send <classified.json> <report.html> <title>.
# Settings (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_IDS) come from the encrypted secrets store.

# shellcheck disable=SC2034  # read by abuse-checker
CONNECTOR_NAME="Telegram"

connector_enabled() { [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_IDS:-}" ]]; }

connector_send() {
    local data="$1" report="$2" title="$3" text chat cfg ok=0 fail=0
    text="$(jq -r --arg title "$title" --argjson force "$FORCE_FULL" '
        def e: tostring | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;");
        def icon: {"NEW":"🔴","ESCALATED":"🟠","UNCHANGED":"🟡"}[.status] // "";
        [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
        | "<b>\($title|e)</b>\n"
        + "Checked <b>\(length)</b> · New <b>\(map(select(.status=="NEW"))|length)</b> · Escalated <b>\(map(select(.status=="ESCALATED"))|length)</b>\n\n"
        + ([$a[:25][] | "\(icon) <code>\(.target|e)</code> — \(.score)% · \(.total) reports" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "\n    <i>\(.isp|e)</i>" else "" end)] | join("\n"))
        + (if ($a|length) > 25 then "\n…and \(($a|length) - 25) more (see report)" else "" end)
        + "\n\n<i>\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted.</i>"' "$data")"
    while IFS= read -r chat; do
        cfg="$(cfg_line url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form-string "parse_mode=HTML")
$(cfg_line form-string "disable_web_page_preview=true")
$(cfg_line form-string "text=$text")"
        if secure_curl "$cfg" --max-time 30 --fail -o /dev/null; then ok=$((ok+1)); else fail=$((fail+1)); warn "Telegram sendMessage to chat $chat failed"; fi
        if [[ -f "$report" ]]; then
            cfg="$(cfg_line url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form "document=@$report;type=text/html")
$(cfg_line form-string "caption=Interactive report: $(basename "$report")")"
            secure_curl "$cfg" --max-time 60 --fail -o /dev/null || { fail=$((fail+1)); warn "Telegram sendDocument to chat $chat failed"; }
        fi
    done < <(split_csv "$TELEGRAM_CHAT_IDS")
    info "Telegram: $ok chat(s) notified, $fail failure(s)"
}
