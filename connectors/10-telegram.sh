# shellcheck shell=bash
# abuse-checker connector: Telegram
# Loaded by abuse-checker from /usr/local/lib/abuse-checker/connectors.d/ in a
# subshell. Interface: connector_enabled (return 0 when configured) and
# connector_send <classified.json> <report.html> <title>.
#
# Settings (from the encrypted secrets store), one pair per bot:
#   TELEGRAM_BOT_TOKEN   + TELEGRAM_CHAT_IDS      bot 1
#   TELEGRAM_BOT_TOKEN_2 + TELEGRAM_CHAT_IDS_2    bot 2, and so on (_3, _4, ...)
# Each bot writes ONLY to the chat IDs listed next to it. Chat IDs must be
# numeric (123456789, -1001234567890) or a public @channelname; anything
# else is skipped with a warning before any request is made. A chat listed
# for several bots gets the alert once (from the first bot). The bot never
# reads incoming messages, so strangers who write to it get nothing.

# shellcheck disable=SC2034  # read by abuse-checker
CONNECTOR_NAME="Telegram"

# Print "<suffix>" for every configured bot: "" for the base pair, then
# _2, _3, ... in numeric order.
_tg_bots() {
    local v
    [[ -n "${TELEGRAM_BOT_TOKEN:-}${TELEGRAM_CHAT_IDS:-}" ]] && echo ""
    for v in $(compgen -v | grep -E '^TELEGRAM_(BOT_TOKEN|CHAT_IDS)_[0-9]+$' | sed -E 's/.*_([0-9]+)$/\1/' | sort -nu); do
        echo "_$v"
    done
    return 0
}
_tg_label() { if [[ -z "$1" ]]; then echo "bot #1"; else echo "bot #${1#_}"; fi; }
_tg_token_ok() { [[ "$1" =~ ^[0-9]{3,15}:[A-Za-z0-9_-]{20,}$ ]]; }
_tg_chat_ok()  { [[ "$1" =~ ^-?[0-9]{1,20}$ || "$1" =~ ^@[A-Za-z][A-Za-z0-9_]{4,31}$ ]]; }

# Validated routing table on stdout: "<suffix> <chat_id>" per line, each
# chat at most once. Warnings name the bot by number, never by token.
_tg_routes() {
    local sfx tv cv token chats chat label
    declare -A seen=()
    while IFS= read -r sfx; do
        tv="TELEGRAM_BOT_TOKEN$sfx"; cv="TELEGRAM_CHAT_IDS$sfx"
        token="${!tv:-}"; chats="${!cv:-}"; label="$(_tg_label "$sfx")"
        if [[ -z "$token" ]]; then warn "Telegram $label: $cv is set but $tv is empty; skipped"; continue; fi
        if [[ -z "$chats" ]]; then warn "Telegram $label: $tv is set but $cv is empty; it writes to nobody"; continue; fi
        if ! _tg_token_ok "$token"; then warn "Telegram $label: token does not look like <digits>:<secret>; skipped"; continue; fi
        while IFS= read -r chat; do
            if ! _tg_chat_ok "$chat"; then warn "Telegram $label: invalid chat id '$chat' skipped (use 123456789, -100... or @channel)"; continue; fi
            if [[ -n "${seen[$chat]:-}" ]]; then info "Telegram $label: chat $chat already served by ${seen[$chat]}; not sent twice"; continue; fi
            seen[$chat]="$label"
            printf '%s %s\n' "${sfx:--}" "$chat"
        done < <(split_csv "$chats")
    done < <(_tg_bots)
}

connector_enabled() {
    local sfx tv cv
    while IFS= read -r sfx; do
        tv="TELEGRAM_BOT_TOKEN$sfx"; cv="TELEGRAM_CHAT_IDS$sfx"
        [[ -n "${!tv:-}" && -n "${!cv:-}" ]] && return 0
    done < <(_tg_bots)
    return 1
}

connector_send() {
    local data="$1" report="$2" title="$3" text chat cfg ok=0 fail=0
    if [[ -n "${ALERT_BODY:-}" ]]; then
        # Free-text alert (e.g. watchdog): high-visibility message, no table.
        text="$(jq -rn --arg t "$title" --arg b "${ALERT_BODY:0:3500}" '
            def e: gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;");
            "🚨 <b>\($t | e)</b>\n<pre>\($b | e)</pre>"')"
    else
        text="$(jq -r --arg title "$title" --arg upd "${UPDATE_NOTICE:-}" --argjson force "$FORCE_FULL" "$JQ_LIB"'
            def e: tostring | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;");
            def icon: {"NEW":"🔴","ESCALATED":"🟠","UNCHANGED":"🟡"}[.status] // "";
            [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
            | "<b>\($title|e)</b>\n"
            + "Checked <b>\(length)</b> · New <b>\(map(select(.status=="NEW"))|length)</b> · Escalated <b>\(map(select(.status=="ESCALATED"))|length)</b>\n\n"
            + ([$a[:25][] | "\(icon) <code>\(.target|e)</code> — \(.score)% · \(.total) reports" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "\n    <i>\(.isp|e)</i>" else "" end)
                + (if catlist != "" then "\n    🏷 \(catlist|e)" else "" end)
                + (if why != "" then "\n    💬 <code>\(why|e)</code>" else "" end)] | join("\n"))
            + (if ($a|length) > 25 then "\n…and \(($a|length) - 25) more (see report)" else "" end)
            + "\n\n<i>\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted.</i>"
            + (if $upd != "" then "\n⬆️ <i>\($upd|e)</i>" else "" end)' "$data")"
    fi
    local sfx tv token label routes
    routes="$(_tg_routes)"
    [[ -n "$routes" ]] || { warn "Telegram: no valid bot/chat pairs; nothing sent"; return 1; }
    while read -r sfx chat; do
        [[ "$sfx" == "-" ]] && sfx=""
        tv="TELEGRAM_BOT_TOKEN$sfx"; token="${!tv}"; label="$(_tg_label "$sfx")"
        cfg="$(cfg_line url "https://api.telegram.org/bot${token}/sendMessage")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form-string "parse_mode=HTML")
$(cfg_line form-string "disable_web_page_preview=true")
$(cfg_line form-string "text=$text")"
        if secure_curl "$cfg" --max-time 30 --fail -o /dev/null; then ok=$((ok+1)); else fail=$((fail+1)); warn "Telegram $label: sendMessage to chat $chat failed"; fi
        if [[ -f "$report" ]]; then
            cfg="$(cfg_line url "https://api.telegram.org/bot${token}/sendDocument")
$(cfg_line form-string "chat_id=$chat")
$(cfg_line form "document=@$report;type=text/html")
$(cfg_line form-string "caption=Interactive report: $(basename "$report")")"
            secure_curl "$cfg" --max-time 60 --fail -o /dev/null || { fail=$((fail+1)); warn "Telegram $label: sendDocument to chat $chat failed"; }
        fi
    done <<< "$routes"
    info "Telegram: $ok chat(s) notified, $fail failure(s)"
    (( ok > 0 ))
}
