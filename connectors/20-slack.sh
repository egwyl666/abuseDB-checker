# shellcheck shell=bash
# abuse-checker connector: Slack
# Loaded by abuse-checker from /usr/local/lib/abuse-checker/connectors.d/ in a
# subshell. Interface: connector_enabled (return 0 when configured) and
# connector_send <classified.json> <report.html> <title>.
# Settings (SLACK_WEBHOOK_URLS) come from the encrypted secrets store.

# shellcheck disable=SC2034  # read by abuse-checker
CONNECTOR_NAME="Slack"

connector_enabled() { [[ -n "${SLACK_WEBHOOK_URLS:-}" ]]; }

connector_send() {
    local data="$1" report="$2" title="$3" payload url n=0 i=0
    payload="$TMPD/slack.json"
    jq --arg title "$title" --arg upd "${UPDATE_NOTICE:-}" --arg report "$(basename "$report")" --argjson force "$FORCE_FULL" '
        [.[] | select(.status=="NEW" or .status=="ESCALATED" or ($force and .status=="UNCHANGED"))] as $a
        | {text:$title, blocks:(
            [{type:"header", text:{type:"plain_text", text:$title[:150]}},
             {type:"section", fields:[
                {type:"mrkdwn", text:"*Checked:* \(length)"},
                {type:"mrkdwn", text:"*Clean:* \(map(select(.status=="CLEAN"))|length)"},
                {type:"mrkdwn", text:":red_circle: *New:* \(map(select(.status=="NEW"))|length)"},
                {type:"mrkdwn", text:":large_orange_circle: *Escalated:* \(map(select(.status=="ESCALATED"))|length)"}]},
             {type:"divider"}]
            + [$a[:20][] | {type:"section",
                text:{type:"mrkdwn", text:("*\(.status)* `\(.target)` — score *\(.score)%*, \(.total) reports" + (if .delta > 0 then " (+\(.delta))" else "" end) + (if (.isp//"") != "" then "\n_\(.isp)_ \(.country // "")" else "" end))},
                accessory:{type:"button", text:{type:"plain_text", text:"AbuseIPDB"}, url:"https://www.abuseipdb.com/check/\(.target|@uri)"}}]
            + [{type:"context", elements:[{type:"mrkdwn", text:("\(map(select(.status=="UNCHANGED"))|length) unchanged dirty IP(s) not re-alerted · full report: \($report)" + (if $upd != "" then "\n:arrow_up: \($upd)" else "" end))}]}])}' "$data" > "$payload" \
        || { warn "Slack: failed to build payload"; return 1; }
    while IFS= read -r url; do
        i=$((i+1))
        if secure_curl "$(cfg_line url "$url")
$(cfg_line header "Content-Type: application/json")" --max-time 30 --fail -o /dev/null --data-binary "@$payload"; then
            n=$((n+1))
        else
            warn "Slack webhook #$i failed"
        fi
    done < <(split_csv "$SLACK_WEBHOOK_URLS")
    info "Slack: $n of $i webhook(s) notified"
}
