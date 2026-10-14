#!/usr/bin/env bash
# Fake curl for the test suite. Reads the curl config from stdin (like
# `curl --config -`), records argv and config separately, and serves
# fixtures from $MOCK_FIX instead of touching the network.
set -uo pipefail
out=/dev/stdout hdr="" wfmt="" data=""
printf '%q ' "$@" >> "$MOCK_LOG/argv.log"; echo >> "$MOCK_LOG/argv.log"
while (( $# )); do
    case "$1" in
        -o) out="$2"; shift ;;
        -D) hdr="$2"; shift ;;
        -w) wfmt="$2"; shift ;;
        --data-binary) data="$2"; shift ;;
        --max-time|--retry|--retry-delay) shift ;;
    esac
    shift
done
cfg="$(cat)"
printf '%s\n---\n' "$cfg" >> "$MOCK_LOG/config.log"
url="$(sed -n 's/^url = "\(.*\)"$/\1/p' <<< "$cfg" | head -n1)"
key="$(sed -n 's/^header = "Key: \(.*\)"$/\1/p' <<< "$cfg" | head -n1)"
[[ "${MOCK_LEAK:-}" == "1" ]] && echo "curl: (7) simulated failure connecting to $url" >&2

respond() { # code body [remaining]
    [[ -n "$hdr" ]] && printf 'HTTP/1.1 %s\r\nX-RateLimit-Remaining: %s\r\n\r\n' "$1" "${3:-100}" > "$hdr"
    printf '%s' "$2" > "$out"
    [[ -n "$wfmt" ]] && printf '%s' "$1"
    return 0
}

case "$url" in
    *api.telegram.org*|*hooks.slack.test*|smtp*)
        echo "$url" >> "$MOCK_LOG/notify.log"
        [[ -n "$data" ]] && cat "${data#@}" >> "$MOCK_LOG/slack_payload.log"
        respond 200 '{"ok":true}'; exit 0 ;;
esac

if [[ ",${MOCK_LIMITED_KEYS:-}," == *",$key,"* ]]; then
    echo "$key" >> "$MOCK_LOG/limited.log"
    respond 429 '{"errors":[{"detail":"Daily rate limit exceeded"}]}' 0; exit 0
fi
echo "$key" >> "$MOCK_LOG/keys_used.log"
target="$(sed -n 's/.*\(ipAddress\|network\)=\([^&]*\).*/\2/p' <<< "$url" | sed 's/%2F/_/g')"
if [[ -f "$MOCK_FIX/$target.json" ]]; then
    respond 200 "$(cat "$MOCK_FIX/$target.json")"
else
    respond 200 "{\"data\":{\"ipAddress\":\"$target\",\"abuseConfidenceScore\":0,\"totalReports\":0,\"lastReportedAt\":null,\"isp\":\"Default ISP\",\"countryCode\":\"DE\"}}"
fi
