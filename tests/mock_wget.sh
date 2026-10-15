#!/usr/bin/env bash
# Fake wget for the bootstrap tests: `wget -qO FILE [--timeout=N] URL`
# serves $MOCK_TARBALL and records the call.
out="" url=""
while (( $# )); do
    case "$1" in
        -qO|-O) out="$2"; shift ;;
        -q|--timeout=*) ;;
        *) url="$1" ;;
    esac
    shift
done
echo "wget $url" >> "$MOCK_LOG/update.log"
[[ -n "${MOCK_TARBALL:-}" && -f "$MOCK_TARBALL" ]] || { echo "wget: 404" >&2; exit 8; }
cp "$MOCK_TARBALL" "$out"
