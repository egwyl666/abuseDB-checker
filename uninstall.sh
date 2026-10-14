#!/usr/bin/env bash
# Remove abuse-checker. Thin wrapper around `abuse-checker --uninstall`, so it
# works from the source checkout even if /usr/local/bin/abuse-checker is gone.
#   sudo ./uninstall.sh            interactive menu
#   sudo ./uninstall.sh --keep     remove app + units, keep config/state/reports
#   sudo ./uninstall.sh --purge    remove everything, including the system user
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    ""|--keep|--purge) ;;
    -h|--help) echo "Usage: sudo $0 [--keep|--purge]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac
exec bash "$SRC/abuse-checker.sh" --uninstall "$@"
