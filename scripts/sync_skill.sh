#!/usr/bin/env bash
# Sync one skill from the local Hermes profile into this repo tree.
# Usage: ./scripts/sync_skill.sh <domain> <skill-name> [profile-category] [hermes-profile-dir]
#   domain:           penetration-testing | dfir | red-teaming
#   profile-category: e.g. security (omit for a top-level profile skill)
set -euo pipefail
DOMAIN="$1"; NAME="$2"; CAT="${3:-}"; HERMES="${4:-$HOME/.hermes/skills}"
case "$DOMAIN" in
  penetration-testing|dfir|red-teaming) ;;
  *) echo "domain must be one of: penetration-testing dfir red-teaming (got '$DOMAIN')" >&2; exit 1 ;;
esac
SRC="$HERMES${CAT:+/$CAT}/$NAME"
DST="$(cd "$(dirname "$0")/.." && pwd)/skills/$DOMAIN/$NAME"
[ -d "$SRC" ] || { echo "not found: $SRC" >&2; exit 1; }
mkdir -p "$DST"
rsync -a --delete --exclude '.DS_Store' "$SRC/" "$DST/"
echo "synced $SRC -> $DST"
# warn only when frontmatter is actually absent (grep -L inverts: it lists files WITHOUT a match)
if [ -f "$DST/SKILL.md" ]; then
  { [ "$(head -1 "$DST/SKILL.md")" = "---" ] && grep -q '^name:' "$DST/SKILL.md"; } \
    || echo "WARNING: SKILL.md missing frontmatter or 'name:'" >&2
fi
# anonymize + leak-gate (public repo: vendor/client names never ship)
python3 "$(dirname "$0")/publish_scrub.py" $(find "$DST" -type f -name "*.md" -o -type f -name "*.json" -o -type f -name "*.py" -o -type f -name "*.sh")
# second gate: nothing internal — personal paths, credentials, private ranges (exit 1 fails the sync)
python3 "$(dirname "$0")/internal_info_lint.py" $(find "$DST" -type f -name "*.md" -o -type f -name "*.json" -o -type f -name "*.py" -o -type f -name "*.sh")
git -C "$(cd "$(dirname "$0")/.." && pwd)" status --short -- "skills/$DOMAIN/$NAME" || true
