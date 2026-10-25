#!/usr/bin/env bash
# Sync one skill from the local Hermes profile into this repo tree.
# Usage: ./scripts/sync_skill.sh <category-or-""> <skill-name> [hermes-profile-dir]
set -euo pipefail
CAT="$1"; NAME="$2"; HERMES="${3:-$HOME/.hermes/skills}"
SRC="$HERMES${CAT:+/$CAT}/$NAME"
DST="$(cd "$(dirname "$0")/.." && pwd)/skills/$NAME"
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
git -C "$(cd "$(dirname "$0")/.." && pwd)" status --short -- "skills/$NAME" || true
