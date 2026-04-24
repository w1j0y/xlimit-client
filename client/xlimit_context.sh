#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo 'Usage: xlimit_context.sh "natural language prompt"' >&2
  exit 1
fi

PROMPT="$1"

echo "=== xLimit hosted context ==="
echo
echo "--- Knowledge (top hits) ---"
"$HOME/xlimit-client/xlimit_search_text.sh" "$PROMPT" knowledge | sed -n '1,22p'
echo
echo "--- Memory (top hits) ---"
"$HOME/xlimit-client/xlimit_search_text.sh" "$PROMPT" memory | sed -n '1,18p'
