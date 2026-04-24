#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo 'Usage: xlimit_search_text.sh "query" [knowledge|memory]' >&2
  exit 1
fi

RAW_JSON="$("$HOME/xlimit-client/xlimit_search.sh" "$1" "${2:-knowledge}")"

python3 - <<'PY' "$RAW_JSON"
import json
import sys

result = json.loads(sys.argv[1])

hits = result.get("hits", [])
if not hits:
    detail = result.get("detail")
    if detail:
        print(f"xLimit returned: {detail}")
    else:
        print("No results.")
    raise SystemExit(0)

print("xLimit hosted retrieval context")
print()

for i, hit in enumerate(hits, 1):
    result_id = hit.get("result_id", "unknown")
    score = hit.get("score", "n/a")
    source = hit.get("source", "unknown")
    snippet = hit.get("snippet", "")

    print(f"[{i}] result_id={result_id} source={source} score={score}")
    print(snippet)
    print()
PY
