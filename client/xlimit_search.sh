#!/usr/bin/env bash
set -euo pipefail

TOKEN_FILE="${HOME}/.config/xlimit/token.env"

if [ $# -lt 1 ]; then
  echo 'Usage: xlimit_search.sh "query" [knowledge|memory]' >&2
  exit 1
fi

if [ ! -f "$TOKEN_FILE" ]; then
  echo "Error: token file not found at $TOKEN_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$TOKEN_FILE"

if [ -z "${XLIMIT_API_TOKEN:-}" ]; then
  echo 'Error: XLIMIT_API_TOKEN is not set in token file' >&2
  exit 1
fi

QUERY="$1"
SOURCE="${2:-knowledge}"

if [ "$SOURCE" != "knowledge" ] && [ "$SOURCE" != "memory" ]; then
  echo 'Error: source must be "knowledge" or "memory"' >&2
  exit 1
fi

curl -sS -X POST https://api.xlimit.org/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${XLIMIT_API_TOKEN}" \
  --data "$(printf '{"query":"%s","limit":5,"source":"%s"}' "$QUERY" "$SOURCE")"
