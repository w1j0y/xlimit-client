#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/xlimit-client"
CONFIG_DIR="${HOME}/.config/xlimit"
TOKEN_FILE="${CONFIG_DIR}/token.env"

mkdir -p "$INSTALL_DIR"
cp "$REPO_DIR"/client/*.sh "$INSTALL_DIR"/
chmod 700 "$INSTALL_DIR"/*.sh

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [ ! -f "$TOKEN_FILE" ]; then
  cat > "$TOKEN_FILE" <<'EOF'
XLIMIT_API_TOKEN=PASTE_YOUR_TOKEN_HERE
EOF
  chmod 600 "$TOKEN_FILE"
  TOKEN_STATUS="Created token template at $TOKEN_FILE"
else
  chmod 600 "$TOKEN_FILE"
  TOKEN_STATUS="Existing token file preserved at $TOKEN_FILE"
fi

cat <<EOF
xLimit client installed.

Installed scripts:
  $INSTALL_DIR/xlimit_search.sh
  $INSTALL_DIR/xlimit_search_text.sh
  $INSTALL_DIR/xlimit_context.sh

$TOKEN_STATUS

Next steps:
  1. Edit $TOKEN_FILE and replace PASTE_YOUR_TOKEN_HERE with your xLimit API token.
  2. Test retrieval:
     $INSTALL_DIR/xlimit_search_text.sh "graphql introspection authorization" knowledge
  3. For local assistants, prefer:
     $INSTALL_DIR/xlimit_context.sh "<full user prompt>"
EOF
