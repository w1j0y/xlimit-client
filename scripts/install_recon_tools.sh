#!/usr/bin/env bash
set -euo pipefail

# xLimit Recon dependency installer
# Supports Kali, Debian, and Ubuntu-style systems.
#
# Usage:
#   bash scripts/install_recon_tools.sh
#   bash scripts/install_recon_tools.sh --yes
#   bash scripts/install_recon_tools.sh --core
#   bash scripts/install_recon_tools.sh --full

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
CYAN="\033[96m"
BOLD="\033[1m"
END="\033[0m"

YES="false"
MODE="full"

log_info() { echo -e "${CYAN}[*]${END} $1"; }
log_ok() { echo -e "${GREEN}[+]${END} $1"; }
log_warn() { echo -e "${YELLOW}[!]${END} $1"; }
log_err() { echo -e "${RED}[-]${END} $1"; }

usage() {
  cat <<'EOF'
xLimit Recon tool installer

Usage:
  bash scripts/install_recon_tools.sh [--yes] [--core|--full]

Options:
  --yes    Do not ask for confirmation before installing packages
  --core   Install only core required tools: subfinder, httpx, Python deps
  --full   Install core tools plus optional recon helpers where available

Notes:
  - This script may use sudo for system packages.
  - Required xLimit Recon tools: subfinder, httpx.
  - Optional tools improve coverage but are not required.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)
      YES="true"
      shift
      ;;
    --core)
      MODE="core"
      shift
      ;;
    --full)
      MODE="full"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log_err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  xLimit Recon Tool Installer                 ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${END}"

if ! command -v apt-get >/dev/null 2>&1; then
  log_err "This installer currently supports apt-based systems only."
  log_err "Install dependencies manually using your OS package manager."
  exit 1
fi

if [ "$YES" != "true" ]; then
  cat <<EOF

This script installs local recon dependencies for xLimit Recon.

Mode: $MODE

It may install system packages and Go-based CLI tools.
Use only in an environment where you are comfortable installing recon tooling.

EOF
  read -r -p "Continue? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      log_warn "Cancelled."
      exit 0
      ;;
  esac
fi

ensure_path_lines() {
  local shell_rc="$HOME/.bashrc"

  if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "zsh" ]; then
    shell_rc="$HOME/.zshrc"
  fi

  if ! grep -q 'HOME/go/bin' "$shell_rc" 2>/dev/null; then
    echo 'export PATH="$HOME/go/bin:$PATH"' >> "$shell_rc"
    log_info "Added ~/go/bin to PATH in $shell_rc"
  fi

  if ! grep -q 'HOME/.local/bin' "$shell_rc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$shell_rc"
    log_info "Added ~/.local/bin to PATH in $shell_rc"
  fi

  export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
}

install_system_packages() {
  log_info "Updating apt package lists..."
  sudo apt-get update

  log_info "Installing base packages..."
  sudo apt-get install -y \
    git curl wget unzip jq \
    python3 python3-pip python3-venv pipx \
    python3-requests python3-bs4 \
    golang-go \
    nmap whatweb

  if [ "$MODE" = "full" ]; then
    log_info "Installing optional apt packages where available..."

    # These are optional. Not all distributions provide all of them.
    sudo apt-get install -y feroxbuster || log_warn "feroxbuster not available through apt"
    sudo apt-get install -y ffuf || log_warn "ffuf not available through apt"
    sudo apt-get install -y gobuster || log_warn "gobuster not available through apt"
    sudo apt-get install -y dirsearch || log_warn "dirsearch not available through apt"
    sudo apt-get install -y wpscan || log_warn "wpscan not available through apt"
    sudo apt-get install -y chromium || log_warn "chromium not available through apt"
  fi

  log_ok "System package phase complete"
}

install_go_tool() {
  local name="$1"
  local package="$2"

  export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"

  if command -v "$name" >/dev/null 2>&1; then
    log_ok "$name already installed"
    return
  fi

  if ! command -v go >/dev/null 2>&1; then
    log_warn "Go is not available; cannot install $name"
    return
  fi

  log_info "Installing $name..."
  go install -v "$package"
  log_ok "$name installed"
}

install_go_tools() {
  install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"

  if [ "$MODE" = "full" ]; then
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "gowitness" "github.com/sensepost/gowitness@latest"
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
  fi
}

install_pipx_tools() {
  if [ "$MODE" != "full" ]; then
    return
  fi

  if ! command -v pipx >/dev/null 2>&1; then
    log_warn "pipx not available; skipping pipx tools"
    return
  fi

  pipx ensurepath || true
  export PATH="$HOME/.local/bin:$PATH"

  if command -v paramspider >/dev/null 2>&1; then
    log_ok "paramspider already installed"
  else
    log_info "Installing paramspider with pipx..."
    pipx install paramspider || log_warn "paramspider installation failed"
  fi
}

verify_tool() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    log_ok "$tool"
    return 0
  fi

  if [ -x "$HOME/go/bin/$tool" ]; then
    log_ok "$tool in ~/go/bin"
    return 0
  fi

  log_warn "$tool missing"
  return 1
}

verify_installation() {
  echo
  echo -e "${BOLD}${GREEN}Installation verification${END}"
  echo

  local required=("subfinder" "httpx")
  local optional=("amass" "gowitness" "whatweb" "nmap" "feroxbuster" "ffuf" "gobuster" "nuclei" "paramspider" "dirsearch" "wpscan")
  local missing_required=0

  echo -e "${BOLD}Required:${END}"
  for tool in "${required[@]}"; do
    verify_tool "$tool" || missing_required=$((missing_required + 1))
  done

  echo
  echo -e "${BOLD}Optional:${END}"
  for tool in "${optional[@]}"; do
    verify_tool "$tool" || true
  done

  echo
  if [ "$missing_required" -gt 0 ]; then
    log_err "Missing required tools. xLimit Recon may not run correctly."
    exit 1
  fi

  log_ok "Required tools are installed."
  echo
  echo "If newly installed Go or pipx tools are not found in this terminal, run:"
  echo "  source ~/.bashrc"
  echo "or open a new terminal."
  echo
  echo "Test xLimit Recon:"
  echo "  python3 recon/xlimit_recon.py -d example.com --skip-js-scan"
  echo
}

main() {
  ensure_path_lines
  install_system_packages
  install_go_tools
  install_pipx_tools
  ensure_path_lines
  verify_installation
}

main "$@"
