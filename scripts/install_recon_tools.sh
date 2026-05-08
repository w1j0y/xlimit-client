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
#
# Fresh-machine goal:
#   Install all tools checked by xlimit_recon.py pre-flight:
#   subfinder, httpx, amass, gowitness, whatweb, nmap, feroxbuster, ffuf,
#   gobuster, nuclei, paramspider, dirsearch, wpscan, assetfinder,
#   github-subdomains, chaos, dnsx, puredns, shuffledns, massdns, alterx,
#   dnsgen, gau, waybackurls, arjun, masscan, asnmap, plus Python deps.

GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
CYAN="\033[96m"
BOLD="\033[1m"
END="\033[0m"

YES="false"
MODE="full"
INSTALL_GO_FROM_UPSTREAM="true"

log_info() { echo -e "${CYAN}[*]${END} $1"; }
log_ok() { echo -e "${GREEN}[+]${END} $1"; }
log_warn() { echo -e "${YELLOW}[!]${END} $1"; }
log_err() { echo -e "${RED}[-]${END} $1"; }

usage() {
  cat <<'EOF'
xLimit Recon tool installer

Usage:
  bash scripts/install_recon_tools.sh [--yes] [--core|--full] [--no-upstream-go]

Options:
  --yes, -y          Do not ask for confirmation before installing packages
  --core             Install only core required tools: subfinder, httpx, Python deps
  --full             Install core tools plus optional recon helpers
  --no-upstream-go   Do not install/update Go from go.dev if apt Go is old
  --help, -h         Show this help

Notes:
  - This script may use sudo for system packages and /usr/local/go.
  - Required xLimit Recon tools: subfinder, httpx.
  - Optional tools improve coverage but are not required.
  - API-backed tools still need env vars:
      GITHUB_TOKEN   for github-subdomains
      PDCP_API_KEY   for chaos
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
    --no-upstream-go)
      INSTALL_GO_FROM_UPSTREAM="false"
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

It may install system packages, Go-based CLI tools, Python tools,
and compile massdns from source.

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

  touch "$shell_rc"

  if ! grep -q 'HOME/go/bin' "$shell_rc" 2>/dev/null; then
    echo 'export PATH="$HOME/go/bin:$PATH"' >> "$shell_rc"
    log_info "Added ~/go/bin to PATH in $shell_rc"
  fi

  if ! grep -q 'HOME/.local/bin' "$shell_rc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$shell_rc"
    log_info "Added ~/.local/bin to PATH in $shell_rc"
  fi

  if ! grep -q '/usr/local/go/bin' "$shell_rc" 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$shell_rc"
    log_info "Added /usr/local/go/bin to PATH in $shell_rc"
  fi

  export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH"
}

go_version_number() {
  if ! command -v go >/dev/null 2>&1; then
    echo "0.0.0"
    return
  fi

  go version | awk '{print $3}' | sed 's/^go//'
}

version_ge() {
  # Returns 0 if $1 >= $2
  python3 - "$1" "$2" <<'PY'
import sys
from packaging.version import Version
sys.exit(0 if Version(sys.argv[1]) >= Version(sys.argv[2]) else 1)
PY
}

install_system_packages() {
  log_info "Updating apt package lists..."
  sudo apt-get update

  log_info "Installing base packages..."
  sudo apt-get install -y \
    ca-certificates \
    git curl wget unzip jq \
    build-essential make gcc \
    python3 python3-pip python3-venv pipx python3-packaging \
    python3-requests python3-bs4 \
    golang-go \
    nmap whatweb masscan

  # Python mmh3 for favicon hashing.
  # Prefer apt package for system Python; fallback to pip with --user / break-system-packages.
  log_info "Installing Python dependencies..."
  sudo apt-get install -y python3-mmh3 || {
    log_warn "python3-mmh3 not available through apt; trying pip user install"
    python3 -m pip install --user mmh3 --break-system-packages || \
      python3 -m pip install --user mmh3 || \
      log_warn "mmh3 installation failed"
  }

  if [ "$MODE" = "full" ]; then
    log_info "Installing optional apt packages where available..."

    sudo apt-get install -y feroxbuster || log_warn "feroxbuster not available through apt"
    sudo apt-get install -y ffuf || log_warn "ffuf not available through apt"
    sudo apt-get install -y gobuster || log_warn "gobuster not available through apt"
    sudo apt-get install -y dirsearch || log_warn "dirsearch not available through apt"
    sudo apt-get install -y wpscan || log_warn "wpscan not available through apt"
    sudo apt-get install -y dnsgen || log_warn "dnsgen not available through apt; will try pipx"
    sudo apt-get install -y chromium || log_warn "chromium not available through apt"
  fi

  log_ok "System package phase complete"
}

install_latest_go_if_needed() {
  if [ "$INSTALL_GO_FROM_UPSTREAM" != "true" ]; then
    log_info "Skipping upstream Go installation because --no-upstream-go was used"
    return
  fi

  export PATH="/usr/local/go/bin:$PATH"

  local current_go
  current_go="$(go_version_number)"

  # Some current ProjectDiscovery tools require Go >= 1.21, and shuffledns currently
  # needs newer Go. Use >=1.24 as the safe fresh-machine baseline.
  if version_ge "$current_go" "1.24.0"; then
    log_ok "Go $current_go is recent enough"
    return
  fi

  log_warn "Current Go version is $current_go; installing latest stable Go from go.dev"

  local latest_go
  latest_go="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n 1 | tr -d '\r')"

  if [ -z "$latest_go" ]; then
    log_warn "Could not determine latest Go version; keeping apt Go"
    return
  fi

  local arch
  arch="$(dpkg --print-architecture)"

  local go_arch
  case "$arch" in
    amd64) go_arch="amd64" ;;
    arm64) go_arch="arm64" ;;
    armhf) go_arch="armv6l" ;;
    *)
      log_warn "Unsupported architecture for upstream Go tarball: $arch"
      return
      ;;
  esac

  local tarball="${latest_go}.linux-${go_arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  local tmp="/tmp/${tarball}"

  log_info "Downloading $url"
  curl -fL "$url" -o "$tmp"

  log_info "Installing Go to /usr/local/go"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$tmp"
  rm -f "$tmp"

  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

  log_ok "Installed $(go version)"
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
  if go install -v "$package"; then
    log_ok "$name installed"
  else
    log_warn "$name installation failed"
  fi
}

install_go_tools() {
  # Required/core.
  install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"

  if [ "$MODE" != "full" ]; then
    return
  fi

  # Existing optional stack.
  install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_go_tool "gowitness" "github.com/sensepost/gowitness@latest"
  install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"

  # Missing tools from new xlimit_recon.py pre-flight.
  install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
  install_go_tool "github-subdomains" "github.com/gwen001/github-subdomains@latest"
  install_go_tool "chaos" "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  install_go_tool "puredns" "github.com/d3mondev/puredns/v2@latest"
  install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  install_go_tool "alterx" "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  install_go_tool "asnmap" "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"

  # URL collection helpers.
  install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
}

install_massdns() {
  if [ "$MODE" != "full" ]; then
    return
  fi

  if command -v massdns >/dev/null 2>&1; then
    log_ok "massdns already installed"
    return
  fi

  log_info "Installing massdns from source..."

  local workdir
  workdir="$(mktemp -d)"

  if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$workdir/massdns"; then
    (
      cd "$workdir/massdns"
      make
      sudo make install
    ) && log_ok "massdns installed" || log_warn "massdns build/install failed"
  else
    log_warn "massdns clone failed"
  fi

  rm -rf "$workdir"
}

install_pipx_package() {
  local command_name="$1"
  local package_name="$2"

  if command -v "$command_name" >/dev/null 2>&1; then
    log_ok "$command_name already installed"
    return
  fi

  if ! command -v pipx >/dev/null 2>&1; then
    log_warn "pipx not available; cannot install $command_name"
    return
  fi

  log_info "Installing $command_name with pipx package $package_name..."
  if pipx install "$package_name"; then
    log_ok "$command_name installed"
  else
    log_warn "$command_name installation failed"
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

  install_pipx_package "paramspider" "paramspider"
  install_pipx_package "arjun" "arjun"

  # If apt dnsgen did not install it, try Python package.
  if ! command -v dnsgen >/dev/null 2>&1; then
    install_pipx_package "dnsgen" "dnsgen"
  fi
}

print_token_notes() {
  echo
  echo -e "${BOLD}${YELLOW}API-backed optional tools${END}"
  echo
  echo "Some tools will install but skip data collection unless tokens are configured:"
  echo
  echo "  github-subdomains requires:"
  echo "    export GITHUB_TOKEN='your_github_token'"
  echo
  echo "  chaos requires:"
  echo "    export PDCP_API_KEY='your_projectdiscovery_api_key'"
  echo
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

  if [ -x "$HOME/.local/bin/$tool" ]; then
    log_ok "$tool in ~/.local/bin"
    return 0
  fi

  log_warn "$tool missing"
  return 1
}

verify_python_module() {
  local module="$1"
  local label="$2"

  if python3 -c "import ${module}" >/dev/null 2>&1; then
    log_ok "Python: $label"
    return 0
  fi

  log_warn "Python: $label missing"
  return 1
}

verify_installation() {
  echo
  echo -e "${BOLD}${GREEN}Installation verification${END}"
  echo

  local required=("subfinder" "httpx")
  local optional=(
    "amass"
    "gowitness"
    "whatweb"
    "nmap"
    "feroxbuster"
    "ffuf"
    "gobuster"
    "nuclei"
    "paramspider"
    "dirsearch"
    "wpscan"
    "assetfinder"
    "github-subdomains"
    "chaos"
    "dnsx"
    "puredns"
    "shuffledns"
    "massdns"
    "alterx"
    "dnsgen"
    "gau"
    "waybackurls"
    "arjun"
    "masscan"
    "asnmap"
  )

  local missing_required=0

  echo -e "${BOLD}Required:${END}"
  for tool in "${required[@]}"; do
    verify_tool "$tool" || missing_required=$((missing_required + 1))
  done

  echo
  echo -e "${BOLD}Optional:${END}"
  if [ "$MODE" = "full" ]; then
    for tool in "${optional[@]}"; do
      verify_tool "$tool" || true
    done
  else
    log_info "Skipped optional verification because mode is --core"
  fi

  echo
  echo -e "${BOLD}Python:${END}"
  verify_python_module "requests" "requests" || true
  verify_python_module "bs4" "beautifulsoup4/bs4" || true
  verify_python_module "mmh3" "mmh3" || true

  echo
  if [ "$missing_required" -gt 0 ]; then
    log_err "Missing required tools. xLimit Recon may not run correctly."
    exit 1
  fi

  log_ok "Required tools are installed."

  print_token_notes

  echo
  echo "If newly installed Go or pipx tools are not found in this terminal, run:"
  echo "  source ~/.bashrc"
  echo "or open a new terminal."
  echo
  echo "Then test xLimit Recon, for example:"
  echo '  python3 ./tools/xlimit_recon.py --scope ./targets/scope.csv --skip-screenshots --custom-header "X-Bug-Bounty: w1j0y" --output ./recon_output/test'
  echo
}

main() {
  ensure_path_lines
  install_system_packages
  install_latest_go_if_needed
  install_go_tools
  install_massdns
  install_pipx_tools
  ensure_path_lines
  verify_installation
}

main "$@"