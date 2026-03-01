#!/usr/bin/env bash
# install-tools.sh — Install all external tools required by Liminal
#
# Usage:
#   chmod +x install-tools.sh
#   ./install-tools.sh          # install everything
#   ./install-tools.sh --go     # Go tools only
#   ./install-tools.sh --python # Python tools only
#   ./install-tools.sh --check  # check what is/isn't installed (no changes)

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
err()  { echo -e "  ${RED}✗${RESET} $*"; }
info() { echo -e "  ${CYAN}→${RESET} $*"; }
header() { echo -e "\n${BOLD}$*${RESET}"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
DO_GO=true
DO_PYTHON=true
CHECK_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --go)     DO_PYTHON=false ;;
    --python) DO_GO=false ;;
    --check)  CHECK_ONLY=true ;;
    --help|-h)
      echo "Usage: $0 [--go] [--python] [--check]"
      echo "  --go      Install Go tools only"
      echo "  --python  Install Python tools only"
      echo "  --check   Show install status, make no changes"
      exit 0
      ;;
    *)
      err "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# ── Go tools ──────────────────────────────────────────────────────────────────
# Each entry: "binary|go_package|description"
GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|Passive subdomain enumeration"
  "amass|github.com/owasp-amass/amass/v4/...@master|Active/passive subdomain enumeration"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest|DNS resolution and validation"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest|HTTP probing and tech detection"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|Port scanning"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|Template-based vulnerability scanning"
  "gau|github.com/lc/gau/v2/cmd/gau@latest|Historical URL discovery"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest|Web crawler"
  "waybackurls|github.com/tomnomnom/waybackurls@latest|Wayback Machine URL fetcher"
  "dalfox|github.com/hahwul/dalfox/v2@latest|XSS scanner"
  "interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|SSRF OOB callback server"
)

# ── Python tools ──────────────────────────────────────────────────────────────
# Each entry: "binary|pip_package|description"
PYTHON_TOOLS=(
  "arjun|arjun|Hidden parameter discovery"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
is_installed() { command -v "$1" &>/dev/null; }

require_go() {
  if ! is_installed go; then
    err "Go is not installed. Install it from https://go.dev/dl/ then re-run this script."
    echo ""
    echo "  Quick install on macOS:   brew install go"
    echo "  Quick install on Debian:  sudo apt install golang-go"
    echo "  Or download:              https://go.dev/dl/"
    echo ""
    exit 1
  fi

  local go_version
  go_version=$(go version | awk '{print $3}' | sed 's/go//')
  local major minor
  major=$(echo "$go_version" | cut -d. -f1)
  minor=$(echo "$go_version" | cut -d. -f2)

  if [[ "$major" -lt 1 ]] || { [[ "$major" -eq 1 ]] && [[ "$minor" -lt 21 ]]; }; then
    warn "Go $go_version detected. Go 1.21+ is recommended for all tools."
    warn "Some tools may fail to install. Consider upgrading: https://go.dev/dl/"
  else
    ok "Go $go_version detected"
  fi

  # Ensure GOPATH/bin is in PATH
  local gobin
  gobin=$(go env GOPATH)/bin
  if [[ ":$PATH:" != *":$gobin:"* ]]; then
    warn "$(go env GOPATH)/bin is not in your PATH."
    warn "Add this to your ~/.bashrc or ~/.zshrc:"
    warn "  export PATH=\"\$PATH:$(go env GOPATH)/bin\""
    echo ""
  fi
}

require_python() {
  local python_cmd=""
  if is_installed python3; then
    python_cmd="python3"
  elif is_installed python; then
    python_cmd="python"
  fi

  if [[ -z "$python_cmd" ]]; then
    err "Python 3 is not installed. Install it from https://python.org"
    exit 1
  fi

  local py_version
  py_version=$($python_cmd --version 2>&1 | awk '{print $2}')
  local major minor
  major=$(echo "$py_version" | cut -d. -f1)
  minor=$(echo "$py_version" | cut -d. -f2)

  if [[ "$major" -lt 3 ]] || { [[ "$major" -eq 3 ]] && [[ "$minor" -lt 8 ]]; }; then
    err "Python $py_version detected. Python 3.8+ is required."
    exit 1
  fi

  ok "Python $py_version detected"

  if ! is_installed pip3 && ! is_installed pip; then
    err "pip is not installed. Install it with: python3 -m ensurepip"
    exit 1
  fi
}

# ── Check mode ────────────────────────────────────────────────────────────────
check_status() {
  header "Tool Status"

  local all_ok=true

  if [[ "$DO_GO" == true ]]; then
    echo ""
    echo "  Go tools:"
    for entry in "${GO_TOOLS[@]}"; do
      local binary pkg desc
      binary=$(echo "$entry" | cut -d'|' -f1)
      pkg=$(echo "$entry" | cut -d'|' -f2)
      desc=$(echo "$entry" | cut -d'|' -f3)

      if is_installed "$binary"; then
        ok "$(printf '%-22s' "$binary")  $desc"
      else
        err "$(printf '%-22s' "$binary")  $desc  (go install $pkg)"
        all_ok=false
      fi
    done
  fi

  if [[ "$DO_PYTHON" == true ]]; then
    echo ""
    echo "  Python tools:"
    for entry in "${PYTHON_TOOLS[@]}"; do
      local binary pkg desc
      binary=$(echo "$entry" | cut -d'|' -f1)
      pkg=$(echo "$entry" | cut -d'|' -f2)
      desc=$(echo "$entry" | cut -d'|' -f3)

      if is_installed "$binary"; then
        ok "$(printf '%-22s' "$binary")  $desc"
      else
        err "$(printf '%-22s' "$binary")  $desc  (pip install $pkg)"
        all_ok=false
      fi
    done
  fi

  echo ""
  if [[ "$all_ok" == true ]]; then
    ok "All tools are installed."
  else
    warn "Some tools are missing. Run without --check to install them."
  fi
}

# ── Install Go tools ──────────────────────────────────────────────────────────
install_go_tools() {
  header "Installing Go tools"
  require_go

  local installed=0
  local skipped=0
  local failed=0

  for entry in "${GO_TOOLS[@]}"; do
    local binary pkg desc
    binary=$(echo "$entry" | cut -d'|' -f1)
    pkg=$(echo "$entry" | cut -d'|' -f2)
    desc=$(echo "$entry" | cut -d'|' -f3)

    if is_installed "$binary"; then
      ok "$(printf '%-22s' "$binary")  already installed"
      ((skipped++)) || true
      continue
    fi

    info "Installing $binary  ($desc)..."
    if go install "$pkg" 2>/tmp/liminal_install_err; then
      ok "$(printf '%-22s' "$binary")  installed"
      ((installed++)) || true
    else
      err "$(printf '%-22s' "$binary")  FAILED"
      err "  $(cat /tmp/liminal_install_err | tail -3)"
      ((failed++)) || true
    fi
  done

  echo ""
  ok "Go tools: $installed installed, $skipped already present, $failed failed"

  # Update nuclei templates if nuclei was just installed or already present
  if is_installed nuclei; then
    echo ""
    info "Updating nuclei templates..."
    if nuclei -update-templates -silent 2>/dev/null; then
      ok "nuclei templates updated"
    else
      warn "nuclei template update failed (non-fatal — templates may already be current)"
    fi
  fi
}

# ── Install Python tools ──────────────────────────────────────────────────────
install_python_tools() {
  header "Installing Python tools"
  require_python

  local pip_cmd
  if is_installed pip3; then
    pip_cmd="pip3"
  else
    pip_cmd="pip"
  fi

  local installed=0
  local skipped=0
  local failed=0

  for entry in "${PYTHON_TOOLS[@]}"; do
    local binary pkg desc
    binary=$(echo "$entry" | cut -d'|' -f1)
    pkg=$(echo "$entry" | cut -d'|' -f2)
    desc=$(echo "$entry" | cut -d'|' -f3)

    if is_installed "$binary"; then
      ok "$(printf '%-22s' "$binary")  already installed"
      ((skipped++)) || true
      continue
    fi

    info "Installing $binary  ($desc)..."
    if $pip_cmd install --quiet "$pkg" 2>/tmp/liminal_install_err; then
      ok "$(printf '%-22s' "$binary")  installed"
      ((installed++)) || true
    else
      err "$(printf '%-22s' "$binary")  FAILED"
      err "  $(cat /tmp/liminal_install_err | tail -3)"
      ((failed++)) || true
    fi
  done

  echo ""
  ok "Python tools: $installed installed, $skipped already present, $failed failed"
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
  header "Final status"

  local all_ok=true
  local missing=()

  for entry in "${GO_TOOLS[@]}" "${PYTHON_TOOLS[@]}"; do
    local binary
    binary=$(echo "$entry" | cut -d'|' -f1)
    if is_installed "$binary"; then
      ok "$binary"
    else
      err "$binary  (not found in PATH)"
      missing+=("$binary")
      all_ok=false
    fi
  done

  echo ""
  if [[ "$all_ok" == true ]]; then
    ok "All tools installed and in PATH. Run your first scan:"
    echo ""
    echo "    liminal scan --config config/config.yaml"
    echo ""
  else
    warn "${#missing[@]} tool(s) not in PATH: ${missing[*]}"
    echo ""
    echo "  If Go tools were just installed, add GOPATH/bin to your PATH:"
    echo ""
    echo "    export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
    echo ""
    echo "  Then open a new shell or run: source ~/.bashrc  (or ~/.zshrc)"
    echo ""
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Liminal — Tool Installer${RESET}"
echo "──────────────────────────"

if [[ "$CHECK_ONLY" == true ]]; then
  check_status
  exit 0
fi

if [[ "$DO_GO" == true ]]; then
  install_go_tools
fi

if [[ "$DO_PYTHON" == true ]]; then
  install_python_tools
fi

print_summary
