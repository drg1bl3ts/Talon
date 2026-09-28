#!/usr/bin/env bash
#
# Talon Installer
#
# Installs everything Talon needs to run end to end:
#
#   Base:
#     curl, wget, jq, git, unzip, build tools, libpcap, Python
#
#   Go:
#     subfinder, httpx, dnsx, naabu, katana         (recon)
#     assetfinder, anew, subfaster                   (recon)
#     gf, nuclei, notify                              (triage)
#     ffuf                                            (triage, --vhost-fuzz)
#
#   Other:
#     findomain                                       (recon)
#     waymore, paramspider, wafw00f                   (recon/triage, via a venv)
#     feroxbuster                                      (triage, --dir-brute)
#     trufflehog                                       (triage, JS secret scan + live verification)
#     GF pattern definitions (~/.gf, + nosqli/proto-pollution written directly) (triage)
#     nuclei-templates                                 (triage, pre-fetched)
#     CMSeeK (~/Tools/CMSeeK)                           (triage, CMS fingerprint — optional, best-effort)
#     SecLists (/usr/share/seclists)                    (triage, --vhost-fuzz/--dir-brute wordlists — optional, best-effort)
#
# wafw00f and trufflehog are hard runtime dependencies by default (talon.py
# only skips them with --no-waf-detect / --no-js-scan respectively) —
# everything else in this list is either opt-in (ffuf/feroxbuster/SecLists)
# or degrades gracefully at runtime if missing (CMSeeK).
#
# Supported platforms:
#   - Debian / Ubuntu / Kali / Mint
#   - Arch / Manjaro / EndeavourOS / BlackArch
#   - Fedora
#   - RHEL / Rocky / AlmaLinux / CentOS
#   - openSUSE
#   - Alpine
#   - macOS (Intel + Apple Silicon)
#
# Requirements:
#   - Run as normal user with sudo available, OR as root
#   - macOS requires Homebrew for automatic package installation
#
# Usage:
#   chmod +x Installer.sh
#   ./Installer.sh
#

set -euo pipefail

RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'

ok()   { printf '%b\n' "${GREEN}[+]${RESET} $1"; }
info() { printf '%b\n' "${CYAN}[*]${RESET} $1"; }
warn() { printf '%b\n' "${YELLOW}[!]${RESET} $1"; }
fail() { printf '%b\n' "${RED}[-]${RESET} $1"; }

# ──────────────────────────────────────────────────────────────
# GLOBALS
# ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MIN_GO_MAJOR=1
MIN_GO_MINOR=24
MIN_PY_MAJOR=3
MIN_PY_MINOR=10   # talon.py uses PEP 604 `X | None` annotations

GOBIN_DIR="${HOME}/go/bin"
LOCAL_BIN="${HOME}/.local/bin"
GF_DIR="${HOME}/.gf"
PYTHON_VENV="${HOME}/.talon-venv"

OS=""
DISTRO=""
PKG_MANAGER=""

printf '\n%b\n\n' "${CYAN}${BOLD}=== Talon Installer ===${RESET}"

# ──────────────────────────────────────────────────────────────
# SUDO
# ──────────────────────────────────────────────────────────────

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        fail "This installer needs root or sudo."
        fail "Install sudo or re-run this script as root."
        exit 1
    fi
fi

# ──────────────────────────────────────────────────────────────
# OS DETECTION
# ──────────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Darwin)  OS="macos"   ;;
        Linux)   OS="linux"   ;;
        FreeBSD) OS="freebsd" ;;
        OpenBSD) OS="openbsd" ;;
        NetBSD)  OS="netbsd"  ;;
        *)       OS="unknown" ;;
    esac

    if [[ "$OS" == "linux" ]] && [[ -r /etc/os-release ]]; then
        # Read each key we need explicitly instead of sourcing the whole
        # file — avoids set -e aborting on any exotic assignment in that
        # file, and keeps our own namespace clean.
        local os_id=""

        while IFS='=' read -r key value; do
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"

            case "$key" in
                ID) os_id="$value" ;;
            esac
        done < /etc/os-release

        DISTRO="${os_id:-unknown}"
    fi
}

detect_package_manager() {
    if [[ "$OS" == "macos" ]]; then
        if command -v brew >/dev/null 2>&1; then
            PKG_MANAGER="brew"
        else
            PKG_MANAGER=""
        fi
        return
    fi

    if [[ "$OS" != "linux" ]]; then
        PKG_MANAGER=""
        return
    fi

    if   command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt"
    elif command -v pacman  >/dev/null 2>&1; then PKG_MANAGER="pacman"
    elif command -v dnf     >/dev/null 2>&1; then PKG_MANAGER="dnf"
    elif command -v yum     >/dev/null 2>&1; then PKG_MANAGER="yum"
    elif command -v zypper  >/dev/null 2>&1; then PKG_MANAGER="zypper"
    elif command -v apk     >/dev/null 2>&1; then PKG_MANAGER="apk"
    else PKG_MANAGER=""
    fi
}

detect_os
detect_package_manager

if [[ "$OS" == "macos" ]] && ! command -v brew >/dev/null 2>&1; then
    fail "Homebrew is required for automatic macOS dependency installation."
    fail "Install Homebrew from: https://brew.sh/"
    fail "Then re-run this installer."
    exit 1
fi

if [[ "$OS" == "unknown" ]]; then
    fail "Unsupported operating system: $(uname -s)"
    exit 1
fi

if [[ "$OS" != "macos" && "$OS" != "linux" ]]; then
    fail "This installer currently supports Linux and macOS."
    fail "Detected: $OS"
    exit 1
fi

if [[ -z "$PKG_MANAGER" ]]; then
    fail "No supported package manager detected."
    exit 1
fi

info "Detected OS:      ${OS}"
[[ -n "$DISTRO"      ]] && info "Detected distro:  ${DISTRO}"
[[ -n "$PKG_MANAGER" ]] && info "Package manager:  ${PKG_MANAGER}"

# ──────────────────────────────────────────────────────────────
# PROFILE / PATH HELPERS
# ──────────────────────────────────────────────────────────────

get_shell_profile() {
    local shell_name
    shell_name="$(basename "${SHELL:-bash}")"

    case "$shell_name" in
        zsh)  echo "${HOME}/.zshrc" ;;
        bash)
            if [[ "$OS" == "macos" ]]; then
                echo "${HOME}/.bash_profile"
            else
                echo "${HOME}/.bashrc"
            fi
            ;;
        fish) echo "${HOME}/.config/fish/config.fish" ;;
        *)    echo "${HOME}/.profile" ;;
    esac
}

PROFILE="$(get_shell_profile)"

add_path_line() {
    local path_to_add="$1"
    local line="export PATH=\"\$PATH:${path_to_add}\""

    [[ ! -f "$PROFILE" ]] && touch "$PROFILE"

    if ! grep -Fq "$path_to_add" "$PROFILE" 2>/dev/null; then
        printf '\n# Talon\n%s\n' "$line" >> "$PROFILE"
    fi

    export PATH="$PATH:$path_to_add"
}

# ──────────────────────────────────────────────────────────────
# VERSION COMPARISON
# (avoids GNU-only sort -V; works on macOS/BSD)
# ──────────────────────────────────────────────────────────────

go_version_ok() {
    local version="$1"
    local major minor

    major="${version%%.*}"
    minor="${version#*.}"
    minor="${minor%%.*}"

    [[ "$major" =~ ^[0-9]+$ ]] || return 1
    [[ "$minor" =~ ^[0-9]+$ ]] || return 1

    if   (( major >  MIN_GO_MAJOR )); then return 0
    elif (( major == MIN_GO_MAJOR && minor >= MIN_GO_MINOR )); then return 0
    else return 1
    fi
}

# ──────────────────────────────────────────────────────────────
# PACKAGE INSTALLATION
# ──────────────────────────────────────────────────────────────

install_packages() {
    local packages=("$@")

    case "$PKG_MANAGER" in
        apt)
            info "Installing packages with apt..."
            $SUDO apt-get update -qq
            $SUDO apt-get install -y -qq "${packages[@]}"
            ;;
        pacman)
            info "Installing packages with pacman..."
            $SUDO pacman -Sy --needed --noconfirm "${packages[@]}"
            ;;
        dnf)
            info "Installing packages with dnf..."
            $SUDO dnf install -y "${packages[@]}"
            ;;
        yum)
            info "Installing packages with yum..."
            $SUDO yum install -y "${packages[@]}"
            ;;
        zypper)
            info "Installing packages with zypper..."
            $SUDO zypper --non-interactive install "${packages[@]}"
            ;;
        apk)
            info "Installing packages with apk..."
            $SUDO apk add --no-cache "${packages[@]}"
            ;;
        brew)
            info "Installing packages with Homebrew..."
            brew update >/dev/null 2>&1 || true
            brew install "${packages[@]}"
            ;;
        *)
            fail "No supported package manager detected."
            fail "Supported: apt, pacman, dnf, yum, zypper, apk, brew."
            exit 1
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# BASE PACKAGES
# ──────────────────────────────────────────────────────────────

install_base_packages() {
    info "Installing base dependencies..."

    case "$PKG_MANAGER" in
        apt)
            install_packages \
                curl wget git unzip jq \
                build-essential libpcap-dev ca-certificates \
                python3 python3-pip python3-venv
            ;;
        pacman)
            install_packages \
                curl wget git unzip jq \
                base-devel libpcap ca-certificates \
                python python-pip python-virtualenv
            ;;
        dnf | yum)
            install_packages \
                curl wget git unzip jq \
                gcc gcc-c++ make libpcap-devel ca-certificates \
                python3 python3-pip
            ;;
        zypper)
            install_packages \
                curl wget git unzip jq \
                gcc gcc-c++ make libpcap-devel ca-certificates \
                python3 python3-pip
            ;;
        apk)
            install_packages \
                curl wget git unzip jq \
                build-base libpcap-dev ca-certificates \
                python3 py3-pip python3-dev
            ;;
        brew)
            install_packages \
                curl wget git unzip jq libpcap python
            ;;
        *)
            fail "Cannot install base packages on this platform."
            exit 1
            ;;
    esac

    ok "Base packages installed."
}

install_base_packages

# ──────────────────────────────────────────────────────────────
# PYTHON VERSION CHECK
# ──────────────────────────────────────────────────────────────

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    fail "Python 3.${MIN_PY_MINOR}+ is required but was not found even after base install."
    exit 1
fi

PY_VER="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER#*.}"

if (( PY_MAJOR < MIN_PY_MAJOR || (PY_MAJOR == MIN_PY_MAJOR && PY_MINOR < MIN_PY_MINOR) )); then
    fail "Python ${PY_VER} found, but talon.py needs ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+."
    exit 1
fi
ok "Python ${PY_VER} (${PYTHON_BIN})"

# ──────────────────────────────────────────────────────────────
# GO TOOLCHAIN
# ──────────────────────────────────────────────────────────────

install_go_from_official() {
    local arch goarch os_name
    local go_tag go_tarball go_url tmp_go

    arch="$(uname -m)"

    case "$arch" in
        x86_64 | amd64)          goarch="amd64"   ;;
        aarch64 | arm64)         goarch="arm64"   ;;
        armv7l)                  goarch="armv6l"  ;;
        *)
            fail "Unsupported CPU architecture for Go installation: $arch"
            exit 1
            ;;
    esac

    case "$OS" in
        linux) os_name="linux"  ;;
        macos) os_name="darwin" ;;
        *)
            fail "Unsupported OS for Go installation: $OS"
            exit 1
            ;;
    esac

    info "Fetching current Go release from go.dev..."

    go_tag="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)"

    if [[ -z "$go_tag" ]]; then
        fail "Could not determine the latest Go release."
        fail "Install Go >= ${MIN_GO_MAJOR}.${MIN_GO_MINOR} manually."
        exit 1
    fi

    go_tarball="${go_tag}.${os_name}-${goarch}.tar.gz"
    go_url="https://go.dev/dl/${go_tarball}"

    tmp_go="$(mktemp -d)"
    trap 'rm -rf "$tmp_go"' RETURN

    info "Downloading ${go_tarball}..."
    curl -fsSL "$go_url" -o "$tmp_go/go.tar.gz"

    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$tmp_go/go.tar.gz"

    add_path_line "/usr/local/go/bin"
    ok "Installed $(/usr/local/go/bin/go version)"
}

install_go() {
    local current_version=""

    if command -v go >/dev/null 2>&1; then
        current_version="$(
            go version |
            grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' |
            sed 's/^go//' |
            head -n1
        )"

        if [[ -n "$current_version" ]] && go_version_ok "$current_version"; then
            ok "Go ${current_version} already installed."
            return
        fi

        warn "Installed Go ${current_version:-unknown} is older than ${MIN_GO_MAJOR}.${MIN_GO_MINOR}."
    fi

    # Try the OS package manager first.
    case "$PKG_MANAGER" in
        brew)   brew install go >/dev/null 2>&1 || brew upgrade go >/dev/null 2>&1 || true ;;
        apt)    $SUDO apt-get install -y -qq golang-go >/dev/null 2>&1 || true ;;
        pacman) $SUDO pacman -S --needed --noconfirm go >/dev/null 2>&1 || true ;;
        dnf)    $SUDO dnf install -y golang >/dev/null 2>&1 || true ;;
        yum)    $SUDO yum install -y golang >/dev/null 2>&1 || true ;;
        zypper) $SUDO zypper --non-interactive install go >/dev/null 2>&1 || true ;;
        apk)    $SUDO apk add --no-cache go >/dev/null 2>&1 || true ;;
    esac

    hash -r 2>/dev/null || true

    if command -v go >/dev/null 2>&1; then
        current_version="$(
            go version |
            grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' |
            sed 's/^go//' |
            head -n1
        )"

        if [[ -n "$current_version" ]] && go_version_ok "$current_version"; then
            ok "Go ${current_version} installed."
            return
        fi
    fi

    # Package manager Go was too old — fall back to official archive.
    install_go_from_official
}

install_go

# ──────────────────────────────────────────────────────────────
# GOPATH / GOBIN / LOCAL BIN
# ──────────────────────────────────────────────────────────────

mkdir -p "$GOBIN_DIR" "$LOCAL_BIN"
add_path_line "$GOBIN_DIR"
add_path_line "$LOCAL_BIN"
export PATH="$PATH:${GOBIN_DIR}:${LOCAL_BIN}"
hash -r 2>/dev/null || true

if ! command -v go >/dev/null 2>&1; then
    fail "Go is not available after installation."
    exit 1
fi

# ──────────────────────────────────────────────────────────────
# GO TOOLS
# (recon toolchain + Talon's own gf/nuclei/notify, all installed here)
# ──────────────────────────────────────────────────────────────

info "Installing Go-based tools..."

bin_exists() {
    local bin="$1"
    [[ -x "${GOBIN_DIR}/${bin}" ]] || command -v "$bin" >/dev/null 2>&1
}

go_install() {
    local pkg="$1"
    local bin_name="$2"
    local log_file="/tmp/talon-goinstall-${bin_name}.log"

    printf '  %b%-14s%b' "$DIM" "$bin_name" "$RESET"

    if bin_exists "$bin_name"; then
        printf ' %bskip (already installed)%b\n' "$CYAN" "$RESET"
        return
    fi

    if go install "$pkg" >"$log_file" 2>&1; then
        printf ' %b\xE2\x9C\x93%b\n' "$GREEN" "$RESET"
    else
        printf ' %b\xE2\x9C\x97%b\n' "$RED" "$RESET"
        warn "Installation failed for ${bin_name}. See ${log_file}"
    fi
}

# Recon
go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"            "httpx"
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"              "dnsx"
go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"         "naabu"
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"          "katana"
go_install "github.com/tomnomnom/assetfinder@latest"                       "assetfinder"
go_install "github.com/tomnomnom/anew@latest"                              "anew"
go_install "github.com/melvinsh/subfaster/v2/cmd/subfaster@latest"         "subfaster"

# Triage
go_install "github.com/tomnomnom/gf@latest"                          "gf"
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
go_install "github.com/projectdiscovery/notify/cmd/notify@latest"    "notify"
go_install "github.com/ffuf/ffuf/v2@latest"                          "ffuf"

ok "Go-based tools processed."

hash -r 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# FINDOMAIN
# ──────────────────────────────────────────────────────────────

install_findomain() {
    if bin_exists findomain; then
        ok "findomain already installed — skipping."
        return
    fi

    case "$PKG_MANAGER" in
        brew)
            info "Installing findomain with Homebrew..."
            if brew list findomain >/dev/null 2>&1; then
                ok "findomain already installed."
                return
            fi
            if brew install findomain >/dev/null 2>&1; then
                ok "findomain installed."
                return
            fi
            ;;
        pacman)
            info "Installing findomain with pacman..."
            if $SUDO pacman -S --needed --noconfirm findomain >/dev/null 2>&1; then
                ok "findomain installed."
                return
            fi
            ;;
    esac

    local arch asset tmp_fd url
    arch="$(uname -m)"

    case "${OS}:${arch}" in
        linux:x86_64 | linux:amd64)          asset="findomain-linux.zip"   ;;
        linux:aarch64 | linux:arm64)         asset="findomain-aarch64.zip" ;;
        linux:armv7l)                        asset="findomain-armv7.zip"   ;;
        macos:x86_64 | macos:amd64)          asset="findomain-osx.zip"     ;;
        macos:arm64 | macos:aarch64)         asset="findomain-osx.zip"     ;;
        *)
            warn "No known prebuilt findomain binary for ${OS}/${arch}. Skipping."
            return
            ;;
    esac

    tmp_fd="$(mktemp -d)"
    url="https://github.com/Findomain/Findomain/releases/latest/download/${asset}"

    info "Downloading findomain..."

    if curl -fsSL "$url" -o "$tmp_fd/findomain.zip"; then
        if unzip -q -o "$tmp_fd/findomain.zip" -d "$tmp_fd"; then
            local binary
            binary="$(
                find "$tmp_fd" -type f \
                    \( -name 'findomain' -o -name 'findomain.dms' \) \
                    -print -quit
            )"

            if [[ -n "$binary" ]]; then
                chmod +x "$binary"
                $SUDO install -m 0755 "$binary" /usr/local/bin/findomain
                ok "findomain installed to /usr/local/bin/findomain."
            else
                warn "findomain archive did not contain the expected binary."
            fi
        else
            warn "Could not extract findomain archive."
        fi
    else
        warn "Could not download findomain."
    fi

    rm -rf "$tmp_fd"
}

install_findomain

# ──────────────────────────────────────────────────────────────
# FEROXBUSTER
# (used by --dir-brute — opt-in, but talon.py -h advertises it, so it
# should actually be there)
# ──────────────────────────────────────────────────────────────

install_feroxbuster() {
    if bin_exists feroxbuster; then
        ok "feroxbuster already installed — skipping."
        return
    fi

    case "$PKG_MANAGER" in
        brew)
            info "Installing feroxbuster with Homebrew..."
            if brew install feroxbuster >/dev/null 2>&1; then
                ok "feroxbuster installed."
                return
            fi
            ;;
        apt)
            info "Installing feroxbuster with apt..."
            if $SUDO apt-get install -y -qq feroxbuster >/dev/null 2>&1; then
                ok "feroxbuster installed."
                return
            fi
            ;;
        pacman)
            info "Installing feroxbuster with pacman..."
            if $SUDO pacman -S --needed --noconfirm feroxbuster >/dev/null 2>&1; then
                ok "feroxbuster installed."
                return
            fi
            ;;
    esac

    local arch asset tmp_fx url
    arch="$(uname -m)"

    case "${OS}:${arch}" in
        linux:x86_64 | linux:amd64)   asset="x86_64-linux-feroxbuster.zip"  ;;
        linux:aarch64 | linux:arm64)  asset="aarch64-linux-feroxbuster.zip" ;;
        linux:armv7l)                 asset="armv7-linux-feroxbuster.zip"  ;;
        macos:x86_64 | macos:amd64)   asset="x86_64-macos-feroxbuster.zip"  ;;
        macos:arm64 | macos:aarch64)  asset="x86_64-macos-feroxbuster.zip" ;;
        *)
            warn "No known prebuilt feroxbuster binary for ${OS}/${arch}."
            warn "--dir-brute will be unavailable until it's installed manually: https://github.com/epi052/feroxbuster"
            return
            ;;
    esac

    tmp_fx="$(mktemp -d)"
    url="https://github.com/epi052/feroxbuster/releases/latest/download/${asset}"

    info "Downloading feroxbuster..."

    if curl -fsSL "$url" -o "$tmp_fx/feroxbuster.zip"; then
        if unzip -q -o "$tmp_fx/feroxbuster.zip" -d "$tmp_fx"; then
            local binary
            binary="$(find "$tmp_fx" -type f -name 'feroxbuster' -print -quit)"

            if [[ -n "$binary" ]]; then
                chmod +x "$binary"
                $SUDO install -m 0755 "$binary" /usr/local/bin/feroxbuster
                ok "feroxbuster installed to /usr/local/bin/feroxbuster."
            else
                warn "feroxbuster archive did not contain the expected binary."
                warn "--dir-brute will be unavailable until it's installed manually."
            fi
        else
            warn "Could not extract feroxbuster archive. --dir-brute will be unavailable until installed manually."
        fi
    else
        warn "Could not download feroxbuster. --dir-brute will be unavailable until installed manually."
    fi

    rm -rf "$tmp_fx"
}

install_feroxbuster

# ──────────────────────────────────────────────────────────────
# TRUFFLEHOG
# (secret verification for the JS secret-scan pass — required by default,
# same as wafw00f, since talon.py only skips it with --no-js-scan)
# ──────────────────────────────────────────────────────────────

install_trufflehog() {
    if bin_exists trufflehog; then
        ok "trufflehog already installed — skipping."
        return
    fi

    case "$PKG_MANAGER" in
        brew)
            info "Installing trufflehog with Homebrew..."
            if brew install trufflehog >/dev/null 2>&1; then
                ok "trufflehog installed."
                return
            fi
            ;;
    esac

    # No apt/pacman/dnf package — trufflehog's own release assets embed the
    # version in the filename (trufflehog_<version>_<os>_<arch>.tar.gz), so
    # unlike findomain/feroxbuster's version-agnostic asset names, the
    # current version has to be resolved first (same pattern install_go
    # already uses against go.dev/VERSION).
    local arch asset tmp_th url version tag
    arch="$(uname -m)"

    case "${OS}:${arch}" in
        linux:x86_64 | linux:amd64)   asset_os="linux"; asset_arch="amd64"  ;;
        linux:aarch64 | linux:arm64)  asset_os="linux"; asset_arch="arm64"  ;;
        macos:x86_64 | macos:amd64)   asset_os="darwin"; asset_arch="amd64" ;;
        macos:arm64 | macos:aarch64)  asset_os="darwin"; asset_arch="arm64" ;;
        *)
            warn "No known prebuilt trufflehog binary for ${OS}/${arch}."
            warn "JS secret scanning will be unavailable until it's installed manually: https://github.com/trufflesecurity/trufflehog"
            return
            ;;
    esac

    info "Resolving latest trufflehog release..."
    tag="$(curl -fsSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')"

    if [[ -z "$tag" ]]; then
        warn "Could not resolve the latest trufflehog version (GitHub API rate limit or network issue)."
        warn "JS secret scanning will be unavailable until it's installed manually: https://github.com/trufflesecurity/trufflehog"
        return
    fi

    asset="trufflehog_${tag}_${asset_os}_${asset_arch}.tar.gz"
    url="https://github.com/trufflesecurity/trufflehog/releases/latest/download/${asset}"
    tmp_th="$(mktemp -d)"

    info "Downloading trufflehog ${tag}..."

    if curl -fsSL "$url" -o "$tmp_th/trufflehog.tar.gz"; then
        if tar -xzf "$tmp_th/trufflehog.tar.gz" -C "$tmp_th" trufflehog 2>/dev/null; then
            chmod +x "$tmp_th/trufflehog"
            $SUDO install -m 0755 "$tmp_th/trufflehog" /usr/local/bin/trufflehog
            ok "trufflehog installed to /usr/local/bin/trufflehog."
        else
            warn "trufflehog archive did not extract as expected."
            warn "JS secret scanning will be unavailable until it's installed manually."
        fi
    else
        warn "Could not download trufflehog (a release tagged moments ago can take ~15min for CI to attach binaries — try again shortly, or install manually)."
        warn "JS secret scanning will be unavailable until it's installed manually: https://github.com/trufflesecurity/trufflehog"
    fi

    rm -rf "$tmp_th"
}

install_trufflehog

# ──────────────────────────────────────────────────────────────
# PYTHON ENVIRONMENT
# (dedicated venv — no --break-system-packages needed)
# ──────────────────────────────────────────────────────────────

install_python_tools() {
    info "Creating Talon Python virtual environment..."

    [[ ! -d "$PYTHON_VENV" ]] && "$PYTHON_BIN" -m venv "$PYTHON_VENV"

    "$PYTHON_VENV/bin/python" -m pip install \
        --upgrade pip setuptools wheel >/dev/null

    if [[ -x "${PYTHON_VENV}/bin/waymore" ]] || command -v waymore >/dev/null 2>&1; then
        ok "waymore already installed — skipping."
    else
        info "Installing waymore..."
        "$PYTHON_VENV/bin/python" -m pip install --upgrade waymore >/dev/null
    fi

    if [[ -x "${PYTHON_VENV}/bin/paramspider" ]] || command -v paramspider >/dev/null 2>&1; then
        ok "paramspider already installed — skipping."
    else
        # NOTE: `pip install paramspider` from PyPI is a name-squatted
        # placeholder with no working CLI. The real tool is only on GitHub.
        info "Installing ParamSpider from GitHub..."
        "$PYTHON_VENV/bin/python" -m pip install --upgrade \
            "git+https://github.com/devanshbatham/ParamSpider.git" >/dev/null
    fi

    if [[ -x "${PYTHON_VENV}/bin/wafw00f" ]] || command -v wafw00f >/dev/null 2>&1; then
        ok "wafw00f already installed — skipping."
    else
        # talon.py requires wafw00f by default (only --no-waf-detect skips
        # it) — unlike waymore/paramspider this one isn't optional.
        info "Installing wafw00f..."
        "$PYTHON_VENV/bin/python" -m pip install --upgrade wafw00f >/dev/null
    fi

    add_path_line "${PYTHON_VENV}/bin"
    export PATH="${PYTHON_VENV}/bin:${PATH}"

    ok "Python tools processed."
}

install_python_tools

# ──────────────────────────────────────────────────────────────
# GF PATTERNS
# ──────────────────────────────────────────────────────────────

info "Checking GF pattern definitions..."

if [[ -d "$GF_DIR" ]] && compgen -G "${GF_DIR}/*.json" >/dev/null 2>&1; then
    PATTERN_COUNT="$(find "$GF_DIR" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
    ok "GF patterns already present in ${GF_DIR} (${PATTERN_COUNT} files)"
else
    info "Cloning GF pattern set..."
    mkdir -p "$GF_DIR"
    TMP_GF="$(mktemp -d)"

    if git clone --depth 1 --quiet https://github.com/1ndianl33t/Gf-Patterns "$TMP_GF" 2>/dev/null; then
        cp "$TMP_GF"/*.json "$GF_DIR"/
        rm -rf "$TMP_GF"
        ok "GF patterns installed to ${GF_DIR}"
    else
        rm -rf "$TMP_GF"
        fail "Could not clone the GF pattern set — Talon's triage stage needs these."
        fail "Install manually: git clone https://github.com/1ndianl33t/Gf-Patterns and copy *.json into ${GF_DIR}"
    fi
fi

# ──────────────────────────────────────────────────────────────
# TALON-AUTHORED GF PATTERNS
# (nosqli/proto-pollution — 1ndianl33t/Gf-Patterns doesn't ship either;
# these are Talon's own, so unlike the clone above they're always
# (re)written to stay in sync with whatever talon.py expects, not just
# written once. Talon's MANUAL_CLASSES docstring for these two explains
# why they route to the manual queue rather than nuclei auto-fuzzing:
# no generic nuclei signature exists for either class, and both real
# bug classes are normally triggered via a POST body key, not the URL
# these patterns match against — they identify candidate endpoints
# worth a hand-tested body payload, not confirmed hits.)
# ──────────────────────────────────────────────────────────────

info "Writing Talon's own GF patterns (nosqli, proto-pollution)..."
mkdir -p "$GF_DIR"

cat > "${GF_DIR}/nosqli.json" <<'GFEOF'
{
    "flags": "-iE",
     "patterns": [

        "username=",
        "password=",
        "passwd=",
        "login=",
        "email=",
        "search=",
        "query=",
        "filter=",
        "sort=",
        "sortby=",
        "orderby=",
        "where=",
        "find=",
        "lookup=",
        "\\$where",
        "\\$ne",
        "\\$regex",
        "\\$gt",
        "\\$lt",
        "\\$in",
        "\\$or",
        "\\$exists"
]
}
GFEOF

cat > "${GF_DIR}/proto-pollution.json" <<'GFEOF'
{
    "flags": "-iE",
     "patterns": [

        "__proto__",
        "constructor(\\[|%5[bB])prototype",
        "constructor\\.prototype",
        "prototype(\\[|%5[bB])",
        "merge=",
        "extend=",
        "assign=",
        "settings=",
        "options=",
        "update="
]
}
GFEOF

ok "GF patterns nosqli.json / proto-pollution.json written to ${GF_DIR}"

# ──────────────────────────────────────────────────────────────
# CMSEEK
# (optional — talon.py's detect_cms_names() checks for
# ~/Tools/CMSeeK/cmseek.py itself and simply skips CMS detection if it's
# not there, so failures here are never fatal to the installer)
# ──────────────────────────────────────────────────────────────

info "Checking CMSeeK (optional — CMS fingerprint pass)..."

CMSEEK_DIR="${HOME}/Tools/CMSeeK"

if [[ -f "${CMSEEK_DIR}/cmseek.py" ]]; then
    ok "CMSeeK already present at ${CMSEEK_DIR}"
else
    mkdir -p "${HOME}/Tools"
    if git clone --depth 1 --quiet https://github.com/Tuhinshubhra/CMSeeK "$CMSEEK_DIR" 2>/dev/null; then
        if [[ -f "${CMSEEK_DIR}/requirements.txt" ]]; then
            # CMSeeK is invoked by talon.py via the system `python3`, not
            # Talon's own venv, so its deps need to land where that
            # python3 can see them.
            if "$PYTHON_BIN" -m pip install --user -r "${CMSEEK_DIR}/requirements.txt" >/dev/null 2>&1; then
                ok "CMSeeK installed to ${CMSEEK_DIR}"
            else
                warn "CMSeeK cloned but its Python dependencies failed to install."
                warn "CMS fingerprinting will be skipped until: pip install --user -r ${CMSEEK_DIR}/requirements.txt"
            fi
        else
            ok "CMSeeK installed to ${CMSEEK_DIR}"
        fi
    else
        warn "Could not clone CMSeeK — CMS fingerprinting will be skipped (this is non-fatal)."
        warn "Install manually: git clone https://github.com/Tuhinshubhra/CMSeeK ${CMSEEK_DIR}"
    fi
fi

# ──────────────────────────────────────────────────────────────
# SECLISTS
# (optional — only used by --vhost-fuzz/--dir-brute, which talon.py
# itself skips with a warning if the wordlist files aren't found, so a
# failed/unavailable install here is also never fatal. Not git-cloned
# directly: the full SecLists repo is several hundred MB, too large to
# pull unconditionally on every install.)
# ──────────────────────────────────────────────────────────────

info "Checking SecLists (optional — --vhost-fuzz/--dir-brute wordlists)..."

if [[ -f /usr/share/seclists/Discovery/DNS/combined_subdomains.txt ]]; then
    ok "SecLists already present at /usr/share/seclists"
else
    case "$PKG_MANAGER" in
        apt)    $SUDO apt-get install -y -qq seclists >/dev/null 2>&1 && ok "SecLists installed." || warn "seclists package not available via apt on this distro." ;;
        pacman) $SUDO pacman -S --needed --noconfirm seclists >/dev/null 2>&1 && ok "SecLists installed." || warn "seclists package not available via pacman (try an AUR helper: yay -S seclists)." ;;
        dnf)    $SUDO dnf install -y seclists >/dev/null 2>&1 && ok "SecLists installed." || warn "seclists package not available via dnf on this distro." ;;
        brew)   brew install seclists >/dev/null 2>&1 && ok "SecLists installed." || warn "seclists package not available via brew." ;;
        *)      warn "No known seclists package for ${PKG_MANAGER}." ;;
    esac
    if [[ ! -f /usr/share/seclists/Discovery/DNS/combined_subdomains.txt ]]; then
        warn "--vhost-fuzz/--dir-brute will skip with a warning until SecLists is installed manually:"
        warn "  git clone https://github.com/danielmiessler/SecLists /usr/share/seclists"
    fi
fi

# ──────────────────────────────────────────────────────────────
# NUCLEI TEMPLATES
# (pre-fetch so the first real run isn't stalled on a download)
# ──────────────────────────────────────────────────────────────

if bin_exists nuclei; then
    info "Updating nuclei-templates..."
    if nuclei -update-templates -silent >/dev/null 2>&1; then
        ok "nuclei-templates up to date"
    else
        warn "nuclei template update failed (check network) — templates may be stale on first run"
    fi
fi

# ──────────────────────────────────────────────────────────────
# CAIDO REMINDER (GUI app — nothing to install here)
# ──────────────────────────────────────────────────────────────

if command -v caido >/dev/null 2>&1; then
    ok "Caido found on PATH"
else
    info "Caido not detected on PATH — that's expected if you run it as a GUI app."
    info "Talon's --caido-proxy just needs Caido listening on 127.0.0.1:8080 (default)."
fi

# ──────────────────────────────────────────────────────────────
# SYMLINK talon ONTO PATH
# ──────────────────────────────────────────────────────────────

chmod +x "${SCRIPT_DIR}/talon.py"
ln -sf "${SCRIPT_DIR}/talon.py" "${LOCAL_BIN}/talon"
ok "Symlinked talon -> ${SCRIPT_DIR}/talon.py"

# ──────────────────────────────────────────────────────────────
# FINAL PATH REFRESH
# ──────────────────────────────────────────────────────────────

export PATH="${GOBIN_DIR}:${LOCAL_BIN}:${PYTHON_VENV}/bin:${PATH}"
hash -r 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# VERIFY
# ──────────────────────────────────────────────────────────────

printf '\n%b\n' "${CYAN}${BOLD}=== Verifying installation ===${RESET}"

TOOLS=(
    curl jq go python3
    subfinder httpx dnsx naabu katana
    assetfinder anew subfaster findomain
    waymore paramspider wafw00f trufflehog
    gf nuclei notify ffuf feroxbuster
    talon
)

FAILED=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '  %b\xE2\x9C\x93%b %-12s %s\n' "$GREEN" "$RESET" "$tool" "$(command -v "$tool")"
    elif [[ "$tool" == "ffuf" || "$tool" == "feroxbuster" ]]; then
        # Opt-in features (--vhost-fuzz/--dir-brute) — missing binary
        # doesn't block a default run, so it's a warning, not a failure.
        printf '  %b!%b %-12s %s\n' "$YELLOW" "$RESET" "$tool" "NOT FOUND (only needed for --vhost-fuzz/--dir-brute)"
    else
        printf '  %b\xE2\x9C\x97%b %-12s %s\n' "$RED" "$RESET" "$tool" "NOT FOUND"
        FAILED=1
    fi
done

if [[ -f "${HOME}/Tools/CMSeeK/cmseek.py" ]]; then
    printf '  %b\xE2\x9C\x93%b %-12s %s\n' "$GREEN" "$RESET" "cmseek" "${HOME}/Tools/CMSeeK/cmseek.py"
else
    printf '  %b!%b %-12s %s\n' "$YELLOW" "$RESET" "cmseek" "NOT FOUND (CMS fingerprint pass will be skipped — non-fatal)"
fi

if [[ -f /usr/share/seclists/Discovery/DNS/combined_subdomains.txt ]]; then
    printf '  %b\xE2\x9C\x93%b %-12s %s\n' "$GREEN" "$RESET" "seclists" "/usr/share/seclists"
else
    printf '  %b!%b %-12s %s\n' "$YELLOW" "$RESET" "seclists" "NOT FOUND (only needed for --vhost-fuzz/--dir-brute)"
fi

printf '\n'

if [[ "$FAILED" -ne 0 ]]; then
    warn "Some tools are missing. Open a new shell or run:"
    printf '    source "%s"\n\n' "$PROFILE"
    warn "Then run this installer again."
    exit 1
fi

warn "Open a new shell, or run:"
printf '    source "%s"\n\n' "$PROFILE"
ok "Talon installation completed successfully."
ok "Run:"
printf '    talon -t example.com\n\n'
