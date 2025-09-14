```bash

#!/bin/bash
# Minimal HTB bootstrap — quiet, idempotent, no aliases.
# - Updates apt safely (handles Debian testing codename changes)
# - Installs core tools via apt
# - Preps wordlists (rockyou)
# - Clones/updates key GitHub repos (PEASS-ng, PayloadsAllTheThings, GTFOBins, Nishang, PowerSploit, Feroxbuster)
# - Installs impacket, pwncat-cs via pip
# - Installs CrackMapExec from GitHub (not PyPI)
# - Builds Feroxbuster via cargo if not already available

set -e
export DEBIAN_FRONTEND=noninteractive

log() { echo "[*] $*"; }

# --- apt update (safe on Debian testing rollovers) ---
log "apt update..."
sudo apt-get -yq update --allow-releaseinfo-change

# --- core tools ---
log "Installing core tools..."
sudo apt-get -yq install --no-install-recommends \
  nmap gobuster enum4linux smbmap smbclient \
  rlwrap tmux jq unzip wget curl git python3-pip build-essential seclists

# --- wordlists (rockyou ready) ---
log "Preparing wordlists..."
mkdir -p "$HOME/seclists"
ln -sfn /usr/share/seclists "$HOME/seclists"
if [ ! -f "$HOME/seclists/Passwords/rockyou.txt" ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
  mkdir -p "$HOME/seclists/Passwords"
  gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$HOME/seclists/Passwords/rockyou.txt" || true
fi

# --- helper: clone or pull a repo ---
clone_or_pull () {
  local url="$1" dest="$2"
  if [ ! -d "$dest/.git" ]; then
    log "Cloning $(basename "$dest")..."
    git clone "$url" "$dest"
  else
    log "Updating $(basename "$dest")..."
    git -C "$dest" pull --quiet || true
  fi
}

# --- GitHub tool repos ---
mkdir -p "$HOME/tools"

# Feroxbuster (repo; binary built below)
clone_or_pull "https://github.com/epi052/feroxbuster.git" "$HOME/tools/feroxbuster"

# PEASS-ng (linPEAS/winPEAS)
clone_or_pull "https://github.com/carlospolop/PEASS-ng.git" "$HOME/tools/PEASS-ng"

# PayloadsAllTheThings
clone_or_pull "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "$HOME/tools/payloads"

# GTFOBins (offline reference)
clone_or_pull "https://github.com/GTFOBins/GTFOBins.github.io.git" "$HOME/tools/gtfobins"

# Nishang (PowerShell offensive scripts)
clone_or_pull "https://github.com/samratashok/nishang.git" "$HOME/tools/nishang"

# PowerSploit (post-exploitation)
clone_or_pull "https://github.com/PowerShellMafia/PowerSploit.git" "$HOME/tools/PowerSploit"

# --- PEASS convenience: make sure linPEAS is executable (repo has builder; script path varies) ---
if [ -f "$HOME/tools/PEASS-ng/linPEAS/linpeas.sh" ]; then
  chmod +x "$HOME/tools/PEASS-ng/linPEAS/linpeas.sh" || true
fi

# --- Python tooling ---
log "Upgrading pip (quiet) and installing Python tools..."
python3 -m pip install -q --upgrade pip || true
python3 -m pip install -q impacket pwncat-cs || true

# CrackMapExec installs from GitHub (PyPI is not maintained for CME)
if ! command -v cme >/dev/null 2>&1 && ! command -v crackmapexec >/dev/null 2>&1; then
  log "Installing CrackMapExec from GitHub..."
  python3 -m pip install -q "git+https://github.com/Porchetta-Industries/CrackMapExec.git" || true
fi

# --- Feroxbuster binary build (one-time) ---
# If feroxbuster isn't already in PATH, build it with cargo (Rust).
if ! command -v feroxbuster >/dev/null 2>&1; then
  log "Building feroxbuster via cargo..."
  sudo apt-get -yq install --no-install-recommends cargo || true
  # Prefer installing from crates.io for a clean binary in ~/.cargo/bin
  cargo install feroxbuster || true
  # Ensure cargo bin dir is in PATH for future shells
  if ! grep -q 'HOME/.cargo/bin' "$HOME/.profile" 2>/dev/null; then
    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.profile"
  fi
fi

log "Done. (Open a new shell to pick up any PATH changes)"


```
