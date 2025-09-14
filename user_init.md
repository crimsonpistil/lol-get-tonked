# user_init
```bash

#!/bin/bash
# HTB bootstrap — core tools + GitHub clones + prebuilt PEASS binaries + Python tools in venv.

set -e
export DEBIAN_FRONTEND=noninteractive
log() { echo "[*] $*"; }

# --- apt update (safe for Debian testing rollovers) ---
log "apt update..."
sudo apt-get -yq update --allow-releaseinfo-change

# --- core tools ---
log "Installing core tools..."
sudo apt-get -yq install --no-install-recommends \
  nmap gobuster enum4linux smbmap smbclient \
  rlwrap tmux jq unzip wget curl git python3-pip python3-venv \
  build-essential seclists cherrytree

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

# --- GitHub tool repos (for docs/scripts/offline reference) ---
mkdir -p "$HOME/tools"
clone_or_pull "https://github.com/epi052/feroxbuster.git"            "$HOME/tools/feroxbuster"
clone_or_pull "https://github.com/carlospolop/PEASS-ng.git"          "$HOME/tools/PEASS-ng"
clone_or_pull "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "$HOME/tools/payloads"
clone_or_pull "https://github.com/GTFOBins/GTFOBins.github.io.git"   "$HOME/tools/gtfobins"
clone_or_pull "https://github.com/samratashok/nishang.git"           "$HOME/tools/nishang"
clone_or_pull "https://github.com/PowerShellMafia/PowerSploit.git"   "$HOME/tools/PowerSploit"

# --- PEASS prebuilt release binaries (ready-to-serve/download) ---
log "Fetching prebuilt PEASS binaries..."
mkdir -p "$HOME/tools/peas"
# linPEAS (bash) prebuilt
curl -fsSL "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" \
  -o "$HOME/tools/peas/linpeas.sh" && chmod +x "$HOME/tools/peas/linpeas.sh"
# winPEAS (x64) prebuilt
curl -fsSL "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" \
  -o "$HOME/tools/peas/winPEASx64.exe"

# --- Python tooling in isolated venv (avoid system package conflicts) ---
log "Setting up Python venv for offensive tools..."
VENV_DIR="$HOME/.venvs/offsec"
BIN_DIR="$HOME/bin"
mkdir -p "$BIN_DIR"

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install -q --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install -q impacket pwncat-cs
# CrackMapExec from GitHub (not PyPI)
if [ ! -x "$VENV_DIR/bin/cme" ] && [ ! -x "$VENV_DIR/bin/crackmapexec" ]; then
  "$VENV_DIR/bin/python" -m pip install -q "git+https://github.com/Porchetta-Industries/CrackMapExec.git" || true
fi

# Expose common tools via ~/bin so they work without activating the venv
ln -sfn "$VENV_DIR/bin/cme"        "$BIN_DIR/cme"         2>/dev/null || true
ln -sfn "$VENV_DIR/bin/pwncat-cs"  "$BIN_DIR/pwncat-cs"   2>/dev/null || true
for tool in secretsdump.py psexec.py smbclient.py wmiexec.py dcomexec.py; do
  [ -x "$VENV_DIR/bin/$tool" ] && ln -sfn "$VENV_DIR/bin/$tool" "$BIN_DIR/$tool"
done
grep -q 'export PATH="$HOME/bin:$PATH"' "$HOME/.profile" 2>/dev/null || echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.profile"

# --- Feroxbuster binary (install via cargo if not present) ---
if ! command -v feroxbuster >/dev/null 2>&1; then
  log "Building feroxbuster via cargo..."
  sudo apt-get -yq install --no-install-recommends cargo || true
  cargo install feroxbuster || true
  grep -q 'HOME/.cargo/bin' "$HOME/.profile" 2>/dev/null || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.profile"
fi

log "Done. Open a new shell or run:  source ~/.profile"


```
---
# HTB Initial Set-Up

## Core Recon / Enum Tools (via apt)

-   `nmap` → port scanning, service detection, NSE scripts
-   `gobuster` → directory & virtual host brute forcing
-   `enum4linux` → SMB/NetBIOS enumeration
-   `smbmap` → enumerate SMB shares & permissions
-   `smbclient` → interact with SMB shares

## Utility Tools

-   `rlwrap` → gives readline support (history, arrow keys) to tools like `nc`
-   `tmux` → terminal multiplexer (manage multiple panes/sessions)
-   `jq` → parse/manipulate JSON (useful for APIs, JWTs)
-   `unzip`, `wget`, `curl`, `git` → file & repo handling
-   `build-essential` → compilers (for exploit building)
-   `seclists` → wordlists at `~/seclists/`
    -   RockYou: `~/seclists/Passwords/rockyou.txt`

## Python Offensive Tools (via venv in `~/.venvs/offsec`)

-   `cme` → CrackMapExec (network exploitation, SMB/WinRM/LDAP, etc.)
-   `pwncat-cs` → post-exploitation handler / persistence shell
-   **Impacket scripts (symlinked to ~/bin):**
    -   `secretsdump.py` → dump hashes from SAM/NTDS
    -   `psexec.py` → get shell via SMB service install
    -   `wmiexec.py` → WMI command execution
    -   `dcomexec.py` → DCOM-based command execution
    -   `smbclient.py` → Python SMB client

## GitHub Repos (cloned into `~/tools/`)

-   `PEASS-ng` → `linPEAS/linpeas.sh` (Linux priv esc) and `winPEAS/winPEASx64.exe`
-   `PayloadsAllTheThings` → `~/tools/payloads/` (web & exploit payloads)
-   `GTFOBins` → `~/tools/gtfobins/` (local privesc tricks)
-   `Nishang` → `~/tools/nishang/` (PowerShell offensive scripts)
-   `PowerSploit` → `~/tools/PowerSploit/` (post-exploitation PowerShell)
-   `feroxbuster` → Rust dirbuster (`feroxbuster` binary installed via cargo)

## Feroxbuster (after build)

-   Run with:

    `feroxbuster -u http://target/ -w ~/seclists/Discovery/Web-Content/raft-medium-words.txt`

* * *

### Quick Reference

-   Linux privesc:

    `bash ~/tools/PEASS-ng/linPEAS/linpeas.sh`

-   Windows privesc:

    `~/tools/PEASS-ng/winPEAS/winPEASx64.exe`

-   CrackMapExec SMB:

    `cme smb 10.10.10.0/24 -u user -p pass`

-   Impacket secretsdump:

    `secretsdump.py domain/user:pass@host`

