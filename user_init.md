```bash

#!/bin/bash
# Minimal HTB bootstrap — fast, quiet, idempotent.

set -e
export DEBIAN_FRONTEND=noninteractive

echo "[*] apt update..."
sudo apt-get -yq update

echo "[*] Installing core tools..."
sudo apt-get -yq install --no-install-recommends \
  nmap gobuster enum4linux smbmap smbclient \
  rlwrap tmux jq unzip wget curl git python3-pip build-essential seclists

# ---------- Feroxbuster (from official release) ----------
echo "[*] Installing feroxbuster..."
mkdir -p "$HOME/tools"
curl -fsSL https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb \
  -o "$HOME/tools/feroxbuster.deb"
sudo dpkg -i "$HOME/tools/feroxbuster.deb" || sudo apt-get -yq -f install

# ---------- Wordlists ----------
mkdir -p "$HOME/seclists"
ln -sfn /usr/share/seclists "$HOME/seclists"
if [ ! -f "$HOME/seclists/Passwords/rockyou.txt" ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
  mkdir -p "$HOME/seclists/Passwords"
  gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$HOME/seclists/Passwords/rockyou.txt" || true
fi

# ---------- PEAS (Linux/Windows) ----------
mkdir -p "$HOME/tools/peas"
curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
  -o "$HOME/tools/peas/linpeas.sh" && chmod +x "$HOME/tools/peas/linpeas.sh"
curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe \
  -o "$HOME/tools/peas/winPEASx64.exe"

# ---------- Windows basics (quiet) ----------
python3 -m pip install -q --upgrade pip || true
python3 -m pip install -q impacket crackmapexec pwncat-cs || true

# ---------- Shell helpers (aliases + on-demand functions) ----------
if ! grep -q "^# HTB_BLOCK_BEGIN" "$HOME/.bashrc" 2>/dev/null; then
cat >> "$HOME/.bashrc" <<'HTBRC'

# HTB_BLOCK_BEGIN
# --- Aliases ---
alias serve='python3 -m http.server 8000'              # quick HTTP server in cwd
alias linpeas='bash ~/too


```
