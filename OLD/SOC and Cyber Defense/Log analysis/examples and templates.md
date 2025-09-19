# intro to logs
## log formats
### Semi-structured Logs 
#### Syslog Message Format
```bash
damianhall@WEBSRV-02:~/logs$ cat syslog.txt

May 31 12:34:56 WEBSRV-02 CRON[2342593]: (root) CMD ([ -x /etc/init.d/anacron ] && if [ ! -d /run/systemd/system ]; then /usr/sbin/invoke-rc.d anacron start >/dev/null; fi)
```
#### Windows Event Log (EVTX)
```powershell
PS C:\WINDOWS\system32> Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\Application.evtx"


   ProviderName: Microsoft-Windows-Security-SPP

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
31/05/2023 17:18:24           16384 Information      Successfully scheduled Software Protection service for re-start
31/05/2023 17:17:53           16394 Information      Offline downlevel migration succeeded.
```

### Structured Logs
#### Field Delimited Formats
```bash
"time","user","action","status","ip","uri"
"2023-05-31T12:34:56Z","adversary","GET",200,"34.253.159.159","http://gitlab.swiftspend.finance:80/"
```
#### JavaScript Object Notation (JSON)
```json
{"time": "2023-05-31T12:34:56Z", "user": "adversary", "action": "GET", "status": 200, "ip": "34.253.159.159", "uri": "http://gitlab.swiftspend.finance:80/"}
```
#### W3C Extended Log Format (ELF)
```elf
#Version: 1.0 
#Fields: date time c-ip c-username s-ip s-port cs-method cs-uri-stem sc-status 31-May-2023 13:55:36 34.253.159.159 adversary 34.253.127.157 80 GET /explore 200
```
#### eXtensible Markup Language (XML)
```xml
<log><time>2023-05-31T12:34:56Z</time><user>adversary</user><action>GET</action><status>200</status><ip>34.253.159.159</ip><url>https://gitlab.swiftspend.finance/</url></log>
```
### Unstructured Logs
#### NCSA Common Log Format (CLF)
```bash
34.253.159.159 - adversary [31/May/2023:13:55:36 +0000] "GET /explore HTTP/1.1" 200 4886

```
#### NCSA Combined Log Format (Combined)
```bash
34.253.159.159 - adversary [31/May/2023:13:55:36 +0000] "GET /explore HTTP/1.1" 200 4886 "http://gitlab.swiftspend.finance/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```