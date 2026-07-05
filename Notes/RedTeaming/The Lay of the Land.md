concepts to know 
- VLAN and Segmentation
- DMZ
## network enumeration
 - **netstat** -> open ports as well as the established connections
```powershell
PS C:\Users\thm> netstat -na

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
```
- **arp** -> IP address and the physical address of the computers
```powershell
PS C:\Users\thm> arp -a

Interface: 10.10.141.51 --- 0xa
  Internet Address      Physical Address      Type
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic
  10.10.255.255         ff-ff-ff-ff-ff-ff     static
```
## AD (active directory environment)

[[AD (Active Directory)#Concepts|concepts to know]] :
- Domain Controller
- Organizational units
- AD objects
- AD domains
- Forest
- AD service accounts -> Built-in local users, Domain users, Managed service accounts
-  Domain Administrators 
In order to check whether the Windows machine is part of the AD environment or not, one way, we can use the command prompt **systeminfo** command.

```powershell
PS C:\Users\thm> systeminfo | findstr Domain
OS Configuration:          Primary Domain Controller
Domain:                    thmdomain.com
```
> [!note] Note that if we get WORKGROUP in the domain section, then it means that this machine is part of a local workgroup.

## Users and Group managemenet

concepts to know :
- ==Account discovery== is the first step once we have gained initial access to the compromised machine to understand what we have and what other accounts are in the system.
- ==Common Active Directory service accounts== include built-in local user accounts, domain user accounts, managed service accounts, and virtual accounts.
![[Pasted image 20260704162200.png]]
### Active Directory (AD) Enum
```powershell
PS C:\Users\thm> Get-ADUser  -Filter *
# We can also use the [LDAP hierarchical tree structure:(http://www.ietf.org/rfc/rfc2253.txt) to find a user within the AD environment

# The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN), and others.
PS C:\Users\thm> Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"

DistinguishedName : CN=Administrator,CN=Users,DC=thmredteam,DC=com
	Enabled           : True
GivenName         :
Name              : Administrator
ObjectClass       : user
ObjectGUID        : 4094d220-fb71-4de1-b5b2-ba18f6583c65
SamAccountName    : Administrator
SID               : S-1-5-21-1966530601-3185510712-10604624-500
Surname           :
UserPrincipalName :
```

## Host security solutions 

#### **Antivirus software** including:
	- Signature-based detection
	- Heuristic-based detection
	- Behavior-based detection
  
```powershell
PS C:\Users\thm> wmic /namespace:\\root\securitycenter2 path antivirusproduct
```
This also can be done using PowerShell, which gives the same result.
```powershell
PS C:\Users\thm> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct


displayName              : Bitdefender Antivirus
instanceGuid             : {BAF124F4-FA00-8560-3FDE-6C380446AEFB}
pathToSignedProductExe   : C:\Program Files\Bitdefender\Bitdefender Security\wscfix.exe
pathToSignedReportingExe : C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe
productState             : 266240
timestamp                : Wed, 15 Dec 2021 12:40:10 GMT
PSComputerName           :
displayName              : Windows Defender
instanceGuid             : {D58FFC3A-813B-4fae-9E44-DA132C9FAA36}
pathToSignedProductExe   : windowsdefender://
pathToSignedReportingExe : %ProgramFiles%\Windows Defender\MsMpeng.exe
productState             : 393472
timestamp                : Fri, 15 Oct 2021 22:32:01 GMT
PSComputerName           :
```

#### Microsoft Windows Defender
```powershell
PS C:\Users\thm> Get-Service WinDefend

Status   Name               DisplayName
------   ----               -----------
Running  WinDefend          Windows Defender Antivirus Service
```

```powershell
PS C:\Users\thm> Get-MpComputerStatus | select RealTimeProtectionEnabled

RealTimeProtectionEnabled
-------------------------
False
# => As a result, MpComputerStatus highlights whether Windows Defender is enabled or not.
```
> [!note] Using PowerShell cmdlets such **Get-MpThreat** can provide us with threats details that have been detected using MS Defender

#### Host-based **Firewall**
```powershell
PS C:\Users\thm> Get-NetFirewallProfile | Format-Table Name, Enabled

Name    Enabled
----    -------
Domain     True
Private    True
Public     True
```
If we have *admin privileges* on the current user we logged in with, then we try to disable one or more than one
```powershell
PS C:\Windows\system32> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
PS C:\Windows\system32> Get-NetFirewallProfile | Format-Table Name, Enabled
---- -------
Domain False
Private False
Public False
```
check the current Firewall rules, whether allowing or denying by the firewall.
```powershell
PS C:\Users\thm> Get-NetFirewallRule | select DisplayName, Enabled, Description

DisplayName                                                                  Enabled
-----------                                                                  -------
Lab Machine Monitoring (DCOM-In)                                           False
Lab Machine Monitoring (Echo Request - ICMPv4-In)                          False
Lab Machine Monitoring (Echo Request - ICMPv6-In)                          False
Lab Machine Monitoring (NB-Session-In)                                     False
Lab Machine Monitoring (RPC)                                               False
SNMP Trap Service (UDP In)                                                     False
SNMP Trap Service (UDP In)                                                     False
Connected User Experiences and Telemetry                                        True
Delivery Optimization (TCP-In)                                                  True
```
During the red team engagement, we have no clue what the firewall blocks. However, we can take advantage of some PowerShell cmdlets such as **Test-NetConnection** and **TcpClient**. Assume we know that a firewall is in place, and we need to test inbound connection without extra tools, then we can do the following:
```powershell
PS C:\Users\thm> Test-NetConnection -ComputerName 127.0.0.1 -Port 80


ComputerName     : 127.0.0.1
RemoteAddress    : 127.0.0.1
RemotePort       : 80
InterfaceAlias   : Loopback Pseudo-Interface 1
SourceAddress    : 127.0.0.1
TcpTestSucceeded : True

PS C:\Users\thm> (New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
True
# => inbound connection on port 80 is open and allowed
```
> [!note] we can also test for remote targets in the same network or domain names by specifying in the **-ComputerName** argument for the Test-NetConnection.

#### Security Event **Logging and Monitoring**   
concepts to know :
- HIDS / IDS
- HIPS / IPS
	- heuristic/signature based 
	- anomaly based
- Endpoint Detection and Response (EDR) = Endpoint Detection and Threat Response (EDTR)
  ![[Pasted image 20260705135040.png]]
	- We can use scripts for enumerating security products within the machine, such as [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker) and [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker). They check for commonly used Antivirus, , logging monitor products by checking file metadata, processes, loaded into current processes, Services, and drivers, directories.
	  

- For more information about the Get-EventLog cmdlet with examples, visit the [Microsoft documents website](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog).
```powershell
PS C:\Users\thm> Get-EventLog -List

  Max(K) Retain OverflowAction        Entries Log
  ------ ------ --------------        ------- ---
     512      7 OverwriteOlder             59 Active Directory Web Services
  20,480      0 OverwriteAsNeeded         512 Application
     512      0 OverwriteAsNeeded         170 Directory Service
 102,400      0 OverwriteAsNeeded          67 DNS Server
  20,480      0 OverwriteAsNeeded       4,345 System
  15,360      0 OverwriteAsNeeded       1,692 Windows PowerShell
```
##### **System Monitor (Sysmon)** -> more info [here](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

features :
- Process creation and termination
- Network connections
- Modification on file
- Remote threats
- Process and memory access
- and many others
  
==To confirm the existence of Sysmon on the host:==

```powershell
# through processes
PS C:\Users\thm> Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    373      15    20212      31716              3316   0 Sysmon

# through services 
PS C:\Users\thm> Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
# or
Get-Service | where-object {$_.DisplayName -like "*sysm*"}

#through registry

PS C:\Users\thm> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

we can try to find the configuration file if we have readable permission to understand what system administrators are monitoring.
```powershell
PS C:\Users\thm> findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
C:\tools\Sysmon\sysmonconfig.xml:      
C:\tools\Sysmon\sysmonconfig.xml:      
```

## Network Security Solutions

concepts to know:
- **Network Firewalls**
	- Packet-filtering firewalls
	- firewalls
	- NAT firewalls
	- Web application firewalls
- **SIEM** -> combines Security Information Management (SIM) and Security Event Management (SEM) to monitor and analyze events and track and log data in real-time
- **IDS/IPS**

## Applications and services
#### Installed applications  

 We will be using the **wmic** Windows command to list all installed applications and their version.
```powershell
PS C:\Users\thm> wmic product get name,version
Name                                                            Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910     14.28.29910
AWS Tools for Windows                                           3.15.1248
Amazon SSM Agent                                                3.0.529.0
aws-cfn-bootstrap                                               2.0.5
AWS PV Drivers                                                  8.3.4
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910  14.28.29910
```

look for particular text strings, hidden directories, backup files. Then we can use the PowerShell cmdlets, Get-ChildItem, as follow:
```powershell
PS C:\Users\thm> Get-ChildItem -Hidden -Path C:\Users\kkidd\Desktop\
```
#### Services and processes

- Sometimes Windows services have misconfiguration permissions, which escalates the current user access level of permissions. Therefore, we must look at **running services** and perform services and processes reconnaissance.

```powershell
PS C:\Users\thm> net start
These Windows services are started:

Active Directory Web Services
Amazon SSM Agent
Application Host Helper Service
Cryptographic Services
DCOM Server Process Launcher
DFS Namespace
DFS Replication
DHCP Client
Diagnostic Policy Service
THM Demo
DNS Client
```
```powershell
PS C:\Users\thm> wmic service where "name like 'THM Demo'" get Name,PathName
Name         PathName
THM Service  c:\Windows\thm-demo.exe
```

- **Process discovery** is an enumeration step to understand what the system provides.
```powershell
PS C:\Users\thm> Get-Process -Name thm-demo

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     82       9    13128       6200              3212   0 thm-service

```
Once we find its ==process ID==, let's check if providing a network service by listing the listening ports within the system.
```powershell
PS C:\Users\thm> netstat -noa |findstr "LISTENING" |findstr "3212"
  TCP    0.0.0.0:8080          0.0.0.0:0              LISTENING       3212
  TCP    [::]:8080             [::]:0                 LISTENING       3212
```
#### Sharing files and printers  
#### Internal services: DNS and local web applications

```powershell
PS C:\Users\thm> nslookup.exe
Default Server:  UnKnown
Address:  ::1
```