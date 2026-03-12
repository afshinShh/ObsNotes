# mindset

- **target offers you a vulnerability** (dont force a vulnerability to the target)
- **Least Change Principle**
- **HOOK based fuzzing**
- *modern websites cannob be crawled by automated tools*
- *always update your wordlist* 
- *should review checker functions in js*
- *Complexity may be benefitial to you if you get used to it* 
- Narrow Recon (most difficult)-> ***ThreatModeling*** (add context to tests) -> Test
- Go as deep as you can but dont skip
- Narrow Recon (JS)
- replacement after ruleset (= checker function or waf) is a killer
- to know a program we must explore it like a nomal user 
- Paid features are golden areas
# Wide Recon -> wider attack surface
- [ ] domain discovery
	- [ ]  google dork
		- [ ] ==footer's legal information==
	- [ ] favicon/logo search 
	- [ ] ==TLD search== the findings could be either: 
		- [ ] mirror domain
		- [ ] seperate domain
	- [ ] certificate search
		- [ ] => new domain, subdomain, property
		- [ ] use Censys, shodan, crt.sh
		- [ ] interesting fields
			- [ ] `Issuer`, `Subject`, `Alternative Name: DNS` 

- tld search oneliner also you can use [tldx as the better alternative](https://github.com/brandonyoungdev/tldx)
```bash
curl -s https://data.iana.org/TLD/tlds-alpha-by-domain.txt | tail -n +2 | tr 'A-Z' 'a-z' | sed 's/^/domain:/'
```
- [ ] whois 
- [ ] reverse whois
	- [ ] `website.informer.com`
	- [ ] `viewdns.info`
- [ ] name resolution   
	- [ ] [dnsx](https://github.com/projectdiscovery/dnsx)
- [ ] monitor the sites with no http response 
- [ ] Avoid falling into third-parties 
# Narrow recon -> more features

- Dorking 
	- google + ===Bing=== 
	- omit the resources you wont need
- better to use old diffrernt snapshots in wayback machine [How?](https://archive.org/developers/wayback-cdx-server.html)
	- use `fl=timestamp` + `collapse=digest` for differet hashes
	- you can use [robofinder](https://github.com/Spix0r/robofinder) for robots.txt
server API - `https://archive.org/developers/wayback-cdx-server.html`
> [!example] usage examples :
```
https://web.archive.org/cdx/search/cdx?url=https://icollab.info
https://web.archive.org/web/2021|208105512if_/http://icollab.info
https://web.archive.org/cdx/search/cdx?url=*.capcut.com/*&fl=timestamp,original&collapse=digest
https://web.archive.org/cdx/search/cdx?url=*.capcut.com/&fl=original&collapse=urlkey
```
- Katana is not good with DOM 
	- *Passive Crawling always / active crawling only in automation*
- [ ] phase 0
	- [ ] work with every bit of app like a normal user 
	- [ ] build mind-map
	- [ ] do not fall into rabbit holes
	- [ ] figure out as many functionalities as possible 
	- [ ] you will see the patterns with enough hunt
- [ ] phase 1 
	- [ ] passive crawling
		- [ ] search engine dorking 
			- [ ] google ==and== bing (NOT OR) + DuckDuckGo
			- [ ] repeat the search with the ommited results included
			- [ ] make your own dork strings based on the target
- [ ] `ext:html` -> when you see raw HTML page test for DOM XSS (some of them might hide functionality behind) 
	- [ ] do not fuzz on them 
	- [ ] look for sinks and sources in DOM
- [ ] directly connected to backend `ext:aspx,php,asp,jsp,`

## what to look
- [ ] does the application have ==certain== ***threat model***?
	- [ ] changing property of organization without premission
	- [ ] changing a property of my organization without permissions
- [ ] what is the application **used for**?
	- [ ] overall business logic
	- [ ] the failure of confidentiality
	- [ ] the failure of integrity
- [ ] how does the application **pass data**?
	- [ ] legacy, all in one, UI + backend
	- [ ] simple web app + jQuery
	- [ ] single page applications (SPA) + rest API
	- [ ] single page applications (SPA) + graphQL
	- [ ] web-socket communication
- [ ] how does the application **handles users**?
    - [ ] what are authentication schemes?
    - [ ] Cookie, token, JWT, etc
    - [ ] 2FA implementations
    - [ ] account delegations
    - [ ] are there other user levels?
    - [ ] is there any authentication transfer?
## threat modeling
- [ ] prepating potential avenus of attack
- [ ] determining the most affective types of attacks
- [ ] understaning the context and related risks
> [!example]
> 	- reflection => XSS  or SSTI
> 	- URL input => SSRF
> 	- file uploader => RCE or XSS
> 	- SQL database called => SQLi
> 	- POST login + sensitive endpoints + misconfig => CORS
> 	- POST login + unwanted action => CSRF
- [ ] use [BackSlash Powered Scanner](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8) for general fuzz in inputs 
	- [ ] see the presentation's paper ( from james kettle ) [here](https://blackhat.com/docs/eu-16/materials/eu-16-Kettle-Backslash-Powered%20Scanning-Hunting-Unknown-Vulnerability-Classes.pdf)
- unicodes are decoded in js code
	- in nodejs apps : yashar === y\u0061shar
- HTML attributes are decoded automatically
- XSS is not related to content-type => always check for it (e.g  json:) 
	- doesnt url encode/decode
	- XSS in json sent data -> must be *DOM XSS* 

# Reporting
## sections 
### attack scenario
- [ ]  avoid using 
	- [ ] potentially
	- [ ] attacker can (without POC)
		- [ ] attacker can achieve RCE by this CVE...
		- [ ] attacker can exploit XSS into ATO 
	- [ ] may, might
- [ ] precisely write what you have done
- [ ] straight to the point + scenario
> [!example]
> ![[Pasted image 20260312182906.png]]

> [!example]
> ![[Pasted image 20260312183111.png]]
### steps to reproduce 
- [ ] do not teach triager team anything
- [ ] be clear, be precise, steps by steps 
- [ ] include Burp packets (text or image) 
> [!example] attacker side: ... victim side: ...
### POC Video
- [ ] less than 2 minute (most effective is 30 seconds)
- [ ] only show the attack scenario
- [ ] only read one or 2 most important files you can read in case of LFI dont go furthure 
### going forward 
- [ ] ask the program to grant premission 
- [ ] Wordpress -> takeover -> plugin (Shell) -> i did not 
### CVSS /CWE 
- [[Reporting#CVSS CWE|more details here]]
## mistakes
- [ ] unnecessary data + long report
- [ ] ==potentially== attacker ==can==,... 
- [ ] ==simple POC== at start (Then complex exploit)