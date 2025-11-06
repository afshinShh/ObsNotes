## Basic

- ***SSRF attacks against the server*** -> HTTP request back to the server that is hosting the application. 
  - **How?** -> URL with <mark style="background: #FFB86CA6;">hostname = loopback</mark>. [[OLD/WEB/vulnerabilities/SSRF/Examples#against the server|example]]
    - `127.0.0.1`
    - `localhost`
  - **Why?** -> _trust relationships_
    - <mark style="background: #D2B3FFA6;">access control check implemented component sits in front</mark> of the application server
    - <mark style="background: #D2B3FFA6;">disaster recovery</mark> -> allow administrative access without logging in.
    - administrative interface might <mark style="background: #D2B3FFA6;">listen on a different port</mark> number to the main application.
- ***SSRF attacks against other back-end systems*** -> interact with back-end systems that are not directly reachable by users.
	- **How?** -> <mark style="background: #FFB86CA6;">non-routable private IP addresses</mark>. [[OLD/WEB/vulnerabilities/SSRF/Examples#against other back-end systems|example]] 
	  - `https://192.168.0.68/admin` 
	- **Why?** -> The back-end systems are normally <mark style="background: #D2B3FFA6;">protected by the network topology</mark>. => weaker security posture.
# Circumventing common SSRF defenses
## blacklist-based input filters

- <mark style="background: #ADCCFFA6;">alternative IP representation</mark> of `127.0.0.1`
  - `2130706433`
  - `017700000001`
  - `127.1`
- Register <mark style="background: #ADCCFFA6;">your own domain</mark> name that resolves to `127.0.0.1`:
  - `spoofed.burpcollaborator.net`
-  [[Obfuscation#Obfuscating attacks using encodings| Obfuscate]] -> URL encoding or case variation
- <mark style="background: #ADCCFFA6;">try to redirect</mark> :
  - different redirect codes
  - different protocols -> `http:` to `https:` 
 [[OLD/WEB/vulnerabilities/SSRF/Examples#blacklist-based input filters|example]]
## whitelist-based input filters
#todo 
[new era of SSRF slides (orange/blackhat)](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
## via open redirection

- application *trusts* the redirection from itself -> request to the desired back-end target [[OLD/WEB/vulnerabilities/SSRF/Examples#via open redirection|example]]

# Blind SSRF

- the *response from the back-end request is not returned* in the application's front-end response => impact is often lower
## out-of-band (OAST)

- -> trigger an HTTP request to an *external system* that you control
- firewalls may <mark style="background: #FFB8EBA6;">block HTTP requests but allow DNS</mark> lookup.
### Exploitability 
#todo
# hidden attack surface 

[Cracking the lens: Remote client exploits](https://portswigger.net/blog/cracking-the-lens-targeting-https-hidden-attack-surface#remoteclient)

-  **Partial URLs in requests**:
   - only a hostname or part of a URL path into request parameters
   - exploitability as full SSRF might be limited

-  **URLs within data formats**:
   - XML data format as an example => SSRF via XXE
  
- **SSRF via the Referer header**:
  - server-side analytics software to track visitors
  - including the anchor text that is used in the incoming links
  - => _Blind SSRF_  
