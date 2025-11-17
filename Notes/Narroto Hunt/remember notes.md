
- unicodes are decoded in js code
	- in nodejs apps : yashar === y\u0061shar
- HTML attributes are decoded automatically
- XSS is not related to content-type => always check for it (e.g  json:) 
	- doesnt url encode/decode
	- XSS in json sent data -> must be *DOM XSS* 
# XSS
## Contexts: 
- **Outside a tag**
	- script tag
	- tag + event handler
	-  </a> + js scheme 
	- non executable tag (eg </title>)
- **Inside a tag** 
	- break the attr & tag 
	- break the attr + event handler
	- attr (eg href / srcdoc)
- **JS context**
	- close </script>
	- break the context (expressions "-" )
- **DOM**
	- reflected but not in source code (ctrl + u ) => DOM
- **postMessage**
	- dangerous sink ? yes 
		- can we control input? yes
			- is it vulnerable? depends => can I Exploit my friend?
	- we cannot forge e.origin in message 
	- not only XSS but CSRF or ATO
## Post XSS
- [ ] ATO
	- [ ] change password
	- [ ] account bind (linking victim's account to that account = in other words: integrations)
- [ ] PII information leakage



# Narrow recon

- Dorking 
	- google + ===Bing=== 
	- omit the resources you wont need
- better to use old diffrernt snapshots in wayback machine [How?](https://archive.org/developers/wayback-cdx-server.html)
	- use `fl=timestamp` + `collapse=digest` for differet hashes
	- you can use [robofinder](https://github.com/Spix0r/robofinder) for robots.txt
- Katana is not good with DOM 
	- *Passive Crawling always / active crawling only in automation*
-  

# FUZZing
- sanding maformed|unexpected HTTP reqs
- to trigger unexpected behavior
- to discover hidden|unlinked  resources 
	- files
	- parameter
	- header
- you should balance the fuzzing condition
- ***FOLLOW the LEAST CHANGE principle***
### hidden resources
- unlinked directories|files
- development|testing environments
- API endpoints
- config files
### tools 
- FFUF
- recollapse
- crunch
- hand
- GAP
	- use value replacement -> observe interesting behavior(reflection|change|malfunction) -> *reduce* and change values to exploit 
- fallparams 
	- discover parameters at first and filterout (leach:) 
- x8 | Arjun
- paramMiner
- IIS shortname scanner
### checking phase
### inputs
### files
### endpoints
### parameters
- query string parameters can be increased, as long as the server handles the request (in average 25 -> 40 params)
- the number of parameters included in each HTTP request is called a ***chunk***
	- smaller chunk => improves discovery
- fuzz on various *status codes* (including 404 -> web application)
- fuzzing *headers is similar to fuzzing parameters*, nothing special
- fuzz with both *GET and POST* HTTP methods
#### magic parameters
- every web app has hidden parameters
	- Findable in web app
	- *similar to other parameter names*
		- yahoo_home_ui
		- yahoo_home_redirect
	- totally new
- ==**programmers use the same parameter names on different pages**==
	- (e.g all params -> unfurl (extract params) -> use elsewhere)
- **where**? 
	- all HTTP req parameters
	- HTML form names + ids + etc
	- JS variable names
	- JSON object in js files
- example ? 
	- (passive (waymore + paramSpider)(`inurl:? || inurl:&`) + active (manually like GAP + automated like x8 + fallparams))
	-  (e.g manual GAP -> replace values -> interesting behavior | e.g automated x8)
	- *MANUALL is ALWASY BETTER* (false positive)
/gitcommi