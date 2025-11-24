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

# mindset

- **target offers you a vulnerability** (dont force a vulnerability to the target)
- **Least Change Principle**
- **HOOK based fuzzing**
- *modern websites cannob be crawled by automated tools*
- *always update your wordlist* 
- *should review checker functions in js*
- Narrow Recon (most difficult)-> ***ThreatModeling*** (add context to tests) -> Test
- Go as deep as you can but dont skip
- Narrow Recon (JS)
- replacement after ruleset (= checker function or waf) is a killer
- to know a program we must explore it like a nomal user 