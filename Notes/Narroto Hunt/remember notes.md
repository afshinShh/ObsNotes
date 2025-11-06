
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