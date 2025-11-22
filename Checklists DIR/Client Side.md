# CSRF

- need POC? ->  [[OLD/WEB/vulnerabilities/CSRF/attack/Examples#POCs|POC examples]]
- [ ] Header based Authorization (like JWT OR custom header) =>  CSRF patched (Unless...)
- [ ] is there any XSS ? -> CSRF is unavoidable  
- [ ]  it checks `Referer`?
	- [ ] bypass the checker function
- [ ] Application supports **Flash** ?
	- [ ] use malicious Flash file (.swf) -> Flash-based CSRF ([poc](https://github.com/appsecco/json-flash-csrf-poc?))
## Bypassing CSRF-token validation

- [ ] change request method (e.g post to get) 
- [ ] delete method property
- [ ] delete CSRF parameter 
- [ ] is the **csrftoken tied to session**?
	- [ ] same request from 2 different user? (Double Submit)
	  - [ ] swap csrf values
	  - [ ] make request -> save csrf -> drop request -> use the saved csrf-token with another user 
	- [ ] is there any **csrfKey cookie**? 
		- [ ] the cookie is not tied to the session ? 
			- [ ] use csrf-token+csrfKey on another user
			- [ ] find sink where you can inject cookie [[OLD/WEB/vulnerabilities/CSRF/attack/Examples#token tied to non-session cookie|Example Senario]] 
- [ ] same csrf is duplicated in cookie -> invent csrf token -> inject csrf cookie (same as injecting csrfKey)
- [ ] calculate entropy -> Predict 