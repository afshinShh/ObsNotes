# CSRF
- Conditions
	- [ ] The targeted functionality or feature must be ==privileged==
	- [ ] session ID must be a cookie with the ==SameSite== cookie policy set to "None" or "Lax" -> [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/concepts and defense#Strict SameSite cookies|Concept]]
	- [ ] HTTP request shouldn't carry any ==unpredictable values==

- need POC? ->  [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#POCs|POC examples]]

- [ ] _unpredictable_ Header based Authorization (like JWT OR custom header) =>  CSRF patched (Unless...?)
- [ ] is there any XSS ? -> CSRF is unavoidable  
- [ ]  it checks **`Referer`**? [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#Referrer-based CSRF|Examples]]
	- [ ] request without a referer header
	- [ ] bypass the checker function
- [ ] Application supports <mark style="background: #FFB86CA6;">Flash</mark> ?
	- [ ] use malicious Flash file (.swf) -> Flash-based CSRF ([poc](https://github.com/appsecco/json-flash-csrf-poc?))
- [ ] Change **Content-Type** (<mark style="background: #FFB86CA6;">Json based</mark> CSRF) [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#Content-Type based CSRF|Examples]]
	- [ ] **`text/plain`**
	- [ ] `application/x-www-form-urlencoded`
	- [ ] `multipart/form-data`
- [ ] Check Other Protocols
	- [ ] cross-site <mark style="background: #FFB86CA6;">WebSocket</mark> hijacking (CSWSH) ([[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#cross-site WebSocket hijacking (CSWSH)|Example]]) 
- [ ] Check CSRF in <mark style="background: #FFB86CA6;">Graphql</mark> endpoints [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#CSRF in Graphql endpoints|Example POC]]
## Bypassing CSRF-token validation

- [ ] change request method (e.g post to get) 
	- [ ] use (`_method=POST`) in query string 
		- [ ]   `/users/delete?user_id=5&_method=POST`
	- [ ] delete method property from form entirely 
- [ ] mess with the CSRF token
	- [ ] delete CSRF parameter
	- [ ] `ZkfcxrWQ9CeoG` -> `ZkfcxrWQ9CeoG_random_`
	- [ ] CSRF Token = Static + Dynamic part ? -> predict 
	- [ ] calculate entropy -> Predict 
- [ ] is the **csrftoken tied to session**?
	- [ ] same request from 2 different user? (Double Submit)
	  - [ ] swap csrf values
	  - [ ] make request -> save csrf -> drop request -> use the saved csrf-token with another user 
	- [ ] is there any **csrfKey cookie**? 
		- [ ] the cookie is not tied to the session ? 
			- [ ] use csrf-token+csrfKey on another user
			- [ ] find sink where you can inject cookie [[unprocessed-obsidians/OLD/WEB/vulnerabilities/CSRF/attack/Examples#token tied to non-session cookie|Example Senario]] 
		- [ ] same csrf is duplicated in cookie ? -> Create and inject csrf cookie (same as injecting csrfKey)
