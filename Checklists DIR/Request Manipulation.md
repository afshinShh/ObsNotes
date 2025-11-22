# Open Redirect
- [ ] where?
	- [ ] *after finishing important action* 
		- [ ] Sign in & register pages 
		- [ ] Sign out 
	- [ ] *multi stage functions* (takes different steps to complete)
		- [ ] Password resets
		- [ ] Email verification links 
			- [ ] check for [password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning#how-does-a-password-reset-work) 
	- [ ] Profile account page
	- [ ] ERROR pages
- [ ] determine the type
	- [ ] header based (server side)? [[Notes/Request Manipulation#Open Redirect#header based (= serverside redirect)|e.g]]
	- [ ] HTML/Javascript based (client side) [[Notes/Request Manipulation#Open Redirect#JS based(= client side redirect)|e.g]]
- [ ] find the <mark style="background: #FFF3A3A6;">checker function</mark> [[Notes/Request Manipulation#Open Redirect#checker function|e.g]]
	- [ ] FUZZ to bypass
		- [ ] ratelimit (OR not :) ? -> [[URL Validation#Open Redirect Manual list |manual fuzz]] 
		- [ ] url validation [cheatsheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet) | [[URL Validation#[PayloadsAllTheThings](https //github.com/swisskyrepo/PayloadsAllTheThings/tree/master)|payload all the things]]
		- [ ] Recollapse
## chain
- [ ] javascript scheme -> XSS
- [ ] authentication flow  -> ATO
- [ ] GET-based CSRF 
- [ ] server requester function + whitelist => SSRF
# Request Smuggling
/git