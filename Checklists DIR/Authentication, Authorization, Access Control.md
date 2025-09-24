
# general 
### behavior inconsistency
 - difference in:
	  - [ ] *Status codes*
	  - [ ] *Error messages
	  - [ ] *Response times*
## Brute Force protection / acount locking / rate limits

  - [ ] <mark style="background: #ADCCFFA6;">include your own login credentials</mark> at regular intervals throughout the wordlist. [[WEB/vulnerabilities/Authentication vulnerabilities/payload#IP block|example]] 
#### Blocking the remote user's IP address
  - [ ] Fuzz IP/host related headers (`X-Forwarded-For`,...)
##  Registration

- [ ] Test password quality rules
- [ ] Test username uniqueness
- [ ] Ensure disposable email addresses are rejected
- [ ] check **Email specific payloads**
	- [ ] alternative formats (`hacker@gmail.com`  = `hacker+anything@gmail.com`  = `h.a.c.k.e.r@gmail.com`)
	- [ ] signup with email of corporation (`very-long-string@Corporation.com.attacker.com`)
	- [ ] injections in email -> `"<svg/onload=alert(1)>"@corpmail.com` 
## Login

- [ ] Test for **username enumeration**
- [ ] Test resilience to password guessing
### (Remember me | Keep me logged in) Cookies
- [ ] test for any sign of **predictability** 
	- [ ] Entropy 
	- [ ] gussable pattern
	- [ ] uses open source framework to generate -> look for misconfig
- [ ] **weak encryption** of the token
	- [ ] no salt -> rainbow attack
### one-time login links
 - [ ] Lack of **Expiration** 
	 - [ ] Search for Leaked or gusssable links 
### Resetting user passwords | Changing user passwords
- <mark style="background: #BBFABBA6;">Links are getting dynamically generated </mark>
	- [ ] Parameter Tempering 
		- [ ] [Password Poisening](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) Attack (when links  are getting created by a third party ) [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Resetting user passwords#password reset poisoning via middleware|senario]]
			- [ ] Test Host Header Injection 
			- [ ] Test Host Header injection through middlewares (`X-Forwarded-Host`)
- [ ] if you can **access directly without being logged in** as the victim user (example: usename can be provided within hidden field)
	- [ ] try if it Bypasses Bruteforce limitations
	- [ ] try if it Bypasses Ratelimit  

## Forget Password

- the link should be
	- [ ] unique 
	- [ ] unpredictable 
	- [ ] safe  

## Multi Factor Auth

- [ ] Second factor of authentication should not be **brute-force-able** 
- [ ] Second factor of authentication should not be **removable**
- [ ] verification code on a separate page ->  *"logged in" state before code verification* [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#simple bypass|senario]]
- [ ]  *doesn't verify* that the *same user* is completing the second step [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#broken logic|senario]]
- [ ] Weak Security Questions ? 
# Access Control

- [ ] Test For **Un-Encrypted Channel** (e.g http)
- [ ] **Default Credentials**
- [ ] try **Response Manipulation** (to bypass client side checks)
- [ ] search client side source code for credentials 
- [ ]  
## HTTP basic authentication
- [ ] BruteForce attacks 
	- [ ] default credentials 
- [ ] Session related attacks [[WEB/vulnerabilities/CSRF/attack/METHODOLOGY|METHODOLOGY]].
- [ ] if has **HSTS** 
	- [ ] [session side jacking](https://en.wikipedia.org/w/index.php?title=Session_hijacking&action=edit&section=2)
- [ ] **Forced Browsing** (directly requesting the resource behind the authentication wall)
      ![[Pasted image 20250921210252.png]]
- [ ] **HTTP verb Tempering**



## Trusted IP whitelist

# SSO

- [ ] Test parameters like `redirect_uri` 
	- [ ] To ***steal token*** and potential Account takeover 
		- [ ] (e.g `attacker.com`)
		- [ ] if limited to whitelist -> Try **open redirect** 
		      (e.g `sub.site.com/logout?r=https://attacker.com/log`  and `https://site.com/oauth/callback/../../user/profile?next=https://attacker.com`)
		- [ ] if SSO works by **XHR => CORS** implemented
			- [ ] bypass checker function (e.g `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`)
			- [ ] if CORS on .site.com -> XSS on subdomains 
		- [ ] if SSO works by **JSONP** and the JavaScript object is accessible **any other cross site** 
# OAuth

- [ ] is the **proper flow** used ? 
	- [ ] client credentials can be kept secret: 
		- [ ] yes (classic web app) -> Authorization code flow 
		- [ ] no (SPA , mobile - desktop apps, ...) -> Authorization code flow  + *PKCE*
- [ ] Check for **CSRF** protection (`state` parameter)
- [ ] Check the `redirect_url` vulns Mentioned above => account takeover  
- [ ] if **implicit grant type** ( access token sent via users's browser = exposed in url)
	- [ ] parameter tampering on the final request which token gets send to server
- [ ] can `scope` be changed after user consent ? -> **scope upgrade** attack
- [ ] is Authorization token, short lived and one-time use ?
- [ ] is client's secret protected and verified ? -> **client confusion** attack

