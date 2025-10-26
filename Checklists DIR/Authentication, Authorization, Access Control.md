
# general 
### behavior inconsistency
 - difference in:
	  - [ ] *Status codes*
	  - [ ] *Error messages*
	  - [ ] *Response times*
- [ ] Test For Weak Authentication In **Alternative Channels** 
	- [ ] different user agents
	- [ ] different country,language...
	- [ ] different browsers and applications (webapp,desktop,mobile,...)
## Brute Force protection | acount locking |  Lock Out | rate limits

  - [ ]  Ensure the account has been locked after 3-5 incorrect attempts
  - [ ] <mark style="background: #ADCCFFA6;">include your own login credentials</mark> at regular intervals throughout the wordlist. [[WEB/vulnerabilities/Authentication vulnerabilities/payload#IP block|example]] 
  - [ ] Explore similar endpoints (`/api/v3/sign-up`, `/Sing-up`, `/SignUp`,...)
  - [ ] Blank Characters in Code or Parameters (code=`1234%0a`)
  - [ ] append random parameters
#### CAPTCHA tests #TODO
#### Blocking the remote user's IP address
  - [ ] Manipulating IP Origin via Headers (`X-Forwarded-For`,...)
  - [ ] Double Header trick (use same (or with subtle change) header twice to exploit inconsistency among servers)
##  Registration

- [ ] Test password quality rules
- [ ] Test username uniqueness
- [ ] Ensure disposable email addresses are rejected
- [ ] check **Email specific payloads**
	- [ ] alternative formats (`hacker@gmail.com`  = `hacker+anything@gmail.com`  = `h.a.c.k.e.r@gmail.com`)
	- [ ] `victim@gmail.com%0a` → 0-20 HEX (FUZZ)
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
### Resetting user passwords | Changing user passwords |  Forget Password
- <mark style="background: #BBFABBA6;">Links are getting dynamically generated </mark>
	- [ ] Parameter Tempering 
		- [ ] [Password Poisening](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) Attack (when links  are getting created by a third party ) [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Resetting user passwords#password reset poisoning via middleware|senario]]
			- [ ] Test Host Header Injection 
			- [ ] Test Host Header injection through middlewares (`X-Forwarded-Host`)
- [ ] if you can **access directly without being logged in** as the victim user (example: usename can be provided within hidden field)
	- [ ] try if it Bypasses Bruteforce limitations
	- [ ] try if it Bypasses Ratelimit  

- the link should be
	- [ ] unique 
	- [ ] unpredictable 
	- [ ] safe  

## 2FA | Multi Factor Auth

- [ ] Second factor of authentication should not be **brute-force-able** 
- [ ] Second factor of authentication should not be **removable**
- [ ] Second factor of authentication should not be **Reusable** 
- [ ] verification code on a separate page ->  *"logged in" state before code verification* [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#simple bypass|senario]]
- [ ]  *doesn't verify* that the *same user* is completing the second step [[WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#broken logic|senario]]
- [ ] some checks are in *client side* ?
	- [ ] EASY way: response manipulation
	- [ ] HARD way: debug and analyse the client side code
- [ ] check *other methods of auth* (like forget password) to see if they bypass 2fa 
- [ ] use `null` or `000000` code
- [ ] see if you can **bruteforce the code in fewer object** (e.g use list in json )
	- [ ] change the request content-type 
- [ ] Weak Security Questions ?
- [even more tests](https://kathan19.gitbook.io/howtohunt/authentication-bypass/otp_bypass)
# Access Control
## 403/401 Error | Access denied | Unauthorized

- [ ] Test For **Un-Encrypted Channel** (e.g http)
- [ ] **Default Credentials**
- [ ] try **Response Manipulation** (to bypass client side checks)
- [ ] search client side source code for credentials
- [ ] try to access page in [time machine](https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original) 
- [ ] change HTTP Verbs/Methods | **Method/Verb tempering** 
	- [ ] `GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, PATCH, INVENTED, HACK`
	- [ ] `HEAD` (-> status code=200 + Content-Length: 55 => you can access data)
	- [ ] **`TRACE`** -> to leak headers added by intermediate proxies
	- [ ] use `X-HTTP-Method-Override: [METHOD]`
- [ ] **FUZZ Paths** to find ==inconsistency== -> [[403 bypass header list#Path fuzzing test cases| Path FUZZING list]]
- [ ] change `Referer` header
- [ ] change your Location (Country | City | ...)
- [ ] test for Access control vulnerabilities in **multi-step processes**
## IDOR #improve

- types:
	- [ ] direct reference to *database* objects
	- [ ] direct reference to *static* files
	- [ ] Controllable object *changes state* of Application [senario](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)
- test:
	- [ ] Test to change the ID like parameters
	- [ ] Get ID from one endpoint use it in another one situation [Google BBP](https://caesarevan23.medium.com/google-vrp-insecure-direct-object-reference-3133-70-a0e37023a4c7)
		- [ ] check *Refresh Token Endpoint* for Misconfiguration -> can lead to account takeover
## HTTP basic authentication
- [ ] BruteForce attacks 
	- [ ] default credentials 
- [ ] Session related attacks [[WEB/vulnerabilities/CSRF/attack/METHODOLOGY|METHODOLOGY]].
- [ ] if has **HSTS** 
	- [ ] [session side jacking](https://en.wikipedia.org/w/index.php?title=Session_hijacking&action=edit&section=2)
- [ ] **Forced Browsing** (directly requesting the resource behind the authentication wall)
      ![[Pasted image 20250921210252.png]]
- [ ] **HTTP verb Tempering**



## Trusted IP|HOST whitelist

- [ ] test these checks manually [[Checklists DIR/Authentication, Authorization, Access Control#Blocking the remote user's IP address| Blocking the remote user's IP address]] 
  - [ ] not working ? => use the  [[403 bypass header list#bypass header list|bypass header FUZZING list]]
- [ ] test Host Header Injection techniques
## JWT #TODO
# SSO

- [ ] Test parameters like `redirect_uri` 
	- [ ] To ***steal token*** and potential Account takeover 
		- [ ] (e.g `attacker.com`)
		- [ ] if limited to whitelist -> Try **open redirect** 
		      (e.g `sub.site.com/logout?r=https://attacker.com/log` )
			- [ ] use CSPT : `https://site.com/oauth/callback/../../user/profile?next=https://attacker.com`
			- [ ] try url validation bypasses -> [portswigger cheatsheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
				- [ ] *Startswith/indexOf*:` target.com.attacker.com`
				- [ ] *Fake relative*: `//attacker.com`
				- [ ] *Multiline regex*:  `attacker.com%0d%0atarget.com`
				- [ ] Chinese dot → 。
		        - [ ] ////evil%E3%80%82com
		        - [ ] evil%E3%80%82com.target.com
		            - evil%E3%80%82com.target.com → provider → sub.target.com
		            - evil%E3%80%82com.target.com → browser → evil.com.target.com

			- [ ] parameter-preserving open redirect (chain of redirects)
			      - `auth.com/?redirect_uri=https://target.com/redir?u=//attacker.com/`
			      - `redirect_uri=https://example.com/callback?next=example.com/logout?next=attacker.com`
		- [ ] if SSO works by **XHR => CORS** implemented
			- [ ] bypass checker function (e.g `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`)
			- [ ] if CORS on .site.com -> XSS on subdomains 
		- [ ] if SSO works by **JSONP** and the JavaScript object is accessible **any other cross site** ->[ account takeover ](https://memoryleaks.ir/vulnerability-discovery-in-sso-authentication-scheme/)
			- [ ] [[Notes/Authentication, Authorization, Access Control#indicators|Indicators of misconfig]]
				- [ ] check for leaked credentials
				- [ ] change `Referer` headers  
- [ ] is Authorization token, short lived and one-time use ?
# OAuth

- [ ] is the **proper flow** used ? 
	- [ ] client credentials can be kept secret: 
		- [ ] yes (classic web app) -> Authorization code flow 
		- [ ] no (SPA , mobile - desktop apps, ...) -> Authorization code flow  + *PKCE*
- [ ] Check for **CSRF** protection (`state` parameter)
- [ ] Check the `redirect_url` vulns Mentioned in [[Checklists DIR/Authentication, Authorization, Access Control#SSO|SSO]] section => account takeover  
- [ ] **race condition** on ==code== OR  ==refresh_token== → access_token → dabble token → vulnerability
- [ ] if **implicit grant type** ( access token sent via users's browser = exposed in url)
	- [ ] parameter tampering on the final request which token gets send to server
- [ ] can `scope` be changed after user consent ? -> **scope upgrade**
- [ ] is client's secret protected and verified ? -> **client confusion** attack [senario](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts)
- [ ] is `prompt` parameter Manipulatable ?  -> do all the above attacks with `prompt=none` to minimize intraction
- [ ] breaking the flow with `response_mode` parameter
- [ ]  `response_mode=fragment` ([ref](https://ldapwiki.com/wiki/Wiki.jsp?page=Fragment%20Response%20Mode)) + leaking the url => account takeover [hackerone report](https://hackerone.com/reports/1567186)
	- [ ] ![[Pasted image 20250925181123.png]]
- [ ] `response_mode=form_post` OR `response_mode=web_message` + xss on authorization server -> see [CVE-2023-6927](https://securityblog.omegapoint.se/en/writeup-keycloak-cve-2023-6927/)
- [ ] post Auth redirect + login CSRF 
	- [ ] ![[Pasted image 20250925183740.png]]

# Session management #TODO




