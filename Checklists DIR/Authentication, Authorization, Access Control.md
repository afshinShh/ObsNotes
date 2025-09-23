# general 
### behavior inconsistency
 - difference in:
	  - [ ] *Status codes*
	  - [ ] *Error messages
	  - [ ] *Response times*
## Brute Force protection
#### Blocking the remote user's IP address
  - [ ] <mark style="background: #ADCCFFA6;">include your own login credentials</mark> at regular intervals throughout the wordlist. [[WEB/vulnerabilities/Authentication vulnerabilities/payload#IP block|example]] 
#### User rate limiting
## Registration

- [ ] Test password quality rules
- [ ] Test username uniqueness
### Bypassing any information

## Login

- [ ] Test for username enumeration
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
	- [ ] Bypass Bruteforce limitations
	- [ ] Bypass Ratelimit  

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


# Access Control
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
