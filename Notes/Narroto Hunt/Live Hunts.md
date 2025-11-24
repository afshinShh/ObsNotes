
# CapCut
test your payloads in JSfiddle
- use `target="_blank"`
- You must be able to create Test cases dynamically
- `?next= `
	- use collaborator to see the exact changes 
	- [ ] server-side request forgery
	- [ ] host header poisoning (created link gets dynamically created )
		- [ ] Start with ==changing the port== determine the reflection 
		      (=> victim gets emailed with specified **_host+port_**) 
		- [ ] x-... headers
		- [ ] same HOST header different **SNI** 
	- [ ] link poisoning
		- [ ] **URL from input parameter**
			- [ ] default behaviour
			- [ ] ==find-able in DOM==
			- [ ] ==fully hidden parameter==
			- [ ] ==header==, example: referer
	- [ ] Path manipulation 
	- [ ] parameter manipulation 
		- [ ] double `code` parameter (in this senario we could inject parameter after `next`)
- `edit profile`
	- [ ] other users profile
	- [ ] Mass Assignment 
 >  	update profile (only updates "about") from json data of profile and 
		 **==HOOK==** again (you can find from DOM) => least change
			name -> SSTI + DOM XSS (in comment section)
			 backgound_url -> ssrf test 
- URL checker function manipulation
	- .com.attacker.com
	- .com@attacker.com
	- .computer
# superbet.ro (small scope)
- [ ] user lock in in bruteforce ?
- [ ] no registration ? -> internal ?
	- [ ] *leaked credentials* -> bug after login
	- [ ] hidden registration (parameter | route) ?
		- [ ] fuzz
		- [ ] *DOM*
			- **Get the clues in DOM for everything**
- [ ] divide the routes into authneticated - unauthenticated
	- if you can bypass one authenticated you can bypass them all
- [ ] ?filter=[{}:{}] -> filters data + applies your input + 500 => SUS 
	- [ ] nosql ? -> default
		- [ ] error -> "1":"1" -> version() => MySQL injection ONLY on some routes
- *don't fuzz on SAPs unless you see some signs*
- if SAP + RestAPI -> 2 different domains => token based auth
- if HTTP status redirected => CRLF injection 
/git