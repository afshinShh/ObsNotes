
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
- `registration`
	- ==When you see encoded data in proxy it must be encoded clientside== = in DOM
	- use "*Step inner*" functionality of debugger to trace other functions  
	- [ ] `afshin+num@gmail.com` ==  `a.f.s.h.in@gamil.com` ==  `afshin@gmail.com` ?
		- [ ] same  OTP -> use to **bypass ratelimit** and account locking  => bruteforce
		- [ ] different OTPs for each variation forget password => **password spray** (keep the OTP value then change the variation)
- [ ] ``<svg/onload=eval(`'`+URL)>`` -> loads the script from url before check by the WAF  (why? :) => `https://site.com/#';alert(origin)`
- [ ] wanna ATO ?
	- [ ] token hijacking
	- [ ] change password
	- [ ] Link Account
- [ ] ==**Application to Web(A2W)**(from mobile app to web app) = GOLD==
	- [ ] **Magic(Deep) Links**  
	- [ ] `tokenAuth` route -> token to cookie convertor
		- [ ] it redirects -> it is client side redirect via JS -> js scheme 403 -> bypass with `\t`
	- [ ] use mobile view of debugger
- [ ] ==needs to be  ***Accept*** ed?== -> hDOM 
> [!abstract] Definition 
>- [ ] the url results to a request (hDOM) -> this request is **FULL AUTHORIZED** (it contains cookie,headers,or an authorized action to indicates) and by the application
>	- [ ] always ask yourself, **how** this request created and by **who**
>	- [ ] e.g: `https://www.capcut.com/approval-result?id=7375174162874286097&status=1` if you change `id` 
- [ ] Search the Sinks first -> why ? usually less in number 
	- [ ] different pages -> loading different JSs => new sources & sinks => *search again* 
	- [ ] sources + sinks != same place
#### Authneticarion transfer bug between mac app and webappz 
- [ ] **==confirmation HTTP request==**
	- [ ] one click ATO in capcut (web to mac app)![[Pasted image 20260121222821.png]]
		  ![[Pasted image 20260121225108.png]]
> in this senario capcut misused **state parameter** for uuid handling
>  first bug on the created link
>  second on the redirect_uri (it gets handled on the app side again in the state param)
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
# hiring.amazon.com
- **DONT look for a goal in Recon or application analysis at first** 
	- if you do so you will limit yourself to checklists and nothing more
- burp may not log some routes in React based webapps 
	- all the routes in this format: `site.com/#/...`
		- read the DOM 
		- refresh and stop repeatedly to log the url
		- you can use ==CPU slowdown (4x) in performance tab ==to slow down the process and see whats happening
- [ ] narrow recon tips
	- [ ] check .map files manually 
	      - (browser only finds them if it already gets mentioned in the js file you must fuzz to discover yourself too)
	      - one route may allow source maps other (at the same site) doesnt 
	- [ ] look for hidden DOM routes
	- [ ] fuzz for JS files (ex: `main.prod.js` => `main.staging.js`,`main.dev.js` ) 
	- [ ] dork for swagger and docs
	- [ ] **==Response Manipulation==** 
	- [ ] **==Click on ALL links on the site ==**
- [ ] `window.location.assign` -> dangerous sink
- [ ] PostMessage gets prioritized when you see two seperate frames talking
> [!question] how does  the application goes from step 2 to step 4 in the bellow senario ? (redirectUrl)
- ![[Pasted image 20260205132132.png]]
	- [ ] ~~hardcoded ?~~
	- [ ] ~~gets the url from previous state?~~
	- [x] uses storage (local storage, cookie) 
		- => you can change it to attacker.com => ATO
