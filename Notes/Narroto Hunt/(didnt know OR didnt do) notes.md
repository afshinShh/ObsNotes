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
- FUZZ for *JS scheme*
	- javascript{FUZZ} also java{FUZZ}script 
		- (%0a, %0d,%09) (you must know)
	- {FUZZ}javascript ...
-  /gitcomm 