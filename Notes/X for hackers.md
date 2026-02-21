# Regex for hackers

## OSINT (default: github)
### Asset Discovery
- [ ] Netflix domains on different TLDs
```
/https?:\/\/[a-z0-9\.-]+\.netflix.[a-z]+\//
```
- [ ] subdomains containing api
```
/https?:\/\/([a-z0-9-]{1,}[\.])*api\.([a-z0-9-]{1,}[\.])*netflix\.[a-z\.]+\//
```
### content discovery
- [ ] URLs containing `*/api/*`
```
/https?:\/\/[a-z0-9\.-]+\.netflix.[a-z]+\/([a-z0-9-_]+\/)*api\//
```
- [ ] URLs containing `*/v*/*`
```
/https?:\/\/[a-z0-9\.-]+\.netflix.[a-z]+\/([a-z0-9-_]+\/)*v[0-9]+\//
```
- [ ] URLs containing /actuator/
```
/https?:\/\/[a-z0-9\.-]{3,}\/([a-z0-9-_]+\/)*actuator\//
```
- ![[Pasted image 20260111211857.png]]
- -> actuator heap dump ![[Pasted image 20260111211932.png]]
- ![[Pasted image 20260111212032.png]]
- ![[Pasted image 20260111212116.png]]
### Saved Secrets
- [ ] JWT token + netflix
```
/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+/ and /netflix\.[a-z]+/
```
- [ ] basic Auth
```
[A-Za-z0-9+/]{20,}={0,2}
```
## Code Review
### Finding reflected values for XSS
- PHP
```php
echo\s*\$_(GET|POST)\[
```
```php
<\?=\s*\$_(GET|POST)\[
```
### **Finding regex’s that could be insecure**
- checks for usage of regex in JS, python or php code 
```
(/[^/\n]+/[gimsuy]*)|(re\.(search|match|compile)|preg_match|new RegExp)\s*\(\s*["'`].+?["'`]
```
### Finding RCE :) (github)
```php
/system\(\s*('|")[^'"]*\$_(GET|POST|REQUEST|SERVER)\[/ path:.php
```
## public routes 
- Python - Flask
```python
\.route\(\s*('|")([^'"]{1,})('|")\)
```
![[Pasted image 20260111213030.png]]
- Python - Django
```python
path\(\s*('|")([^'"]{1,})('|")
```
![[Pasted image 20260111213227.png]]
- PHP - Laravel
```php
Route::([a-z]{1,})\((\s*('|")([^'"]{1,})('|"))
```
![[Pasted image 20260111213113.png]]
- JavaScript - Express JS
```js
\.(get|post|put|delete|patch)\(\s*('|")([^'"]{1,})('|\")
```
![[Pasted image 20260111213145.png]]
- ASP.NET
```c#
\.Map(Get|Post|Put|Patch|Delete)\(\s*('|")([^'"]{1,})('|")
```
![[Pasted image 20260111213304.png]]
- Ruby On Rails
```ruby
get\s+('|")([^'"]{1,})('|")
```
![[Pasted image 20260111213332.png]]
- GO! HTTP
```go
\.(HandleFunc|Handle)\(\s*('|")([^'"]{1,})('|")
```
![[Pasted image 20260111213402.png]]
## Git Scraper (PHP code)
### Parameters 
```php
\$_(GET|POST)\[\s*('|")([^'"]{1,})('|")\]
```
### HTTP Headers
```php
\$_(SERVER)\[\s*('|")([^'"]{1,})('|")\]
```
### Method Names
```php
function\s*([a-zA-Z_]\w+)\(
```

# JS for bug hunter
## Intro
- Write Fuzzer to understand the limits of language and middle mans 
  > [!example] bypass WAF using tagged templates 
```js
function sneakyCall(fn) { fn``; }
sneakyCall(() => console.log("Sneaky!")); // Sneaky!
```
  > [!example] fuzzing valid whitespace for variable definition 
```js
for (let i = 0; i<=0x10ffff; i++) {
let char = String.fromCharCode(i);
try {
eval(`let${char}x=1;`);
console.log(`Character ${i} (${char}) is valid whitespace!`);
} catch (e) {}
} //

``` 
## Chapter 1: The basics 
> [!note] a is equal to 61 in hex and 141 in octal
```js
// variable "a" = value "a"
// hexadecimal
a = '\x61'
a = "\x61"
a = `\x61`
//unicode
a = '\u0061'
a = "\u0061"
a = `\u0061`
a = '\u{61}'
a = "\u{000000000061}"
a = `\u{0061}`
//octal
a = '\141'
a = "\8" //outside of octal scope therefore 8 is returned

function a(){}
\u{61}() // correctly calls the function
```
### `eval` function first decodes then executes
```js
// variable "a" = value of 123
eval('\x61=123')
// variable "a" = value of 124
eval('\\u0061=124')
// variable "a" = value of 125
eval('\\u\x30061=125')
// variable "a" = value of 126
eval('\\u\x300\661=126') // \x30=0  | \66=0 --> \u61=a
// a = "secret"
eval('\\u\x300\x306\x31= "secret"'); 
```
### String behavior
```js
backspace = '\b' // "hello\bworld" === hellworld
form_feed = '\f'
new_line = '\n'
carriage_return = '\r' // moves the pointer to the first of the next line
tab = '\t'
vertical_tab = '\v'
null = '\0'
single_quote = '\''
double_quote = '\"'
backslash = '\\'
HELLO = '\H\E\L\L\O'

//line continuation
Hel_nexline_lo = 'Hel\

lo'
x = `a\

b\

c`;
x==='abc' // true

x = `a

b

c`;
x !=='abc' // false --> x = a \n b \n c

console.log(`${7*7}`) //49
console.log(`${`${`${`${7*7}`}`}`}`) //49

  
// you can call the functions using backticks
alert`1337`
// returns x function recursively
function x(){return x}
x```````````` // this comment is for keeping the cool (DONT REMOVE)
```
>[!example] reversing string using tagged template
```js
function reverse(strings, ...values) {
return strings[0].split('').reverse().join('');
}
console.log(reverse`hello`); // olleh
```
### Call and Apply
- `call` is part of `Function.prototype` and lets you to bind `this` explicitly
```js
function x(){console.log(this.bar);}
let foo = {bar:'baz'}
x.call(foo);

// If you don’t supply a “this” value to the call function it will use the window object if not in strict mode   

function x(){
// if you uncomment the line bellow, the value of "this" would be equal to null 
// "use strict";
console.log(arguments[0]);
console.log(arguments[1]);
console.log(this);
}
x.call(null,0,1);
```
- `apply` is just like `call` but you can supply an _array of arguments in the second argument_:
```js
function x() {
console.log(arguments[0]);//1
console.log(arguments[1]);//2
console.log(this);//[object Window]
}
x.apply(null, [1, 2])


let nums = [4, 2, 8, 1];
console.log(Math.min.apply(null, nums)); // 1
```
## Chapter 1.5 - Extra 
### proxy object
- proxy stays in the middle of calling the specified `target` and executes its `handlers` before
 ```js
 let obj = new Proxy({}, {
get: (target, prop) => {
console.log(`Accessing ${prop}`);
return target[prop] || "Not found";
}
});
obj.test; // Accessing test
 ```
- you can change the attributes or behavior of that specified target or even restrict any access to it 
```js
let secureObj = new Proxy({
secret: "hidden"
}, {
get: (target, prop) => {
if (prop === "secret") {
throw new Error("Access Denied!");
}
return target[prop];
}
});
console.log(secureObj.secret);
// Error: Access Denied!
console.log(secureObj.other);
// undefined
```
- you can even create unexpected behaviors when the specified target gets called 
```js
let fakeWindow = new Proxy(window, {
get: (target, prop) => {
if (prop === "location") {
return { href: "https://fake.com" };}
return target[prop];}});
console.log(fakeWindow.location.href); // https://fake.com
console.log(window.location.href); // The actual page address
```
### debug with **Source Maps**
- when the initial code gets minified (or transpiled in typescript cases) with some tools like Webpack, Babel or Rollup, the source map shows the browser how to map each part of the minified code to its original counterpart.
- when you unmap the code in DevTools of the browser, the errors get more clear and verbose. 
```js
// Assume you have minified code
// A separate source map is generated (for example, with Webpack)
console.log("Check browser dev tools with source maps enabled");
// Webpack configuration
module.exports = {
devtool: 'source-map', // Generates the .map file
// Other settings...
};
```
### WeakMap
- structure like `Map` but 
	- its keys must always be **object**
	- if doesn't get referenced in the code, `garbage collector` can delete its keys and values from the memory => suitable for huge projects  
	- => prevents **memory leak** 
	- supports only few basic methods: 
		- has
		- get
		- set
		- delete 

```js
et wm = new WeakMap();
let obj = {};
wm.set(obj, "data");
console.log(wm.get(obj)); // data
obj = null
```
- best choice for storing temp DOM data without leaking and the memory gets freed by GC 
```js
let wm = new WeakMap();
let element = document.querySelector('#myElement');
wm.set(element, { clicks: 0 });
element.addEventListener('click', () => {
let data = wm.get(element);
data.clicks++;
console.log(`هاکلیک: ${data.clicks}`);
});
element = null;
```
### testing browser's behavior
- different JS engine => different implementation of ECMAScript
	- `V8` in Chrome
	- `SpiderMonkey` in Firefox
```js
// Output: "object" (in all browsers) - unexpected right?
console.log(typeof null);

// Output: "[object Null]" - Old browsers have differernt behaviors
console.log(Object.prototype.toString.call(null)); 

// old browsers like Internet Explorer dont support
try {
console.log(BigInt(123)); // Output: 123n
} catch (error) {
console.log("BigInt is not supported!");
}
```
### Fuzzing automation (with Puppeteer)
> [!example] injects XSS payload and checks for reflection:
```js
const puppeteer = require('puppeteer');
(async () => {
const browser = await puppeteer.launch();
const page = await browser.newPage();
await page.goto('http://example.com/form');
await page.type('#input', '<script>alert("XSS!")</script>');
await page.click('#submit');
const content = await page.content();
console.log(content.includes('alert("XSS!")')); // Check for XSS
await browser.close();
})();
```
## Chapter 2: JavaScript without parentheses
### Calling functions without parentheses
```js
let obj;
obj = {valueOf(){return 1}};
obj+1 //2

obj = {valueOf:alert};
obj +1 //illegal invocation

window.valueOf=alert;window+1 // calls alert()
valueOf=alert;window+1//calls alert
toString=alert;window+""//calls alert
```