# Same-origin policy (SOP)
- The same-origin policy restricts scripts on one origin from accessing data from another origin![[Pasted image 20251106175839.png]]
### solutions to remove the restriction
***postMessage*** → Sending and receiving messages between two different origins
***JSONP*** → Using the `<script>` tag to transfer JavaScript objects
***Cross Origin Resource Sharing*** → Modifying SOP by some special response headers
- Let’s review CORS headers:
	>`Access-Control-Allow-Origin: <Origin> | *`  
	- → which means that the resource can be accessed by `<origin>`
	>`Access-Control-Allow-Credentials: true` 
	- -> indicates response can be exposed or not when HTTP request has Cookies
- The browsers always put the ==correct origin== in the request by Origin HTTP header, it cannot be spoofed or modified by JavaScript
# Cross Origin HTTP Requests
- Browsers only permit to send **simple HTTP requests** on behalf of users -> else: first *Preflight HTTP request*
### Simple HTTP Request
allowed request methods:
- **`GET`** / **`POST`** / **`HEAD`**
allowed content types:
- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`
Some headers (Original headers cannot be changed, [more info](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name))
> example
```js
const xhr = new XMLHttpRequest();
const url = 'https://site.tld/resources/data/';
xhr.open('GET', url); xhr.onreadystatechange = handlerFunction; xhr.send();
```
### Preflight HTTP Request
an ***OPTION*** HTTP request will be sent which is called Preflight
- If response headers permit the HTTP method and headers, the HTTP request will be sent
> example
```js
const invocation = new XMLHttpRequest();
const url = 'http://domain.tld/resources/api/me/data/'; 
function callOtherDomain() { 
	if (invocation) { 
		invocation.open('GET', url, true); 
		invocation.withCredentials = true; 
		invocation.setRequestHeader('Content-Type', 'application/json');
		invocation.onreadystatechange = handlerFunction; invocation.send(); } }
```
> response must contain:
> `Access-Control-Allow-Origin: https://memoryleaks.ir`
> `Access-Control-Allow-Credentials: true `
> `Access-Control-Allow-Headers: Content-Type`
![[Pasted image 20251106181744.png]]
/gitcomm