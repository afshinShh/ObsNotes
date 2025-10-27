# basic attack
#apprentice 
#### reflected
`https://insecure-website.com/search?term=gift` -> `<p>You searched for: gift</p>`
#### stored
```http
POST /post/comment HTTP/1.1 
Host: vulnerable-website.com 
Content-Length: 100 
postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```
 -> `<p>This post was extremely helpful.</p>` (visible to all of people seeing the comment)
#### DOM-based 
 > => `document.write('... <script>alert(document.domain)</script> ...');`  
 
# DOM sinks:

<mark style="background: #D2B3FFA6;">main</mark> sinks:
```js
document.write()
document.writeln() 
document.domain 
element.innerHTML
element.outerHTML element.insertAdjacentHTML element.onevent
```

<mark style="background: #D2B3FFA6;">jQuery</mark> sinks :

``` js
add()
after()
append() 
animate() 
insertAfter() 
insertBefore()
before()
html() 
prepend() 
replaceAll() 
replaceWith() 
wrap() 
wrapInner()
wrapAll() 
has() 
constructor() 
init() 
index() 
jQuery.parseHTML() 
$.parseHTML()
```
