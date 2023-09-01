## basic concepts
**at a glance**: [[Test and find#reflected XSS|finding one]] -> find out the context -> outsmart their outsmarting(evasions) -> exploit and take advantage (or make a PoC)

-> [[WEB/vulnerabilities/XSS/attack/payload#basic reflected|basic]] payload
##### PoC
showing yourself and others without further exploitation  -> alert() OR **print()**

---
# contexts 
based on [portswigger academy](https://portswigger.net/web-security/cross-site-scripting/contexts) labs 
## between HTML tags
-> introduce new html tag to trigger execution of javascript

#practitioner 
- ***reflected examples***
  - **most tags and attributes blocked** -> find accepted tags -> find accepted attributes (burp intruder): [[WEB/vulnerabilities/XSS/attack/payload#most tags and attributes blocked|payload]]
  - **all tags blocked except custom ones** -> onfocus + attribute that triggers it (like tabindex): [[WEB/vulnerabilities/XSS/attack/payload#all tags and attributes blocked except custom ones|payload]]
  - **some SVG markup allowed** -> find accepted markup using intruder [[WEB/vulnerabilities/XSS/attack/payload#some SVG markup allowed|payload]]

## in HTML tag attributes

#apprentice 
- <mark style="background: #D2B3FFA6;">close the tag</mark> -> introduce new one 
- angle brackets are blocked (or encoded) -> execute within the <mark style="background: #D2B3FFA6;">same tag</mark> using:
  - **new attribute** that creates a scriptable context (such as event handlers)(like autofocus onfocus=...) 
  - create scriptable context within the **same attribute** (href="javascript: ...")
[[WEB/vulnerabilities/XSS/attack/payload#in HTML tag attributes|payload]]
/git