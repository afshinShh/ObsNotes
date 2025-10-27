## basic concepts
**at a glance**: [[Test and find#reflected XSS|finding one]] -> find out the context -> outsmart their outsmarting(evasions) -> exploit and take advantage (or make a PoC)

-> [[Notes/XSS/attack/payload#basic attack|basic payload]]
##### PoC
showing yourself and others without further exploitation  -> alert() OR **print()**

---
# contexts 
based on [portswigger academy](https://portswigger.net/web-security/cross-site-scripting/contexts) labs 
## between HTML tags

-> introduce new html tag to trigger execution of javascript
- ***reflected examples***
  - **most tags and attributes blocked** -> find accepted tags -> find accepted attributes (burp intruder): / [[Notes/XSS/attack/payload#most tags and attributes blocked|payload]]
  - **all tags blocked except custom ones** -> onfocus + attribute that triggers it (like tabindex): / [[Notes/XSS/attack/payload#all tags and attributes blocked except custom ones|payload]]
  - **some SVG markup allowed** -> find accepted markup using intruder / [[Notes/XSS/attack/payload#some SVG markup allowed|payload]]

## in HTML tag attributes

- <mark style="background: #D2B3FFA6;">close the tag</mark> -> introduce new one 
- angle brackets are blocked (or encoded) -> execute within the <mark style="background: #D2B3FFA6;">same tag</mark> using:
  - **new attribute** that creates a scriptable context (such as event handlers)(like _autofocus onfocus_=...) 
  - create scriptable context within the **same attribute**
    - href="_javascript:_ ..."
    -  hidden input -> don't usually fire events automatically -> [canonical link](https://ahrefs.com/blog/canonical-tags/) tag -> [accesskey](https://portswigger.net/research/xss-in-hidden-input-fields) attribute

[[Notes/XSS/attack/payload#in HTML tag attributes|payloads]]
## XSS into JavaScript

- <mark style="background: #BBFABBA6;">context: into a JavaScript string</mark>
	- **Terminating the existing script** -> close script tag -> introduce new HTML tag / [[Notes/XSS/attack/payload#Terminating the existing script|payload]]
	- **Breaking out of a JavaScript string** -> repair -> a code without error / [[Notes/XSS/attack/payload#Breaking out of a JavaScript string|payload]]
	  - single quote escaped with backslash -> escape backslash with another backslash 
- <mark style="background: #BBFABBA6;">context:within a quoted tag attribute & into a JavaScript string</mark> (like event handlers) -> **Making use of HTML-encoding** [[Notes/XSS/attack/payload#Making use of HTML-encoding|payload]]
- <mark style="background: #BBFABBA6;">context:in JavaScript template literals</mark> -> use `${...}` / [[Notes/XSS/attack/payload#XSS in JavaScript template literals|payload]]
  
## XSS via client-side template injection

#todo 
...

---
# exploits

## to steal cookies

- The victim might not be logged in.
- applications hide cookie `HttpOnly` using flag.
- additional factors (like IP address).
- session might time out
[[Notes/XSS/attack/payload#to steal cookies|payload]]
## to capture passwords

- only works when user uses password auto-fill (password managers)
[[Notes/XSS/attack/payload#to capture passwords|payload]]

## to perform CSRF

**anything the user can do we can probably do that too with XSS**

- CSRF alone: can be patched using anti-CSRF tokens -> +XSS: no one can stop us
[[Notes/XSS/attack/payload#to perform CSRF|payload]]

---

[Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) #todo
[CSP(content-security-policy)](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) #todo
