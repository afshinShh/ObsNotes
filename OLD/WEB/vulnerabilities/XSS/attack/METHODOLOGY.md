## basic concepts
**at a glance**: [[Test and find#reflected XSS|finding one]] -> find out the context -> outsmart their outsmarting(evasions) -> exploit and take advantage (or make a PoC)

-> [[OLD/WEB/vulnerabilities/XSS/attack/Examples#basic attack|basic payload]]
##### PoC
showing yourself and others without further exploitation  -> alert() OR **print()**

---
# contexts 
based on [portswigger academy](https://portswigger.net/web-security/cross-site-scripting/contexts) labs 
## between HTML tags

-> introduce new html tag to trigger execution of javascript
- ***reflected examples***
  - **most tags and attributes blocked** -> find accepted tags -> find accepted attributes (burp intruder): / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#most tags and attributes blocked|payload]]
  - **all tags blocked except custom ones** -> onfocus + attribute that triggers it (like tabindex): / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#all tags and attributes blocked except custom ones|payload]]
  - **some SVG markup allowed** -> find accepted markup using intruder / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#some SVG markup allowed|payload]]

## in HTML tag attributes

- <mark style="background: #D2B3FFA6;">close the tag</mark> -> introduce new one 
- angle brackets are blocked (or encoded) -> execute within the <mark style="background: #D2B3FFA6;">same tag</mark> using:
  - **new attribute** that creates a scriptable context (such as event handlers)(like _autofocus onfocus_=...) 
  - create scriptable context within the **same attribute**
    - href="_javascript:_ ..."
    -  hidden input -> don't usually fire events automatically -> [canonical link](https://ahrefs.com/blog/canonical-tags/) tag -> [accesskey](https://portswigger.net/research/xss-in-hidden-input-fields) attribute

[[OLD/WEB/vulnerabilities/XSS/attack/Examples#in HTML tag attributes|payloads]]
## XSS into JavaScript

- <mark style="background: #BBFABBA6;">context: into a JavaScript string</mark>
	- **Terminating the existing script** -> close script tag -> introduce new HTML tag / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#Terminating the existing script|payload]]
	- **Breaking out of a JavaScript string** -> repair -> a code without error / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#Breaking out of a JavaScript string|payload]]
	  - single quote escaped with backslash -> escape backslash with another backslash 
- <mark style="background: #BBFABBA6;">context:within a quoted tag attribute & into a JavaScript string</mark> (like event handlers) -> **Making use of HTML-encoding** [[OLD/WEB/vulnerabilities/XSS/attack/Examples#Making use of HTML-encoding|payload]]
- <mark style="background: #BBFABBA6;">context:in JavaScript template literals</mark> -> use `${...}` / [[OLD/WEB/vulnerabilities/XSS/attack/Examples#XSS in JavaScript template literals|payload]]
  
## XSS via client-side template injection

#todo 
...
## XSS in WebWorker 
when the web worker handles token refresh functionality dynamicaly 
- [the original article -> Why avoiding LocalStorage for tokens is the wrong solution](https://pragmaticwebsecurity.com/articles/oauthoidc/localstorage-xss.html) 

```javascript
// Keep a reference to the original MessageChannel
window.MyMessageChannel = MessageChannel;

// Redefine the global MessageChannel
MessageChannel = function() {
    // Create a legitimate channel
    let wrappedChannel = new MyMessageChannel();

    // Redefine what ports mean
    let wrapper = {
        port1: {
            myOnMessage: null,
            postMessage: function(msg, list) {
                wrappedChannel.port1.postMessage(msg, list);
            },
            set onmessage (val) {
                // Defining a setter for "onmessage" so we can intercept messages
                this.myOnMessage = val;
            }
        },
        port2: wrappedChannel.port2
    }
    
    // Add handlers to legitimate channel
    wrappedChannel.port1.onmessage = function(e) {
        // Stealthy code would not log, but send to a remote server
        console.log(`Intercepting message from port 1 (${e.data})`)
        console.log(e.data);
        wrapper.port1.myOnMessage(e);
    }

    // Return the redefined channel
    return wrapper;
}
```

---
# exploits

## to steal cookies

- The victim might not be logged in.
- applications hide cookie `HttpOnly` using flag.
- additional factors (like IP address).
- session might time out
[[OLD/WEB/vulnerabilities/XSS/attack/Examples#to steal cookies|payload]]
## to capture passwords

- only works when user uses password auto-fill (password managers)
[[OLD/WEB/vulnerabilities/XSS/attack/Examples#to capture passwords|payload]]

## to perform CSRF

**anything the user can do we can probably do that too with XSS**

- CSRF alone: can be patched using anti-CSRF tokens -> +XSS: no one can stop us
[[OLD/WEB/vulnerabilities/XSS/attack/Examples#to perform CSRF|payload]]

---

[Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) #todo
[CSP(content-security-policy)](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) #todo


