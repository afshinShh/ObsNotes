# reflected XSS

#apprentice 
## how to test?
- ##### test every entry point 
  - parameters or other data within the URL query string and message body
  - the URL file path.
  - HTTP headers.
- ##### Submit random alphanumeric values
  should be designed to survive most input validation -> A <mark style="background: #ADCCFFA6;">random alphanumeric value of around 8 characters</mark> is normally ideal. You can use Burp [Intruder's number payloads](https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types#numbers).
- ##### Determine the reflection context
   - text between HTML tags
   - within a tag attribute which might be quoted
   - within a JavaScript string
   - ...
- ##### Test a candidate payload
  [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater) -> An efficient way to work is to leave the original random value in the request and <mark style="background: #ADCCFFA6;">place the candidate XSS payload before or after it</mark> -> search term in Burp Repeater's response view
- #####  Test alternative payloads.
   -> modified by the application, or blocked altogether -> change the context
- #####  Test the attack in a browser
   payload works within Burp Repeater -> transfer the attack to a real browser (by pasting the URL into the address bar or [Burp Proxy's intercept view](https://portswigger.net/burp/documentation/desktop/tools/proxy/intercept-messages)) -> execute something like `print(document.domain)`.