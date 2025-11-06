** Table of Contents **

- [A relevant action](#A%20relevant%20action)
- [Cookie-based session handling](#Cookie-based%20session%20handling)
- [No unpredictable request parameters](#No%20unpredictable%20request%20parameters)
- [CERF-token](#CERF-token)
	- [Criteria](#Criteria)
	- [How should CSRF-tokens be generated?](#How%20should%20CSRF-tokens%20be%20generated?)
	- [How should CSRF-tokens be transmitted?](#How%20should%20CSRF-tokens%20be%20transmitted?)
			- [hidden field of an HTML form that is submitted using the POST method](#hidden%20field%20of%20an%20HTML%20form%20that%20is%20submitted%20using%20the%20POST%20method)
			- [URL query string](#URL%20query%20string)
			- [costume request header](#costume%20request%20header)
	- [How should CSRF tokens be validated?](#How%20should%20CSRF%20tokens%20be%20validated?)
- [Strict SameSite cookies](#Strict%20SameSite%20cookies)
	- [concepts](#concepts)
		- [What's the difference between a site and an origin?](#What's%20the%20difference%20between%20a%20site%20and%20an%20origin?)
- [checking referer header](#checking%20referer%20header)
- [Be aware of cross-origin, same-site attacks](#Be%20aware%20of%20cross-origin,%20same-site%20attacks)

# cause
## A relevant action

There is an action within the application that the attacker has a reason to induce. This might be a <mark style="background: #FF5582A6;">privileged action</mark> (such as modifying permissions for other users) or any action on <mark style="background: #FF5582A6;">user-specific data</mark> (such as changing the user's own password).

## Cookie-based session handling

Performing the action involves issuing one or more HTTP requests, and the application <mark style="background: #FFB86CA6;">relies solely on session cookies to identify the user who has made the requests.</mark> There is no other mechanism in place for tracking sessions or validating user requests.

## No unpredictable request parameters

For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password.

# vulnerable example
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded 
Content-Length: 30 Cookie: 
session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE 

email=wiener@normal-user.com
```

This meets the conditions required for CSRF:

- The action of changing the email address on a user's account.
  
- The application uses a session cookie to identify which user issued the request. There are no other tokens or mechanisms in place to track user sessions.
  
- The attacker can easily determine the values of the request parameters that are needed to perform the action

you can exploit it using :
[[OLD/WEB/vulnerabilities/CSRF/attack/Examples#basic| basic payload]]


# defense

## CERF-token

### Criteria

1) Unpredictable with high <mark style="background: #FFF3A3A6;">entropy</mark>, as for session tokens in general.
2) <mark style="background: #FFF3A3A6;">Tied</mark> to the user's session.
3) <mark style="background: #FFF3A3A6;"> Strictly validated </mark>in every case before the relevant action is executed.
---
### How should CSRF-tokens be generated?

1) You should use a <mark style="background: #BBFABBA6;">cryptographically secure pseudo-random number generator (CSPRNG)</mark>, <mark style="background: #BBFABBA6;">seeded with the timestamp</mark> when it was created <mark style="background: #BBFABBA6;">plus a static secret. </mark>
2) you can generate individual tokens by concatenating its output with some user-specific entropy and take a strong hash of the whole structure.
---
### How should CSRF-tokens be transmitted?

##### hidden field of an HTML form that is submitted using the POST method 

``` html
< input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz" />
```
 + should be placed as early as possible (ideally before any non-hidden input field)
  
##### URL query string

is somewhat <mark style="background: #D2B3FFA6;">less safe</mark> because the query string:
1) Is logged in various locations on the client and server side;
2) Is liable to be transmitted to third parties within the HTTP Referrer header
3) can be displayed on-screen within the user's browser.

##### costume request header
+ further defense against an attacker who manages to predict or capture another user's token, because browsers do not normally allow custom headers to be sent cross-domain
+ limits the application to making CSRF-protected requests using XHR (as opposed to HTML forms) and might be deemed over-complicated for many situations
+ CSRF tokens should not be transmitted within cookies


---
### How should CSRF tokens be validated?

- server-side 
- matches the value that was stored in the user's session
- regardless of HTTP method & content type of the request
- if there is no token the request should be rejected

---
## Strict SameSite cookies

explicitly setting <mark style="background: #ADCCFFA6;">your own SameSite restrictions</mark> with each cookie you issue => you can control exactly which contexts the cookie will be used in, regardless of the browser
ideally, you should use the `Strict` policy by default, then lower this to `Lax` only if you have a good reason to do so.
### concepts

![[Pasted image 20230905141119.png]]
![[Pasted image 20230905141141.png]]

#### What's the difference between a site and an origin? 

| **Request from**          | **Request to**                 | **Same-site?**        | **Same-origin?**           |
| ------------------------- | ------------------------------ | --------------------- | -------------------------- |
| `https://example.com`     | `https://example.com`          | Yes                   | Yes                        |
| `https://app.example.com` | `https://intranet.example.com` | Yes                   | No: mismatched domain name |
| `https://example.com`     | `https://example.com:8080`     | Yes                   | No: mismatched port        |
| `https://example.com`     | `https://example.co.uk`        | No: mismatched eTLD   | No: mismatched domain name |
| `https://example.com`     | `http://example.com`           | No: mismatched scheme | No: mismatched scheme      |

- top-level domain (TLD) -> `.com` or `.net`
- "effective top-level domain" (eTLD) -> `.co.uk`
- SameSite restriction levels: -> `Set-Cookie:` `SameSite=?`
  - [`Strict`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#strict) -> does not match the site currently shown in the browser's address bar, it will not include the cookie
  - [`Lax`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#lax) -> default for Chrome -> OK if:  1)`GET` method 2)top-level navigation(such as clicking on a link).
  - [`None`](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#none) ->  disables SameSite -> cookie is intended to be used from a third-party context -> + `Secure`
---
## checking referer header
---
## Be aware of cross-origin, same-site attacks

isolating insecure content 
- user-upload files on a separate site from any sensitive functionality or data
- sibling domains

/git