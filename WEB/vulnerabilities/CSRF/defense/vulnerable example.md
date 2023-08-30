

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
[[WEB/vulnerabilities/CSRF/payload#basic| basic payload]]