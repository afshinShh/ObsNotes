# common session specific attacks

## Session Hijacking

- In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to **obtain them**, and uses them to authenticate to the server and **impersonate** the victim.

An attacker can obtain a victim's session identifier using several methods, with the most common being:

- Browser history or log-diving
- Passive Traffic Sniffing
- ==Cross-Site Scripting (XSS)==
- Read access to a database containing session information

 if a session identifier's security level is low, an attacker may also be able to brute force it or even predict it.
### Remediating Session Hijacking

It is pretty challenging to counter session hijacking since a valid session identifier grants access to an application by design. User session monitoring/anomaly detection solutions can detect session hijacking. It is a safer bet to counter session hijacking by trying to eliminate all vulnerabilities covered in this module
## Session Fixation

-  occurs when an attacker **can fixate a (valid) session identifier**. As you can imagine, the attacker will then ==have to trick the victim into logging into the application== using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).
- Such bugs usually occur when session identifiers (such as cookies) are being accepted from _URL Query Strings_ or _Post Data_ (more on that in a bit).

### stages (common flow)

1. **Stage 1: Attacker manages to obtain a valid session identifier**

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.
> [!Note] An attacker can also obtain a valid session identifier by creating an account on the targeted application (if this is a possibility).

2. **Stage 2: Attacker manages to fixate a valid session identifier**

- The above is expected behavior, but it can turn into a session fixation vulnerability if:
	- The assigned session identifier ==pre-login remains the same post-login== ***`and`***
	- Session identifiers (such as cookies) are being accepted from ==_URL Query Strings_ or _Post Data_ ==and propagated to the application

> [!example] for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

3. **Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier**

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

The attacker can then proceed to a session hijacking attack since the session identifier is already known.
> [!danger] an example of vulnerable code snippet  
```php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

### Obtaining Session Identifiers Post-Exploitation (Web Server Access)
#### PHP
- ![[Pasted image 20260306191104.png]]
	- In our default configuration case it's `/var/lib/php/sessions`. Now, please note a victim has to be authenticated for us to view their session identifier. The files an attacker will search for use the name convention `sess_<sessionID>`.
	- ![[Pasted image 20260306191225.png]]
	- for a hacker to hijack the user session related to the session identifier above, a new cookie must be created in the web browser
#### Java
> [!qoute] According to the Apache Software Foundation:
 "The `Manager` element represents the _session manager_ that is used to create and maintain HTTP sessions of a web application.

Tomcat provides two standard implementations of `Manager`. The default implementation stores active sessions, while the optional one stores active sessions that have been swapped out (in addition to saving sessions across a server restart) in a storage location that is selected via the use of an appropriate `Store` nested element. The filename of the default session data file is `SESSIONS.ser`."
#### .NET
Session data can be found in:
- The application worker process (==aspnet_wp.exe==) - This is the case in the _InProc Session mode_
- ==StateServer== (A Windows Service residing on IIS or a separate server) - This is the case in the _OutProc Session mode_
- An ==SQL Server==
Please refer to the following resource for more in-depth details: [Introduction To ASP.NET Sessions](https://www.c-sharpcorner.com/UploadFile/225740/introduction-of-session-in-Asp-Net/)
### Remediating Session Fixation

Ideally, session fixation can be remediated by generating a new session identifier upon an authenticated operation. Simply invalidating any pre-login session identifier and generating a new one post-login should be enough.

#### PHP

```php
session_regenerate_id(bool $delete_old_session = false): bool
```

The above updates the current session identifier with a newly generated one. The current session information is kept. Please refer to the following resource for more in-depth details: [session_regenerate_id](https://www.php.net/manual/en/function.session-regenerate-id.php)
#### Java

```java
...
session.invalidate();
session = request.getSession(true);
...
```

The above invalidates the current session and gets a new session from the request object.

Please refer to the following resource for more in-depth details: [Using Sessions](https://docs.oracle.com/cd/E19146-01/819-2634/6n4tl5kmm/index.html)
#### .NET

```c#
...
Session.Abandon();
...
```

For session invalidation purposes, the .NET framework utilizes _Session.Abandon()_, but there is a caveat. Session.Abandon() is not sufficient for this task. Microsoft states that "When you abandon a session, the session ID cookie is not removed from the browser of the user. Therefore, as soon as the session has been abandoned, any new requests to the same application will use the same session ID but will have a new session state instance." So, to address session fixation holistically, one needs to utilize _Session.Abandon()_ and overwrite the cookie header or implement more complex cookie-based session management by enriching the information held within and cookie and performing server-side checks.

---
## other related vulnerablities (can be chained to achieve session layer attack)

- `XSS (Cross-Site Scripting)` <-- With a focus on user sessions
- [[Client Side#CSRF|CSRF (Cross-Site Request Forgery)]]: 
	-  This attack is usually mounted with the help of attacker-crafted web pages that the victim must visit or interact with. These web pages contain malicious requests that essentially inherit the identity and privileges of the victim to perform an undesired function on the victim's behalf.
- [[Notes/Request Manipulation#Open Redirect|Open Redirects ]] <-- With a focus on user sessions: 
	- An Open Redirect vulnerability occurs when an attacker can redirect a victim to an attacker-controlled site by abusing a legitimate application's redirection functionality. In such cases, all the attacker has to do is specify a website under their control in a redirection URL of a legitimate website and pass this URL to the victim.
## Cross-Site WebSocket Hijacking (CSWSH)

- The impact is similar to a `Cross-Site Request Forgery (CSRF)` attack, but more powerful since it’s two-way: the malicious site can also read the responses to malicious requests. Normally a CSRF attack can’t read the server’s responses – unless the targeted server supports `Cross-Origin Resource Sharing (CORS)` requests
#### conditions 
1) The app uses ==cookie-based authentication==  
2) The authentication cookie is set to ==SameSite=None==  
3) The WebSocket server ==does not validate the Origin== of the Websocket handshake request (and does not use another means to validate the source of requests, such as authenticating in the first WebSocket message).

This seems like a lot of things that have to line up, but CSWSH has been more common than I expected. If I had to speculate:  
1) Cookies are still fairly popular compared to token auth.  
2) Authentication services often operate across different origins forcing session cookies to use SameSite=None and to rely on CSRF tokens as the main mechanism to defeat CSRF, which aren’t applied to WebSocket handshakes.  
3) The ws library for Nodejs and for other common webapp frameworks don’t enforce validating the Origin.
### Total Cookie Protection
- Over the past several years Firefox has been locking down their [“Enhanced Tracking Protection” feature](https://chromestatus.com/feature/5088147346030592).
- Total Cookie Protection works by isolating cookies to the site in which they are created. Essentially <mark style="background: #ADCCFFA6;">each site has its own cookie storage partition</mark> to prevent third parties linking a user’s browsing history together. This is designed to prevent a tracker.com script loaded on site A to set a cookie which can be read by a tracker.com script loaded on site B. ==><mark style="background: #ADCCFFA6;"> stops cookie-based CSWSH</mark> => A malicious site cannot perform a successful cross-site WebSocket handshake with a user’s cookie, since that cookie is outside the current cookie storage partition. This applies <mark style="background: #ADCCFFA6;">even if the cookie is configured as SameSite=None.</mark>
### Private Network Access
- The [Private Network Access specification](https://wicg.github.io/private-network-access/) acknowledges that an increasing amount of services run on a user’s localhost and their private network, and describes a control similar to CORS to prevent public Internet resources from making unapproved requests to private resources. See for instance [this incredible writeup against Tailscale](https://emily.id.au/tailscale).

- Within the Private Network Access specification, IP address spaces are divided into three types: `public`,` private`, and `local`. A request <mark style="background: #BBFABBA6;">(even a GET request</mark>) that is made from a more public to a more private address space<mark style="background: #BBFABBA6;"> triggers a preflight OPTIONS request </mark>that has the ==Access-Control-Request-Private-Network: true== header attached by Chrome, and must receive a corresponding ==Access-Control-Allow-Private-Network: true== header in the response for the main request to be sent.
- [called out in the specification](https://wicg.github.io/private-network-access/#integration-websockets), since Private Network Access uses CORS preflight requests as the protection method, and WebSockets do not follow SOP and thus do not use preflight requests => ==Private Network Access in Chrome does not block CSWSH against private networks.==
### Mitigation

- WebSocket server **should first check the Origin of the WebSocket handshake request**. If the request does not come from a trusted and expected Origin, then the WebSocket handshake should fail. “`Missing Origin Validation in WebSockets`” has its own Common Weakness Enumeration [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- thinking of setting CSRF cookie ? => **[you can’t set arbitrary headers](https://github.com/whatwg/websockets/issues/16)**. There are some workarounds such as putting a token in the [Sec-WebSocket-Protocol header](https://ably.com/blog/websocket-authentication) or authenticating in the first WebSocket message.
- `SameSite=Lax` by default (not all the browsers support this)
