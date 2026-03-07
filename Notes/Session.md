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