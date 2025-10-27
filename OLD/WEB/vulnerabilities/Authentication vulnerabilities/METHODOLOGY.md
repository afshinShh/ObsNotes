# password-based login

## Brute-force attacks

- <mark style="background: #FF5582A6;">attacker uses a system of trial and error to guess valid user credentials</mark>. -> automated
- _educated guesses_ using tools (take a look at this [[resources|Book]])

### Brute-forcing usernames
- easy to **guess**
  - `firstname.lastname@somecompany.com`
  - profile name as username
  - common high-privileged accounts :
    - admin
    - administrator
    - ...
- **public disclosures**
- **HTTP responses** -> email address of high-privileged users (admin/IT support)
#### Username enumeration

- **when** an attacker is able to observe <mark style="background: #ABF7F7A6;">changes in the website's behavior in order to identify</mark> whether a given username is valid 

- **where?** 
  - registration forms
  - login page

- **How?** difference in:
  - *Status codes*
  - *Error messages
  - *Response times*

[[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Brute-forcing usernames|examples]]
### Brute-forcing passwords
- *knowledge of human behavior* + *password policy* => effective password bruteforce 
- again *public disclosures*
## Flawed brute-force protection

brute-force protection -> make it as tricky as possible to <mark style="background: #FFF3A3A6;">automate the process</mark> and <mark style="background: #FFF3A3A6;">slow down the rate</mark> at which an attacker can attempt logins.
- ***Blocking the remote user's IP address***
  - _failed attempts counting_ -> <mark style="background: #ADCCFFA6;">include your own login credentials</mark> at regular intervals throughout the wordlist. [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#IP block|example]] 
- ***Locking the account***
  - list of candidate *usernames that are likely to be valid* [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#account lock|example]]
  - *very small shortlist of passwords* -> at least one user is likely to have
    ex: limit=3 => maximum of 3 password guesses
  - *credential stuffing* 
    - `username:password` pairs
    - composed of genuine <mark style="background: #ADCCFFA6;">login credentials stolen in data breaches</mark>
       - people reuse the same username and password for different websites
    - each username is only being attempted once
    - dangerous -> compromising multiple account in a single automated attempt
- ***User rate limiting*** #todo,  
## HTTP basic authentication

- the client receives an authentication token from the server
- This token is stored and managed by the browser, which automatically adds it to the *`Authorization` header* of *every subsequent request*
```http header
GET /index.php HTTP/1.1

Authorization: Basic base64(username:password)
```

- ***NOT SECURE***
  - <mark style="background: #D2B3FFA6;">vulnerable to</mark>: 
    1) being **brute-forced**
    2) **session-related exploits**, notably [[Notes/CSRF/attack/METHODOLOGY|METHODOLOGY]].
    3) user's login credentials with every request => 
        _unless implemented_ *HTTP Strict Transport Security* ([HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)) -> vulnerable to **Man In The Middle attack (MITM)**:
        - [cookie hijacking](https://en.wikipedia.org/wiki/Session_hijacking)
        - [protocol downgrade attacks](https://en.wikipedia.org/wiki/Protocol_downgrade_attack)  
  - <mark style="background: #D2B3FFA6;">if gets exploited</mark>:
    - further **attack surface**
    - **credentials exposed** => reusable for other parts

# multi-factor authentication

##### concepts
- <mark style="background: #FF5582A6;">typical two-factor authentication (2FA) is based on something you know and something you have</mark>. -> password + out-of-band physical device
- as secure as its **implementation**.
  - *illusion of multiple-factor* -> _Email-based_ 2FA (still something you know)
  - *potential vulnerable devices* -> _SMS-based_ (vulnerable to SIM swapping/intercept)
## Bypassing two-factor authentication

### Flawed two-factor verification logic

- verification code on a separate page ->  *"logged in" state before code verification* [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#simple bypass|senario]]
- *doesn't verify* that the *same user* is completing the second step [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Bypassing two-factor authentication#broken logic|senario]]
  - ex: 
  	- victim's cookie is guessable 
### Brute-forcing 2FA verification codes
#todo
# other authentication mechanisms

## Keeping users logged in

- "<mark style="background: #FFB86CA6;">Remember me</mark>" or "<mark style="background: #FFB86CA6;">Keep me logged in</mark>"
- <mark style="background: #FF5582A6;">Token -> stored in persistent cookie</mark>.
  - **predictable cookie** -> brute force [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#brute-force|senario]]
  - **weak encryption** of the token
    - encoding only
    - (proper encryption + one way hash function) but no salt => the old rainbow attack. [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#offline password cracking|example]]
  - **construct the cookie**
    - open source framework -> read the documentation
    - additional sensitive information in the cookie
    - no access to creating account -> XSS for stealing the cookie
## Resetting user passwords

- ***Sending passwords by email*** 
  - _Man In The Middle attack (MITM)_ unless:
    - generated password expiring
    - user changing their password again immediately
- ***Resetting passwords using a URL***
  - *weak implementation* / broken logic / easily guessable parameter [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Resetting user passwords#broken logic|example]] 
  - URL in the reset email is *generated dynamically* => [Password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Resetting user passwords#password reset poisoning via middleware|senario]]
## Changing user passwords

- **same procces** as of the above functions -> *same vulnerabilities*
- **access directly without being logged in**as the victim user 
  - ex: username provided in a hidden field => *enumerate usernames* and *brute-force passwords* [[OLD/WEB/vulnerabilities/Authentication vulnerabilities/payload#Changing user passwords#password brute-force|example]]
