# password-based login

## Brute-force attacks

- <mark style="background: #FF5582A6;">attacker uses a system of trial and error to guess valid user credentials</mark>. -> automated
- _educated guesses_ using tools (take a look at this [[WEB/vulnerabilities/Authentication vulnerabilities/resources|Book]])

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
[[WEB/vulnerabilities/Authentication vulnerabilities/payload#Brute-forcing usernames|examples]]
### Brute-forcing passwords
- *knowledge of human behavior* + *password policy* => effective password bruteforce 
- again *public disclosures*
## Flawed brute-force protection

brute-force protection -> make it as tricky as possible to <mark style="background: #FFF3A3A6;">automate the process</mark> and <mark style="background: #FFF3A3A6;">slow down the rate</mark> at which an attacker can attempt logins.
- **Blocking the remote user's IP address**
  - _failed attempts counting_ -> <mark style="background: #ADCCFFA6;">include your own login credentials</mark> at regular intervals throughout the wordlist. [[WEB/vulnerabilities/Authentication vulnerabilities/payload#IP block|example]] 
- **Locking the account**
  - list of candidate *usernames that are likely to be valid* [[WEB/vulnerabilities/Authentication vulnerabilities/payload#account lock|example]]
  - *very small shortlist of passwords* -> at least one user is likely to have
    ex: limit=3 => maximum of 3 password guesses
  - *credential stuffing* 
    - `username:password` pairs
    - composed of genuine <mark style="background: #ADCCFFA6;">login credentials stolen in data breaches</mark>
       - people reuse the same username and password for different websites
    - each username is only being attempted once
    - dangerous -> compromising multiple account in a single automated attempt
- **User rate limiting** #todo
## HTTP basic authentication

- the client receives an authentication token from the server
- This token is stored and managed by the browser, which automatically adds it to the *`Authorization` header* of *every subsequent request*
```http header
GET /index.php HTTP/1.1

Authorization: Basic base64(username:password)
```

- ***NOT SECURE***
  - <mark style="background: #D2B3FFA6;">vulnerable to</mark>: 
    1) being **brute-force**d
    2) **session-related exploits**, notably [[WEB/vulnerabilities/CSRF/attack/METHODOLOGY|METHODOLOGY]].
    3) user's login credentials with every request => 
        _unless implemented_ *HTTP Strict Transport Security* ([HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)) -> vulnerable to **Man In The Middle attack (MITM)**:
        - [cookie hijacking](https://en.wikipedia.org/wiki/Session_hijacking)
        - [protocol downgrade attacks](https://en.wikipedia.org/wiki/Protocol_downgrade_attack)  
  - <mark style="background: #D2B3FFA6;">if gets exploited</mark>:
    - further **attack surface**
    - **credentials exposed** => reusable for other parts

# multi-factor authentication

