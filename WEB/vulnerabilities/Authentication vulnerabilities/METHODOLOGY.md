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
[[WEB/vulnerabilities/Authentication vulnerabilities/payload#Username enumeration|examples]]
### Brute-forcing passwords
- *knowledge of human behavior* + *password policy* => effective password bruteforce 
- again *public disclosures*
- 