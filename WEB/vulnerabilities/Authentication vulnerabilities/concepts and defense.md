- Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality + additional attack surface 

# What is Authentication?

<mark style="background: #FF5582A6;">the process of verifying the identity of a user or client</mark>

- types:
  - Something you **know**
    - password or the answer to a security question.
    - "<mark style="background: #ABF7F7A6;">knowledge factors</mark>"
  - Something you **have**
    - physical object such as a mobile phone or security token
    - "<mark style="background: #ABF7F7A6;">possession factors</mark>"
  - Something you **are** or do. 
    - your biometrics or patterns of behavior 
    - "<mark style="background: #ABF7F7A6;">inherence factors</mark>"
## Authentication vs Authorization

**Authorization** involves <mark style="background: #FF5582A6;">verifying whether a user is allowed</mark> to do something.
- ex:
  - authentication -> the person who calims to be Afshin is realy him?
  - authorization -> can Afshin perform actions such as deleting another user's account?

# How do authentication vulnerabilities arise?

- most vulns:
  - *The authentication **mechanisms** are weak*
    - fail to adequately protect against brute-force attacks
  - *Logic flaws or poor coding in the **implementation**.*
    - allow to be bypassed entirely by an attacker
    - = "_broken authentication_"
# impact

- bypasses authentication or brute-forces their way into another user's account => <mark style="background: #FFB86CA6;">account takeover</mark>
  - high-privileged account => <mark style="background: #FFB86CA6;">full takeover over the entire application</mark>.
- access to some internal functionalities => <mark style="background: #FFB86CA6;">extra attack surface</mark>.

# defense

- **Take care with user credentials**:
  - 
- **Don't count on users for security**:
- **Prevent username enumeration**:
- **Implement robust brute-force protection**:
- **Triple-check your verification logic**:
- **Don't forget supplementary functionality**:
- **Implement proper multi-factor authentication**:
/gitcomm