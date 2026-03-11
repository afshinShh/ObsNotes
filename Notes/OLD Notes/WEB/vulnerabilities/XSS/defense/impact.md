## What can XSS be used for?

An attacker who exploits a cross-site scripting vulnerability is typically able to:

- <mark style="background: #FFB86CA6;">Impersonate or masquerade</mark> as the victim user.
- Carry out <mark style="background: #FFB86CA6;">any action</mark> that the user is able to perform.
- <mark style="background: #FFB86CA6;">Read any data</mark> that the user is able to access.
- Capture the user's <mark style="background: #FFB86CA6;">login credentials</mark>.
- Perform virtual <mark style="background: #FFB86CA6;">defacement</mark> of the web site.
- <mark style="background: #FFB86CA6;">Inject trojan</mark> functionality into the web site.
## measuring the impact

The actual impact of an XSS attack generally depends on the **nature of the application**, its **functionality** and **data**, and the status of the **compromised user**

- In a brochureware application -> all users are anonymous and all information is public -> <mark style="background: #BBFABBA6;">minimal</mark>
- In an application holding sensitive data -> (banking transactions, emails, or healthcare records) -> <mark style="background: #FFF3A3A6;">serious</mark>
- compromised user has elevated privileges -> <mark style="background: #FF5582A6;">critical</mark> (full compromise)


