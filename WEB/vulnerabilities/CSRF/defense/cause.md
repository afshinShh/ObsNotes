** Table of Contents **
- [A relevant action](#A%20relevant%20action)
- [Cookie-based session handling](#Cookie-based%20session%20handling)
- [No unpredictable request parameters](#No%20unpredictable%20request%20parameters)

## A relevant action

There is an action within the application that the attacker has a reason to induce. This might be a <mark style="background: #FF5582A6;">privileged action</mark> (such as modifying permissions for other users) or any action on <mark style="background: #FF5582A6;">user-specific data</mark> (such as changing the user's own password).

## Cookie-based session handling

Performing the action involves issuing one or more HTTP requests, and the application <mark style="background: #FFB86CA6;">relies solely on session cookies to identify the user who has made the requests.</mark> There is no other mechanism in place for tracking sessions or validating user requests.

## No unpredictable request parameters

For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password.