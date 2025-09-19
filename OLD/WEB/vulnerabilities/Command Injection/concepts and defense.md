# What is command injection?

- *OS command injection (shell injection)* is a vulnerability which allows the attacker to <mark style="background: #FF5582A6;">execute operating system (OS) commands on the server</mark> that is running an application => **full compromise** of the application and its data

# how to prevent ? 

**The most effective way** -> <mark style="background: #BBFABBA6;">never call out to OS commands from application-layer code</mark>.
- implement the required functionality using *safer platform APIs*.

**If you have to** call out to OS commands with user-supplied input -> strong input validation

- Validating against a <mark style="background: #ABF7F7A6;">whitelist</mark> of permitted values.
- Validating that the input is a <mark style="background: #ABF7F7A6;">number</mark>.
- Validating that the input contains <mark style="background: #ABF7F7A6;">only alphanumeric characters</mark>, _no other syntax or whitespace_.

**Never attempt to** sanitize input <mark style="background: #CACFD9A6;">by escaping shell metacharacters</mark>. In practice, this is just too _error-prone and vulnerable_ to being bypassed by a skilled attacker.