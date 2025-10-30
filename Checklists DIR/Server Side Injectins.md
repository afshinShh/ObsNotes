## **_fingerprint which back-end is used_**
- [ ] **use HTTP parameter pollution**  -> [link to research](https://medium.com/@0xAwali/http-parameter-pollution-in-2024-32ec1b810f89)
	- [ ]  ![[Pasted image 20251029224311.png]]

# SQLI 

# C|SSTI (Client|Server side template injection)
- [ ] try simple detection payloads 
	- [ ] can you invoke some errors ? -> [[SSTI#Detect#Special characters | Special characters ]]
	- [ ] can you invoke Expression ? -> [[SSTI#Detect#[Template Expressions - Seclist ](https //github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-expression.txt) | Seclist FUZZing list ]]
- [ ] **look for template** behavior -> [link to research](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
	- [ ] ![[Pasted image 20251029224436.png]]
- [ ] **Exploit** 
	- [ ]  Out of Band Template Injection Payloads -> [link to research ](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)