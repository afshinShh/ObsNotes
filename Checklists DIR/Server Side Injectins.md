## **_fingerprint which back-end is used_**
- [ ] **use HTTP parameter pollution**  -> [link to research](https://medium.com/@0xAwali/http-parameter-pollution-in-2024-32ec1b810f89)
	- [ ]  ![[Pasted image 20251029224311.png]]

# SQLI 
- [ ]  **detect Entry points** [[SQLi#Entry point detection |payloads]]
	- [ ] all user inputs that can intract with database 
	- [ ] any sign of sql query in response (r.g Errors)
	- [ ] po￼ssible Headers (blind works here)
		- [ ] User-agent 
		- [ ] Cookie
		- [ ] Referer
		- [ ] X-Forwarded-For ? 
		- [ ] X-Forwarded-Host ? 
> data = related data (to that specified input you used) in response
- [ ] **Dumping Database manually?**
	- [ ] data retrivied? 
		- [ ] UNION based [[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#UNION attacks|METHODOLOGY]] 
	- [ ] existence of input is getting checked? (so there is data)
		- [ ] difference in response ? -> Boolean based [[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Boolean-based|METHODOLOGY]]
		- [ ] you can raise any Error ? -> Error based [[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Error-based|METHODOLOGY]]  
	- [ ] there is no data but you can make delays ?
		- [ ] Time based [[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#triggering time delays|METHODOLOGY]] | [[SQLi#time based |payloads]] 

- [ ] **Bypass Authentication** [[SQLi#Authentication bypass |payloads]]
- [ ] SQLmap? [[Server Side Injections#SQLmap |see here]] 
# C|SSTI (Client|Server side template injection)
- [ ] try simple detection payloads 
	- [ ] can you invoke some errors ? -> [[SSTI#Detect#Special characters | Special characters ]]
	- [ ] can you invoke Expression ? -> [[SSTI#Detect#[Template Expressions - Seclist ](https //github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-expression.txt) | Seclist FUZZing list ]]
- [ ] **look for template** behavior -> [link to research](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
	- [ ] ![[Pasted image 20251029224436.png]]
- [ ] **Exploit** 
	- [ ]  Out of Band Template Injection Payloads -> [link to research ](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)