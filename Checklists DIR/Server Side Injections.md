## **_fingerprint which back-end is used_**
- [ ] **use HTTP parameter pollution**  -> [link to research](https://medium.com/@0xAwali/http-parameter-pollution-in-2024-32ec1b810f89)
	- [ ]  ![[Pasted image 20251029224311.png]]

# SQLI 
- [ ]  **detect Entry points** [[SQLi#Entry point detection |payloads]]
	- [ ] all user inputs that can intract with database 
	- [ ] any sign of sql query in response (r.g Errors)
	- [ ] possible Headers (blind works here)
		- [ ] User-agent 
		- [ ] Cookie
		- [ ] Referer
		- [ ] X-Forwarded-For ? 
		- [ ] X-Forwarded-Host ? 
> data = related data (to that specified input you used) in response
- [ ] **Dumping Database manually?**
	- [ ] data retrivied? 
		- [ ] UNION based [[unprocessed-obsidians/OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#UNION attacks|METHODOLOGY]] 
	- [ ] existence of input is getting checked? (so there is data)
		- [ ] difference in response ? -> Boolean based [[unprocessed-obsidians/OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Boolean-based|METHODOLOGY]]
		- [ ] you can raise any Error ? -> Error based [[unprocessed-obsidians/OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Error-based|METHODOLOGY]]  
	- [ ] there is no data but you can make delays ?
		- [ ] Time based [[unprocessed-obsidians/OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#triggering time delays|METHODOLOGY]] | [[SQLi#time based |payloads]] 

- [ ] **Bypass Authentication** [[SQLi#Authentication bypass |payloads]]
- [ ] SQLmap? [[Notes/Server Side Injections#SQLmap|see here]] 
# C|SSTI (Client|Server side template injection)
- [ ] **Detect** 
	- [ ] in what context you are?
		- [ ] Plaintext context (reflected) where you can directly input HTML 
		      `freemarker=Hello ${7*7} =>  Hello 49`
			- [ ] can you invoke Expression ? -> [[SSTI#Detect#[Template Expressions - Seclist ](https //github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-expression.txt) | Seclist FUZZing list ]]
			- [ ] can you invoke some errors ? -> [[SSTI#Detect#Special characters | Special characters ]]
		- [ ] Code context
		      `personal_greeting=username}}<tag> =>  Hello user01 <tag>`
			- [ ] break out of the template statement and inject HTML tag after it 
- [ ] **look for template** behavior -> [link to research](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
	- [ ] ![[Pasted image 20251029224436.png]]
- [ ] **Exploit** 
	- [ ]  Out of Band Template Injection Payloads -> [link to research ](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
	- [ ]  Error based blind SSTI (mentioned a bit later at this page)
- [ ] wanna scale and automate ? use the bellow paper's approach + SSTImap
 - [ Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning](https://hackmanit.de/images/download/thesis/Improving-the-Detection-and-Identification-of-Template-Engines-for-Large-Scale-Template-Injection-Scanning-Maximilian-Hildebrand-Master-Thesis-Hackmanit.pdf)
 - The technique is focused on determining the template engines using the minimal amount of requests, but only works for simple injection contexts.
- ![[Pasted image 20260221220610.png]]
## Error based blind SSTI 
- [source: Successful Errors: New Code Injection and SSTI Techniques](https://github.com/vladko312/Research_Successful_Errors/blob/main/README.md)
- [SSTImap](https://github.com/vladko312/SSTImap) uses this approach for blind detection 
- [ ] [[Payloads/SSTI#Blind Erorr-Based|list of payloads for manual detection and exploitation based oin the template parser and language]]
