# SQL 

```sql
-- SQL is not case-sensitive about keywords
-- Create and delete a database. Database and table names are case-sensitive.
CREATE DATABASE someDatabase;
DROP DATABASE someDatabase;
-- List available databases.
SHOW DATABASES;
-- Use a particular existing database.
USE employees;
-- Select all rows and columns from the current database's departments table.
SELECT * FROM departments;
-- Retrieve all rows from the departments table,
SELECT dept_no,
       dept_name FROM departments;
-- Retrieve all departments columns, but just 5 rows.
SELECT * FROM departments LIMIT 5;
-- Retrieve dept_name column values from the departments table where the dept_name value has the substring 'en'.
SELECT dept_name FROM departments WHERE dept_name LIKE '%en%';
-- Retrieve all columns from the departments table where the dept_name
-- column starts with an 'S' and has exactly 4 characters after it.
SELECT * FROM departments WHERE dept_name LIKE 'S____';
-- Select title values from the titles table but don't show duplicates + sorted.
SELECT DISTINCT title FROM titles ORDER BY title;
-- Show the number of rows in the departments table that have 'en' as a substring of the dept_name value.
SELECT COUNT(*) FROM departments WHERE dept_name LIKE '%en%';

-- -> Read about INNER-JOIN / right/left/full OUTER-JOIN for querying multiple tables 

-- List all the tables in all the databases. Implementations typically provide
-- their own shortcut command to do this with the database currently in use.
SELECT * FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_TYPE='BASE TABLE';
-- Insert a row of data into the table tablename1. This assumes that the
INSERT INTO tablename1 VALUES('Richard','Mutt');
-- In tablename1, change the fname value to 'John' for all rows that have an lname value of 'Mutt'.
UPDATE tablename1 SET fname='John' WHERE lname='Mutt';
-- Delete rows from the tablename1 table where the lname value begins with 'M'.
DELETE FROM tablename1 WHERE lname LIKE 'M%';
-- Delete all rows from the tablename1 table, leaving the empty table.
DELETE FROM tablename1;
-- Remove the entire tablename1 table.
DROP TABLE tablename1;
```

---
# sql injection

-> *vulnerability that allows an attacker to **interfere with the queries** that an application makes to its **database***
## impact 

- can result in unauthorized <mark style="background: #D2B3FFA6;">access to sensitive data</mark>, such as:
	- Personal user information.
	- Credit card details.
	- Passwords.
- In many cases, an attacker can <mark style="background: #FFB86CA6;">modify or delete</mark> this data, causing persistent changes to the application's content or behavior.
- In some situations, an attacker can escalate a SQL injection attack to <mark style="background: #FF5582A6;">compromise</mark> the underlying server or other back-end infrastructure. It can also enable them to perform <mark style="background: #ABF7F7A6;">denial-of-service</mark> attacks.
- Command execution by [appropriate permission](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16#permissions) 

## detection

- The <mark style="background: #CACFD9A6;">single quote character</mark> `'` and look for <mark style="background: #CACFD9A6;">errors</mark> or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic <mark style="background: #CACFD9A6;">differences in the application responses</mark>.
- <mark style="background: #CACFD9A6;">Boolean conditions</mark> such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
- Payloads designed to trigger <mark style="background: #CACFD9A6;">time delays </mark>when executed within a SQL query, and look for differences in the time taken to respond.
- [OAST](https://portswigger.net/burp/application-security-testing/oast) payloads designed to trigger an <mark style="background: #CACFD9A6;">out-of-band network interaction</mark> when executed within a SQL query, and monitor any resulting interactions.
#### wait a second:
in SQL,*backslash* means to temporarily escape out of parsing the next character For example,
```sql
select "\"test" from table
```
-> selects "test from corresponding tables (it escapes)
## SQL injection in different parts of the query

Most SQL injection vulnerabilities occur within the *`WHERE` clause of a `SELECT` query*.
However, SQL injection vulnerabilities can occur at any location within the query, and within different query types. Some other common locations where SQL injection arises are:

- *In `UPDATE` statements, within the updated values or the `WHERE` clause.*
- *In `INSERT` statements, within the inserted values.*
- *In `SELECT` statements, within the table or column name.*
- *In `SELECT` statements, within the `ORDER BY` clause.*

examples:
```mysql
# https://site.com/product_id/142
select if ((select count from products where product_id = $PRODUCT_ID) > 0, 1, 0) # 0 or 1
```
-> The blind SQL injection works here (boolean based)

```mysql
# https://site.com/ inserts user’s information (IP, user agent, etc)
INSERT INTO table_name VALUES (value1, value2,…);
```
-> The blind SQL injection works here (time based)
## SQL injection examples

- [Retrieving hidden data](https://portswigger.net/web-security/sql-injection#retrieving-hidden-data), where you can modify a SQL query to return additional results.
- [Subverting application logic](https://portswigger.net/web-security/sql-injection#subverting-application-logic), where you can change a query to interfere with the application's logic.
- [UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks), where you can retrieve data from different database tables.
- [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind), where the results of a query you control are not returned in the application's responses.
/gitco