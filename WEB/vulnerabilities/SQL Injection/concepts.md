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

