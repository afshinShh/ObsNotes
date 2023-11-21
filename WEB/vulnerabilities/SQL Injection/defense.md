## How to prevent SQL injection

You can prevent most instances of SQL injection using <mark style="background: #FF5582A6;">parameterized queries</mark> instead of string concatenation within the query. These parameterized queries are also know as "<mark style="background: #FF5582A6;">prepared statements</mark>".

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:

```java
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

You can rewrite this code in a way that prevents the user input from interfering with the query structure:

```java
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

You can use parameterized queries for any situation where untrusted input appears as data within the query, including the `WHERE` clause and values in an `INSERT` or `UPDATE` statement. They can't be used to handle untrusted input in other parts of the query, such as table or column names, or the `ORDER BY` clause. Application functionality that places untrusted data into these parts of the query needs to take a different approach, such as:

- <mark style="background: #FFF3A3A6;">Whitelisting permitted input values</mark>.
- Using <mark style="background: #FFF3A3A6;">different logic</mark> to deliver the required behavior.

For a parameterized query to be effective in preventing SQL injection, the string that is used in the query must always be a <mark style="background: #FFF3A3A6;">hard-coded constant</mark>. It must <mark style="background: #FFF3A3A6;">never contain any variable data from any origin</mark>. Do not be tempted to decide case-by-case whether an item of data is trusted, and continue using string concatenation within the query for cases that are considered safe. It's easy to make mistakes about the possible origin of data, or for changes in other code to taint trusted data.

