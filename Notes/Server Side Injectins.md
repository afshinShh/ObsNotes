# SQLi
![types of SQL injection](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1716989638556)

## In-band 
- ERROR based
- Union based
[[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#In-Band SQL injection|Manual Exploitation]] (OLD notes)

## Inferential 
 - Boolean based
 - Time based
[[OLD/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY#Inferential(Blind) SQL injection|Manual Exploitation]] (OLD notes)

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
(like sqli):
1. **Authentication Bypass:** Modifying LDAP authentication queries to log in as another user without knowing their password.
2. **Unauthorized Data Access:** Altering LDAP search queries to retrieve sensitive information not intended for the attacker's access.
3. **Data Manipulation:** Injecting queries that modify the LDAP directory, such as adding or modifying user attributes.

![[Pasted image 20251030195722.png]]
example of vulnerable code:
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
/gitcomm