# Concepts

- A **Domain Controller** is a Windows server that provides Active Directory services and controls the entire domain. It is a form of centralized user management that provides encryption of user data as well as controlling access to a network, including users, groups, policies, and computers. It also enables resource access and sharing. These are all reasons why attackers target a domain controller in a domain because it contains a lot of high-value information.
  ![[Pasted image 20260704131324.png]]
- **Organizational Units ('s)** are containers within the domain with a hierarchical structure.

- **Active Directory Objects** can be a single user or a group, or a hardware component, such as a computer or printer. Each domain holds a database that contains object identity information that creates an environment, including:

- Users - A security principal that is allowed to authenticate to machines in the domain
- Computers - A special type of user accounts
- GPOs - Collections of policies that are applied to other objects

- **AD domains** are a collection of Microsoft components within an network. 

- **Forest** is a collection of domains that trust each other.
  ![[Pasted image 20260704131428.png]]

- The built-in local users' accounts are used to manage the system locally, which is not part of the AD environment.
- Domain user accounts with access to an active directory environment can use the AD services (managed by ).
- managed service accounts are limited domain user account with higher privileges to manage AD services.
- Domain Administrators are user accounts that can manage information in an Active Directory environment, including configurations, users, groups, permissions, roles, services, etc. One of the red team goals in engagement is to hunt for information that leads to a domain administrator having complete control over the AD environment.
  ==Active Directory Administrators accounts:==
```dataviewjs
dv.table(["Group", "Description"], [
  ["BUILTIN\\Administrator", "Local admin access on a domain controller"],
  ["Domain Admins", "Administrative access to all resources in the domain"],
  ["Enterprise Admins", "Available only in the forest root"],
  ["Schema Admins", "Capable of modifying domain/forest; useful for red teamers"],
  ["Server Operators", "Can manage domain servers"],
  ["Account Operators", "Can manage users that are not in privileged groups"]
])
```
