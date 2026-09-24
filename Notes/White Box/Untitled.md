## Reading orientation 

| Step  | What to Read                             | What It Tells Us                                                                                  |
| ----- | ---------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **1** | README and documentation                 | Understand what the application does, how it is run, and which framework it uses.                 |
| **2** | Dependency manifest                      | Identify libraries, versions, and the third-party attack surface.                                 |
| **3** | Configuration files                      | Look for debug flags, secrets, database connection strings, and environment settings.             |
| **4** | Routing / Entry points                   | Build a complete map of the application's attack surface by identifying all accessible endpoints. |
| **5** | Authentication middleware and decorators | Determine which routes require authentication and which are publicly accessible.                  |
| **6** | Database / Models layer                  | Understand where data is stored and how database queries are constructed.                         |
| **7** | Individual route handlers                | Analyze the business logic implemented behind each endpoint.                                      |
### Dependency manifest

- `requirements.txt` (or `pyproject.toml`), in Java `pom.xml`, in .NET a `.csproj`
- `pip-audit` and node audit 
- 