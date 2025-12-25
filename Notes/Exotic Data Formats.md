# Json 
### parameter polution
```json
{"id": 2} => {"id": [2]}
{"id": 2} => {"id": {"id": 2}}
{"id": 2} => {"id": 1, "id": 2}
{"id": 2} => {"id": 2, "id": 1}
{"id": 2} => {"id": "*"}
```

# Parser Differentials 

- [Unexpected security footguns in Go's parsers](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/)
- [Security Implications of URL Parsing Differentials](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/#)
- [Breaking Down Multipart Parsers: File upload validation bypass](https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/)

/git