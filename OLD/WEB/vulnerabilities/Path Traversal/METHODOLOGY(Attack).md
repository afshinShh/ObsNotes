simplest form -> use `../` , `..\` [[OLD/WEB/vulnerabilities/Path Traversal/Examples#basic|basic ]]

# Common obstacles 

- application strips or blocks directory traversal sequences
  - use _absolute path_ [[OLD/WEB/vulnerabilities/Path Traversal/Examples#absolute path|payload]]
  - use _nested traversal sequences_ (`....//` or `....\/`) [[OLD/WEB/vulnerabilities/Path Traversal/Examples#nested traversal sequences|payload]]
  - in some contexts (like URL path or the `filename` parameter of a `multipart/form-data`) -> _URL encoding_, or even _double URL encoding_ [[OLD/WEB/vulnerabilities/Path Traversal/Examples#URL encode|payload]]
- application expects the filename to start with an _expected base folder_ [[OLD/WEB/vulnerabilities/Path Traversal/Examples#expected base folder|example]]
- An application expects the filename to end with an _expected file extension_ -> use null byte `%00` [[OLD/WEB/vulnerabilities/Path Traversal/Examples#expected file extension|example]]
