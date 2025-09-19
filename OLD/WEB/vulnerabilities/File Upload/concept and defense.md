# concept

## What are file upload vulnerabilities?

- when a web server allows users to upload files *to its filesystem* *without sufficiently validating*
- -> <mark style="background: #FFB86CA6;">name</mark>, <mark style="background: #FFB86CA6;">type</mark>, <mark style="background: #FFB86CA6;">contents</mark>, or <mark style="background: #FFB86CA6;">size</mark>.
- -> typically to trigger its *execution by the server*.
## impact

- Which aspect of the file the website *fails to <mark style="background: #BBFABBA6;">validate</mark>* properly?
- What *<mark style="background: #BBFABBA6;">restrictions</mark>* are imposed on the file *after a successful upload*? 
### chain 
- file's type isn't validated properly(executable files can be executed)=> <mark style="background: #FF5582A6;">RCE</mark> 
- overwrite files in the same location with same name + directory traversal => <mark style="background: #FF5582A6;">change in the files on the server</mark> 
- fail to validate the size of the file => <mark style="background: #FF5582A6;">DoS</mark>
## How do file upload vulnerabilities arise?

- rare to have no restrictions
- they may attempt to **blacklist** dangerous file types -> bypassable
- attempt to check the file type by verifying **properties that can be manipulated**.
- validation measures may be applied *inconsistently* across the network of hosts and directories that form the website -> **discrepancies**
  
  ## How do web servers handle requests for static files?

- _in the past_ -> mapped 1:1 with the file system hierarchy
- _nowadays_ -> dynamic mapping => no direct relationship
	- <mark style="background: #D2B3FFA6;">preconfigured mapping between extensions and MIME types</mark> -> filetype:
		- **non-executable** => server just sends the file's content.
		- **executable + configured to execute** => assign varibles based on the headers and parameters in HTTP request -> execute -> (maybe) show the output in the HTTP response.
		- **executable + not configured** => error OR plaintext 
	- `Content-Type` response header -> clue about what the server thinks

# defense 

- **the most effective way** -> **implement all** of these practices:
	- check file type against *<mark style="background: #BBFABBA6;">whitelist</mark>* => easier to restrict
	- filename doesn't contain any substrings that may be interpreted as a *<mark style="background: #BBFABBA6;">directory or a traversal sequence</mark>* (`../`) 
	- *<mark style="background: #BBFABBA6;">Rename uploaded files</mark>* to avoid collisions => overwrite
	- Do not upload files to the server's permanent filesystem until they have been <mark style="background: #BBFABBA6;">fully validated</mark>. 
	- use an *<mark style="background: #BBFABBA6;">established framework</mark>* for preprocessing file uploads instead of manual validation mechanisms.

