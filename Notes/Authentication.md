most cases 
     - authentication -> session (checked every request)
     - Re-Authentication token is saved in the Cookie (checked only if the Session is not present)
       ![[Pasted image 20250921190655.png]]
- user can alter 
	- session token
	- cookie 
## authentication token 
- stateless
- In session based application behind load balancer, **sticky session** mechanism should be used ([more info](https://medium.com/@mrcyna/what-are-the-sticky-sessions-222c378d2ce1))
- Multiple platforms and domains (CORS: * )
- commonly saved in
	- **localStorage**
	- **sessionStorage**

