
# test & exploit

#apprentice 
no defense -> create a form ( [[WEB/vulnerabilities/CSRF/payload#basic| basic payload]] )
## Bypassing CSRF-token validation

#practitioner  
- change request method to get -> accepted -> delete method property of form 
- delete the entire csrf parameter 
- same request from 2 different user =>
  - swap csrf values
  - make request -> save csrf -> drop request -> use the saved csrf-token with another user 
  - change csrfKey cookie -> not related to session ->
    - use csrf-token+csrfKey on another user
    - find sink where you can inject cookie -> use a html element to deliver crafted link 
      [[WEB/vulnerabilities/CSRF/payload#token tied to non-session cookie| token tied to non-session cookie]]
- same csrf is duplicated in cookie -> invent csrf token -> inject csrf cookie (same as injecting csrfKey) 
# chain 


**remember to check the [[checklist]]**
