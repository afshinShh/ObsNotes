
# test & exploit

Burp Suit professional-> right-click request -> Engagement tools -> Generate CSRF PoC 
no defense -> create a form ( [[OLD/WEB/vulnerabilities/CSRF/attack/Examples#basic| basic payload]] )
## Bypassing CSRF-token validation

- [ ] change method to get -> accepted -> delete method property of form 
- [ ] delete the entire csrf parameter 
- [ ] same request from 2 different user? ( == is csrftoken tied to session token?)
  - [ ] swap csrf values
  - [ ] make request -> save csrf -> drop request -> use the saved csrf-token with another user 
  - [ ] change csrfKey cookie -> not related to session ->
    - [ ] use csrf-token+csrfKey on another user
    - [ ] find sink where you can inject cookie -> use a html element to deliver crafted link 
      [[OLD/WEB/vulnerabilities/CSRF/attack/Examples#token tied to non-session cookie| token tied to non-session cookie]]
- [ ] same csrf is duplicated in cookie -> invent csrf token -> inject csrf cookie (same as injecting csrfKey)
---

# chain 
