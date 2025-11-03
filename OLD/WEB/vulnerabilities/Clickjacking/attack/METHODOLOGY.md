# test & exploit

simple attack: [[OLD/WEB/vulnerabilities/Clickjacking/attack/payload#basic attack|create a decoy website]]
prefilled form -> site uses GET request -> parse your parameter in URL 

## Bypassing frame busting (breaking) script

- frame buster -> **sandbox** attribute (HTML5) within the form 
  - ``` allow-script ```| ``` allow-forms ```
  - ommit  ``` allow-top-navigation ```
---
# chain
## clickjacking + DOM XSS 

- simple example: like-boosting on facebook
- XSS payload + iframe URL target
[[OLD/WEB/vulnerabilities/Clickjacking/attack/payload#clickjacking + DOM XSS|payload]]

## Multistep clickjacking

- buying from a retail website so items need to be added to a shopping basket before the order is placed.
- getting confirmation before deleting the user's account.
[[OLD/WEB/vulnerabilities/Clickjacking/attack/payload#Multistep clickjacking|payload]]

