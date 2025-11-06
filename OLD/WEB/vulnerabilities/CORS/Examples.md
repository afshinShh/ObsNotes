Case 1
`Access-Control-Allow-Origin: https://attacker.com`
`Access-Control-Allow-Credentials: True`

Case 2
`Access-Control-Allow-Origin: https://company.com.attacker.com`
`Access-Control-Allow-Credentials: True`

Case 3
`Access-Control-Allow-Origin: null`
`Access-Control-Allow-Credentials: True`

Case 4
`Access-Control-Allow-Origin: https://anysub.company.com`
`Access-Control-Allow-Credentials: True`


>NOTICE:
- it’s a flaw once you can exploit it [example report](<- it’s a flaw once you can exploit it https://hackerone.com/reports/288912>)

