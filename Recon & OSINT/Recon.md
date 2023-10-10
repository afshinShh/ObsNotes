- ###### find and verify credentials:
  nahamcon2022 | codingo  -> [truffle hog](https://github.com/trufflesecurity/trufflehog)
- nahamsec -> [Critical Bounties via Leaked API Keys (FT TruffleHug)](https://youtu.be/gkKLV-r_OQI)
  
  
- ###### A lightweight web security auditing toolkit.
	- nahamcon2022 | codingo  -> [caido](https://caido.io/) 

###### recon platform 
- nahamcon2022 | codingo -> security trails


# bug bounty recon for beginner's guide

## scanning

### nmap 

ctf -> `nmap  -A -p- -T4 -Pn 10.10.10.223 -v `
bug bounty -> `nmap  -A -F -T1(or 2) 10.10.10.223 -v`

### ffuf
realy fast -> may get you rate limited
`ffuf -w /usr/share/wordlists/dirb/common.txt -u http://dasasdda/FUZZ -fc 403 -p 2`
fc -> filter  403 requests
-p ->  delay between requests 
-> SecLists wordlist  
### dirb 

is slow 



## shodan 

- passive recon 
shodan init (API KEY)


## whois
## theHarvester

## crt.sh 

## wayback machin
 - tomnomnom tool -> waybackurls
## httprobe 

##  openlist firefox -> opens multiple urls at the same time 

## amass -> in depth attack surface mapping and asset discovery

## wappalyzer extension - react developer tool 
## ffuf

## dirb 

## ctf: wpscan 

