
# Common in Payment-Related Applications

## 2.1 Time-of-Check-Time-of-Use (TOCTOU) and Race Condition Issues
- [ ] 2.1.1 Transferring Money or Points, or Buying Items Simultaneously
- [ ] 2.1.2 Changing the Order upon Payment Completion
- [ ] 2.1.3 Changing the Order after Payment Completion

## 2.2 Parameter Manipulation
- [ ] 2.2.1 **Price** Manipulation -> rare 
	- [ ] negative
	- [ ] hedden field
	- [ ] dependence of value to the items
	- [ ] change price on the callback from the payment server
- [ ] 2.2.2 **Currency** Manipulation
	- example: ![[Pasted image 20251225133318.png]]
- [ ] 2.2.3 **Quantity** Manipulation
- [ ] 2.2.4 **Shipping Address** and Post Method Manipulation
	- [ ] TOCTOU
	- [ ] change in tax
- [ ] 2.2.5 Additional Costs Manipulation ( any parameter that impact the cost )
	- e.g: adding Gift wrap for free during payment process 
- [ ] 2.2.6 **Response** Manipulation
	- [ ] usually with third party
	- [ ] controlling the response to see client side limited features 
- [ ] 2.2.7 **Repeating an Input Parameter** Multiple Times
	- [ ] use param\[\]
	- [ ] use [[Exotic Data Formats#Json#parameter polution | json features]]
- [ ] 2.2.8 **Omitting** an Input Parameter or its Value
	- [ ] removing parameter completely
	- [ ] removing value
	- [ ] bull character
	- [ ] removing equal sign (\=) 
- [ ] 2.2.9 **Mass Assignment**, Autobinding, or Object Injection
- [ ] 2.2.10 Monitor the Behaviour while Changing Parameters to Detect Logical Flaws
	- [ ] sometimes the **combination of parameters** needed to change behavior
		- example: 
			- ![[Pasted image 20251225140637.png]]
		- [ ] set the target field (e.g price) to an unexpected value => then change other paramters one by one



## 2.3 Replay Attacks (Capture-Replay)
- [ ] 2.3.1 Replaying the **Call-back Request**
	- e.g: same request only change in tansaction-id parameter
- [ ] 2.3.2 Replaying an **Encrypted Parameter**
	-  e.g: price value was encrypted and checked at server-side but not the entire request  
## 2.4 Rounding Errors
- [ ] 2.4.1 **Currency** Rounding Issues
	-  ![[Pasted image 20251225142012.png]]
	- ![[Pasted image 20251225141944.png]]
	- [ ] what reduces the impact ?
		- [ ] is there any commition fee ?
		- [ ] is there any different buy and sell rates(in favour of the company) ?
- [ ] 2.4.2 Generic Rounding Issues
	- [ ] **inconsistency** in handling of value between different code or application
		-  eg: app accepts digits, api accepts 2 digits
## 2.5 Numerical Processing
- [ ] 2.5.1 **Negative** Numbers
	- [ ] generic value
	- [ ] <mark style="background: #FF5582A6;">-1</mark> can flip the logic  
- [ ] 2.5.2 Decimal Numbers
- [ ] 2.5.3 **Large or Small** Numbers
- [ ] 2.5.4 Overflows and Underflows
	- [ ] 2\*\*31-1
	- [ ] -2\*\*31
- [ ] 2.5.5 Zero, Null, or Subnormal Numbers
	- [ ] NaN
	- [ ] 0
	- [ ] null
	- [ ] rounds to zero 
		- [ ] 0.0000000000000000000000001
		- [ ] 1e-50
- [ ] 2.5.6 Exponential Notation
	- [ ] 9e99 -> 100 digits
	- [ ] 1e-1 -> 0.1
- [ ] 2.5.7 Reserved Words
	- [ ] NaN
	- [ ] Infinity
	- [ ] -NaN
	- [ ] -Infinity
- [ ] 2.5.8 Numbers in Different Formats
	- [ ] ![[Pasted image 20251225144241.png]] ![[Pasted image 20251225144302.png]]

## 2.6 Card Number-Related Issues (PCI DSS compliant)
- must be encrypted in storage

- [ ] 2.6.1 Showing a Saved Card Number during the Payment Process
	- [ ] can be auuired when xss or session related issue 
- [ ] 2.6.2 Card Number Enumeration via Registering Duplicate Cards

## 2.7 Dynamic Prices, Prices with Tolerance, or Referral Schemes

## 2.8 Discount Codes, Vouchers, Offers, Reward Points, and Gift Cards
- [ ] 2.8.1 **Enumeration** and Guessing
- [ ] 2.8.2 Vouchers and Offers Stacking
- [ ] 2.8.3 **Earning More Points or Cash Return than the Price** when Buying an Item
- [ ] 2.8.4 Using Expired, Invalid, or Other Users' Codes
- [ ] 2.8.5 State and **Basket Manipulation**
	- [ ] 2.8.6 Refund Abuse
- [ ] 2.8.7 **Buy-X-Get-Y-Free**
	- [ ] not discounting the cheapest item in 3 for 2
	- [ ] 3 for 2 
		- [ ] can become 2 for 1 (free item counts as 3)
		- [ ] can become 33% off the whole bascket (1 expensive + 2 cheap)
		- [ ] can become 4 for 2 (adding 4 item instead of 3) 
		- [ ] can become 3 for 1 due to logical issues
- [ ] 2.8.8 Ordering Out of Stock or Unreleased Items
	- e.g: when the out of stock items are cheaper
		- [ ]  buying and cancelling to lower the target stock temporary
- [ ] 2.8.9 Bypassing Other Restrictions
	- [ ] abusing customer specific offers
	- [ ] use one time voucher multiple time
- [ ] 2.8.10 Point Transfer

## 2.9 Cryptography Issues
- [ ] bruteforce the secret key
- [ ] length-extension attack
- [ ] use of forgeable delimeter
	- e.g: ![[Pasted image 20251225233501.png]]
## 2.10 Downloadable and Virtual Goods
- [ ] direct object reference attack (IDOR)
## 2.11 Hidden and Insecure Backend APIs
- [ ] mobile or tablet app APIs 
- [ ] access control issues

## 2.12 Using Test Data in Production Environment
- [ ] change the HOST header to a knwon internal domain
- [ ] debugging and test pages with juicy functionality
- [ ] tokens, dummmy vaia

## 2.13 Currency Arbitrage in Deposit/Buy and Withdrawal/Refund
- [ ] deposit in one currency and withdraw with another => if the methods are different 

- ![[Pasted image 20251225234133.png]]  
# WSTG Payment Functionality

### Payment Gateway Integration Methods
> [!question] which one of these ?
- [ ] Redirecting the user to a third-party payment gateway.
- [ ] Loading a third-party payment gateway in an IFRAME on the application.
- [ ] Having a HTML form that makes a cross-domain POST request to a third-party payment gateway.
- [ ] Accepting the card details directly, and then making a POST from the application backend to the payment gateway’s API.
### PCI DSS
it applies to any system that “**stores**, **processes** or **transmits**” cardholder data (i.e, debit or credit card details)

/gitc