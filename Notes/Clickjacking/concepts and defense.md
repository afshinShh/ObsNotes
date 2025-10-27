** Table of Contents **

- [definition](#definition)
	- [example](#example)
	- [Clickjacking vs CSRF](#Clickjacking%20vs%20CSRF)
- [How To](#How%20To)
- [defense](#defense)

# definition

Clickjacking is an <mark style="background: #FF5582A6;">interface-based</mark> attack in which a user is tricked into clicking on actionable content on a <mark style="background: #FF5582A6;">hidden website </mark>by clicking on some other content <mark style="background: #FF5582A6;">in a decoy website</mark>.
## example

win a prize sites -> hidden pay request using iframe
## Clickjacking vs CSRF

differs from [[WEB/vulnerabilities/CSRF/defense/cause|CSRF]] attack : 
-  user is <mark style="background: #FFF3A3A6;">required to perform an action</mark> (click) - CSRF depends upon forging an entire request without the user's knowledge or input
- all requests happening <mark style="background: #FFF3A3A6;">on-domain</mark> - you can't use csrf token as protection
---
# How To

Clickjacking attacks use <mark style="background: #BBFABBA6;">CSS to create and manipulate layers</mark>. (the target website as an <mark style="background: #BBFABBA6;">iframe</mark> layer overlaid on the decoy website)
<mark style="background: #BBFABBA6;">Absolute and relative position</mark> values are used to ensure that the target website accurately overlaps the decoy regardless of screen size.
<mark style="background: #BBFABBA6;">z-index</mark> determines the stacking order of the iframe and website layers.
The attacker selects <mark style="background: #BBFABBA6;">opacity</mark> values so that the desired effect is achieved without triggering protection behaviors.

let's see in action: [[Notes/Clickjacking/attack/payload#basic attack|simple attack]]


# defense 

- These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript
- they perform some or all of the following behaviors:
  *   check and enforce that the current application window is the main or top window,
  *   make all frames visible,
  *   prevent clicking on invisible frames,
  *   intercept and flag potential clickjacking attacks to the user.

