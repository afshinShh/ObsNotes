
The most effective way -> <mark style="background: #FF5582A6;">avoid passing user-supplied input to filesystem APIs</mark> altogether.

If you can't avoid passing user-supplied input to filesystem API use this  two layers of defense to prevent attacks:

- <mark style="background: #FF5582A6;">Validate the user input before processing it</mark>. Ideally, compare the user input with a <mark style="background: #ADCCFFA6;">whitelist</mark> of permitted values. If that isn't possible, <mark style="background: #ADCCFFA6;">verify</mark> that the input contains only permitted content, such as alphanumeric characters only.
- After validating the supplied input, append the input to the base directory <mark style="background: #FF5582A6;">and use a platform filesystem API to canonicalize</mark> the path. Verify that the canonicalized path starts with the expected base directory.

Below is an example of some simple Java code to validate the canonical path of a file based on user input:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
	// process file
}
```

/git