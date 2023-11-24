# XML

## Some definitions and introductions
- [source](https://learnxinyminutes.com/docs/xml/) 
```xml
<!-- This is a comment. It must not contain two consecutive hyphens (-). -->
<!-- Comments can span
  multiple lines -->

<!-- Elements -->
<!-- An element is a basic XML component. There are two types, empty: -->
<element1 attribute="value" /> <!-- Empty elements do not hold any content -->
<!-- and non-empty: -->
<element2 attribute="value">Content</element2>
<!-- Element names may only contain alphabets and numbers. -->

<empty /> <!-- An element either consists an empty element tag… -->
<!-- …which does not hold any content and is pure markup. -->

<notempty> <!-- Or, it consists of a start tag… -->
  <!-- …some content… -->
</notempty> <!-- and an end tag. -->

<!-- Element names are case sensitive. -->
<element />
<!-- is not the same as -->
<eLEMENT />

<!-- Attributes -->
<!-- An attribute is a key-value pair and exists within an element. -->
<element attribute="value" another="anotherValue" many="space-separated list" />
<!-- An attribute may appear only once in an element. It holds just one value.
  Common workarounds to this involve the use of space-separated lists. -->

<!-- Nesting elements -->
<!-- An element's content may include other elements: -->
<parent>
  <child>Text</child>
  <emptysibling />
</parent>
<!-- Standard tree nomenclature is followed. Each element being called a node.
  An ancestor a level up is the parent, descendants a level down are children.
  Elements within the same parent element are siblings. -->

<!-- XML preserves whitespace. -->
<child>
  Text
</child>
<!-- is not the same as -->
<child>Text</child>
```
## Well-formedness and Validation
- [source](https://learnxinyminutes.com/docs/xml/) 
```xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE bookstore SYSTEM "Bookstore.dtd">
<!-- Declares that bookstore is our root element and 'Bookstore.dtd' is the path
  to our DTD file. -->
<bookstore>
  <book category="COOKING">
    <title lang="en">Everyday Italian</title>
    <author>Giada De Laurentiis</author>
    <year>2005</year>
    <price>30.00</price>
  </book>
</bookstore>
```
- The DTD file (Bookstore.dtd):
```xml
<!ELEMENT bookstore (book+)>
<!-- The bookstore element may contain one or more child book elements. -->
<!ELEMENT book (title, price)>
<!-- Each book must have a title and a price as its children. -->
<!ATTLIST book category CDATA "Literature">
<!-- A book should have a category attribute. If it doesn't, its default value
  will be 'Literature'. -->
<!ELEMENT title (#PCDATA)>
<!-- The element title must only contain parsed character data. That is, it may
  only contain text which is read by the parser and must not contain children.
  Compare with CDATA, or character data. -->
<!ELEMENT price (#PCDATA)>
```
- The DTD could be declared inside the XML file itself:
```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE bookstore [
<!ELEMENT bookstore (book+)>
<!ELEMENT book (title, price)>
<!ATTLIST book category CDATA "Literature">
<!ELEMENT title (#PCDATA)>
<!ELEMENT price (#PCDATA)>
]>

<bookstore>
  <book category="COOKING">
    <title>Everyday Italian</title>
    <price>30.00</price>
  </book>
</bookstore>
```
### What are XML custom entities?

`<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>` -> any usage of the entity reference `&myentity;` = "`my entity value`"

### What are XML external entities?

ex: `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>` 
-> (file protocol in url): `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>`

-  a type of custom entity whose definition is *located outside* of the DTD
- The declaration of an external entity uses the **`SYSTEM`** keyword
- it must specify a *URL* from which the *value of the entity should be loaded*
- this is where 
/gitcomm