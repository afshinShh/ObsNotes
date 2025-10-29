# Detect
## Special characters
```
{
}
$
#
@
%)
"
'
|
{{
}}
${
<%
<%=
%>
```

## [Template Expressions - Seclist ](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-expression.txt) :
```
42*42  
{42*42}  
{{42*42}}  
{{{42*42}}}  
#{42*42}  
${42*42}  
<%=42*42 %>  
{{=42*42}}  
{^xyzm42}1764{/xyzm42}  
${donotexists|42*42}  
[[${42*42}]]
```

# Escalate
## [Template Special Vars](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt)

