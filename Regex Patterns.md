# Networking

## IP Addresses

Use the following regular expressions to **match IPv4 addresses** 

### all expressions from `0.0.0.0` to `999.999.999.999`

```r
([0-9]{1,3}[\.]){3}[0-9]{1,3}
```
### only Valid IPv4 Addresses

```r
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```
/gitcomm