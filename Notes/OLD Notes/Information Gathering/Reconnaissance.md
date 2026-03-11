.# spiders
- _gpt written script_  -> test first 
```bash
#!/bin/bash

# Run GoSpider, Hakrawler, and Katana on the specified URL
url="https://example.com"
gosSpiderOutput=$(gospider -s "$url" -o gospider_output)
hakrawlerOutput=$(hakrawler -url "$url" -plain hakrawler_output)
katanaOutput=$(katana --url "$url" --output katana_output)

# Extract URLs from the outputs
gospiderUrls=$(cat gospider_output | grep "URL" | awk '{print $5}')
hakrawlerUrls=$(cat hakrawler_output | grep "$url" | awk '{print $1}')
katanaUrls=$(cat katana_output/*.txt | grep -ioE 'href="([^"#]+)"' | cut -d'"' -f2)

# Combine all URLs into a single list
allUrls=$(echo -e "$gospiderUrls\n$hakrawlerUrls\n$katanaUrls")

# Sort and remove duplicates from the list
sortedUniqueUrls=$(echo "$allUrls" | sort -u)

# Print the final sorted and unique list of URLs
echo "$sortedUniqueUrls"
```

## GoSpider

 - issue for -q flag still isn't quiet `grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*"`

### oneliner -> json
```shell
gospider -S sites.txt —json | grep “{” | jq -r ‘.output’

### collect js files from hosts up by gospider

xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```
### .js gau + wayback + gospider and makes an analysis of the js. tools you need below.


```shell
cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> AliveJs.txt ; xargs -a AliveJs.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat AliveJs.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'
```

## hakrawler
## katana


