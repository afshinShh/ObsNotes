
- I haven't include one-file scripts (.py/.sh/etc)
## asciinema
```shell
sudo pip3 install asciinema
```

# go 

```shell
apt install go 
nano ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
source ~/.bashrc
```
# karma v2

### [1. Clone the repo](https://github.com/Dheerajmadhukar/karma_v2#1-clone-the-repo)

```shell
git clone https://github.com/Dheerajmadhukar/karma_v2.git
```

### [2. Install shodan & mmh3 python module](https://github.com/Dheerajmadhukar/karma_v2#2-install-shodan--mmh3-python-module)

```shell
python3 -m pip install shodan mmh3
```

### [3. Install JSON Parser [JQ]](https://github.com/Dheerajmadhukar/karma_v2#3-install-json-parser-jq)

```shell
apt install jq -y
```

### [4. Install httprobe](https://github.com/Dheerajmadhukar/karma_v2#4-install-httprobe-tomnomnom-to-probe-the-requests) [@tomnomnom](https://github.com/tomnomnom/httprobe) to probe the requests

```shell
go install -v github.com/tomnomnom/httprobe@master
```

### [5. Install Interlace](https://github.com/Dheerajmadhukar/karma_v2#5-install-interlace-codingo-to-multithread-follow-the-codingo-interlace-repo-instructions) [@codingo](https://github.com/codingo/Interlace.git) to multithread Follow the codingo interlace repo instructions

```shell
git clone https://github.com/codingo/Interlace.git
cd Interlace/ 
python3 setup.py install
```

### [6. Install nuclei](https://github.com/Dheerajmadhukar/karma_v2#6-install-nuclei-projectdiscovery) [@projectdiscovery](https://github.com/projectdiscovery/nuclei)

```shell
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### [7. Install lolcat](https://github.com/Dheerajmadhukar/karma_v2#7-install-lolcat)

```shell
apt install lolcat -y
```
### [8. Install anew](https://github.com/Dheerajmadhukar/karma_v2#8-install-anew)

```shell
go install -v github.com/tomnomnom/anew@master
```

# wtfis

```bash
pip install wtfis
```

wtfis uses these environment variables:

- [x]  `VT_API_KEY` (required) - Virustotal API key 
- [ ] `PT_API_KEY` (optional) - Passivetotal API key
- [ ] `PT_API_USER` (optional) - Passivetotal API user
- [ ] `IP2WHOIS_API_KEY` (optional) - IP2WHOIS API key
- [ ] `SHODAN_API_KEY` (optional) - Shodan API key
- [ ] `GREYNOISE_API_KEY` (optional) - Greynoise API key
- [ ] `WTFIS_DEFAULTS` (optional) - Default arguments

Set these using your own method.

Alternatively, create a file in your home directory `~/.env.wtfis` with the above declarations. See [.env.wtfis.example](https://github.com/pirxthepilot/wtfis/blob/main/.env.wtfis.example) for a template. **NOTE: Don't forget to `chmod 400` the file!**
# shosubgo 
### Get your shodan api FREE with limit usage

[https://developer.shodan.io/api/requirements](https://developer.shodan.io/api/requirements)

### Install

```shell
$ go install github.com/incogbyte/shosubgo@latest
# verify inside your $GOPATH the folder "bin"
```

### basic usage

```shell
go run main.go -d target.com -s YourAPIKEY
```

# #todo BBRF client and server
# #todo SubGPT 

#  GoSpider

### [GO install](https://github.com/jaeles-project/gospider#go-install)

```
GO111MODULE=on go install github.com/jaeles-project/gospider@latest
```

### [Docker](https://github.com/jaeles-project/gospider#docker)

```shell
# Clone the repo
git clone https://github.com/jaeles-project/gospider.git
# Build the contianer
docker build -t gospider:latest gospider
# Run the container
docker run -t gospider -h
```

# hackrawler

### [Normal Install](https://github.com/hakluke/hakrawler#normal-install)

```shell
go install github.com/hakluke/hakrawler@latest
```
### [Docker Install (from dockerhub)](https://github.com/hakluke/hakrawler#docker-install-from-dockerhub)

```shell
echo https://www.google.com | docker run --rm -i hakluke/hakrawler:v2 -subs
```

### [Local Docker Install](https://github.com/hakluke/hakrawler#local-docker-install)

```shell
git clone https://github.com/hakluke/hakrawler
cd hakrawler
sudo docker build -t hakluke/hakrawler .
sudo docker run --rm -i hakluke/hakrawler --help
```
### basic usage

```shell
echo https://www.google.com | docker run --rm -i hakluke/hakrawler -subs
	```

# subfinder

```shell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

# amass

```shell
go install -v github.com/owasp-amass/amass/v4/...@master
```

# BBOT

```shell
python3 -m pip install --user pipx
```

```shell
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot

bbot --help
```

# github_subdomains

## [Install](https://github.com/gwen001/github-subdomains#install)

```shell
go install github.com/gwen001/github-subdomains@latest
```

or

```shell
git clone https://github.com/gwen001/github-subdomains
cd github-subdomains
go install
```


# github-search
## [Install](https://github.com/gwen001/github-search#install)

```shell
git clone https://github.com/gwen001/github-search
cd github-search
pip3 install -r requirements.txt
```

Most of the time GitHub requires a token to perform searches.

You can create a `.tokens` file in the cloned repo directory with 1 token per line  
OR  
You can configure an environment variable (recommended) like this: `GIHTHUB_TOKEN=token1,token2,...`


# puredns

## Prerequisites

### [massdns](https://github.com/d3mondev/puredns#massdns)

Puredns requires massdns on the host machine. If the path to the massdns binary is present in the PATH environment variable, puredns will work out of the box. A good place to copy the massdns executable is `/usr/local/bin` on most systems. Otherwise, you will need to specify the path to the massdns binary file using the `--bin` command-line argument.

The following should work on most Debian based systems. [Follow the official instructions](https://github.com/blechschmidt/massdns#compilation) for more information.

```shell
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install
```

### [List of public DNS resolver servers](https://github.com/d3mondev/puredns#list-of-public-dns-resolver-servers) #todo

You need to obtain a list of public DNS servers in order to use puredns. [Refer to the FAQ](https://github.com/d3mondev/puredns#how-do-i-get-resolvers-for-use-with-puredns) to learn how to curate your own list of working servers.
## Installation

- You can [download a binary release](https://github.com/d3mondev/puredns/releases).

or just:
```shell
go install github.com/d3mondev/puredns/v2@latest
```

# dnsgen

`pip3 install dnsgen`

..or from GitHub directly:

```shell
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
python3 setup.py install
```

# EyeWitness

```shell
git clone https://github.com/RedSiege/EyeWitness
cd EyeWitness/Python/setup 
sudo ./setup.sh
```


# FavFreak
### installation

```shell
git clone https://github.com/devanshbatham/FavFreak
python3 -m pip install mmh3
```
### basic usage 

```shell
cd FavFreak
cat urls.txt | python3 favfreak.py -o output
#Note : URLs must begin with either http or https
```
/gitco