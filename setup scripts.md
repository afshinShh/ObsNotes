
- I haven't include one-file scripts (.py/.sh/etc)
## asciinema 

-> for recording the screen (commandline)

```shell
sudo pip3 install asciinema
```

# Zsh

1. There are two main ways to install Zsh:
    
    - With the package manager of your choice, _e.g._ `sudo apt install zsh` (see [below for more examples](https://github.com/ohmyzsh/ohmyzsh/wiki/Installing-ZSH#how-to-install-zsh-on-many-platforms))
    - From [source](https://zsh.sourceforge.io/Arc/source.html), 
2. Verify installation ->  `zsh --version`
    
3. Make it your default shell: `chsh -s $(which zsh)` or use `sudo lchsh $USER` if you are on Fedora.
    
    - Note that this will not work if Zsh is not in your authorized shells list (`/etc/shells`) or if you don't have permission to use `chsh`. If that's the case [you'll need to use a different procedure](https://www.google.com/search?q=zsh+default+without+chsh).
    - If you use `lchsh` you need to type `/bin/zsh` to make it your default shell.
4. Log out and log back in again to use your new default shell.
    
5. Test that it worked with `echo $SHELL`. Expected result: `/bin/zsh` or similar.
    
6. Test with `$SHELL --version`. Expected result: 'zsh 5.8' or similar

# go 

```shell
apt install go 
nano ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
source ~/.bashrc
```

# Rust
### **Installing Rust directly**

```bash
sudo pacman -Sy rust
```

### **Installing Rust via Rustup**

```bash
# Download and install Rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Configure the PATH environment variable
source $HOME/.cargo/env

# Test the installation
rustc --version
```

# rustscan 
### using cargo

- you need to install <mark style="background: #FFF3A3A6;">rust</mark> and <mark style="background: #D2B3FFA6;">nmap</mark> first
```shell 
cargo install rustscan
```
### using docker(recommended)

the guide is [here](https://github.com/RustScan/RustScan/wiki/Installation-Guide#docker-) ( #todo make it summarized)

# metasploit & searchsploit
## metasploit

   ```shell
   sudo apt install -y build-essential zlib1g zlib1g-dev libpq-dev libpcap-dev libsqlite3-dev ruby ruby-dev git
   git clone https://github.com/rapid7/metasploit-framework.git
   cd metasploit-framework/
   sudo gem install bundler
   bundle install
   ```
## searchsploit

```shell
sudo apt update
sudo apt install snapd
sudo snap install searchsploit
```
/git
--- 
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

---

# webanalyze

```shell
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
webanalyze -update # loads new technologies.json file from wappalyzer project
```

- #todo -> -update doesn't work recently due to update in  wapplyzer's repository so you need to figure it out later 
  
# nuclei

```shell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Brew

```shell
brew install nuclei
```

Docker

```shell
docker pull projectdiscovery/nuclei:latest
```

**More installation [methods can be found here](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

## CENT - nuclei community edition

```shell
go install -v github.com/xm1k3/cent@latest
```

## AllForOne - Nuclei Template Collector

1. Clone the repository: `git clone https://github.com/AggressiveUser/AllForOne.git` 💻
    
2. Install the required dependencies: `pip install -r requirements.txt` 🔑
    
3. Run the script: `python AllForOne.py` 🐍
    
4. Sit back and relax! The script will start collecting the Nuclei templates from public repositories.

# jaeles

## [Installation](https://github.com/jaeles-project/jaeles#installation)

```shell
go install github.com/jaeles-project/jaeles@latest
```

 - [**Note**: Checkout](https://github.com/jaeles-project/jaeles#note-checkout-signatures-repo-for-install-signature) [Signatures Repo](https://github.com/jaeles-project/jaeles-signatures) for install signature.

# ffuf

- [Download](https://github.com/ffuf/ffuf/releases/latest) a prebuilt binary from [releases page](https://github.com/ffuf/ffuf/releases/latest), unpack and run!
    
    _or_
    
- If you are on macOS with [homebrew](https://brew.sh), ffuf can be installed with: `brew install ffuf`
    
    _or_
    
- If you have recent go compiler installed: `go install github.com/ffuf/ffuf/v2@latest` (the same command works for updating)
    
    _or_
    
- `git clone https://github.com/ffuf/ffuf ; cd ffuf ; go get ; go build`
# SecLists

### Zip

```
wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip \
  && unzip SecList.zip \
  && rm -f SecList.zip
```

### Git (Small)

```
git clone --depth 1 \
  https://github.com/danielmiessler/SecLists.git
```

### Git (Complete)

```
git clone https://github.com/danielmiessler/SecLists.git
```

### Kali Linux ([Tool Page](https://www.kali.org/tools/seclists/))

```
apt -y install seclists
```
# assetnote.io

```shell
wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -e robots=off
```
# WayMore


```shell
git clone https://github.com/xnl-h4ck3r/waymore.git
cd waymore
sudo python setup.py install
```

if you're having a problem running the **`setup.py`** for whatever reason you can run the following to install the dependencies:

```shell
sudo pip3 install -r requirements.txt
```

# APKLeaks
### [from PyPi](https://github.com/dwisiswant0/apkleaks#from-pypi)

```shell
pip3 install apkleaks
```

### [from Source](https://github.com/dwisiswant0/apkleaks#from-source)

Clone repository and install requirements:

```shell
git clone https://github.com/dwisiswant0/apkleaks
cd apkleaks/
pip3 install -r requirements.txt
```

# GAP (burp extension)

### [Installation](https://github.com/xnl-h4ck3r/GAP-Burp-Extension#installation)

1. Visit [Jython Offical Site](https://www.jython.org/download), and download the latest stand alone JAR file, e.g. `jython-standalone-2.7.3.jar`.
2. Open Burp, go to **Extensions** -> **Extension Settings** -> **Python Environment**, set the **Location of Jython standalone JAR file** and **Folder for loading modules** to the directory where the Jython JAR file was saved.
3. On a command line, go to the directory where the jar file is and run `java -jar jython-standalone-2.7.3.jar -m ensurepip`.
4. Download the `GAP.py` and `requirements.txt` from this project and place in the same directory.
5. Install Jython modules by running `java -jar jython-standalone-2.7.3.jar -m pip install -r requirements.txt`.
6. Go to the **Extensions** -> **Installed** and click **Add** under **Burp Extensions**.
7. Select **Extension type** of **Python** and select the **GAP.py** file.

# JS Miner(burp extension)

- download from BApp Store [portswigger official page](https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b




