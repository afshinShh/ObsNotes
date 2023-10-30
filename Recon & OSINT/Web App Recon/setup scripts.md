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

### Usage

```shell
go run main.go -d target.com -s YourAPIKEY
```

# #todo BBRF client and server

