# ConfigPy-Node
[![Build Status](https://travis-ci.com/natemellendorf/configpy-node.svg?branch=master)](https://travis-ci.com/natemellendorf/configpy-node)

### Author:
Nate Mellendorf - nate.mellendorf@gmail.com

## Overview:
This project builds off of the JunosPyEZ OpenSSH Server.
When a Junos device checks in, the server will perform a basic get-facts.
Once gathered, it will search for a config file based off the device's serial number.
If found, it will attempt to load that config file (set commands) to the device and perform a diff.
If a diff is detected, it will perform a commit check.
If the commit check passes, it will perform a commit confirm.
After the config is pushed, it will perform a commit check to confirm the changes.
Finally, the server will disconnect the SSH session.
The device will attempt to connect again, and the cycle continues.

### Additional details
The server listens on TCP port 9000.
If a Redis server is provided when the container starts, it will push status updates to it.
These updates are leveraged by the ConfigPy Hub interface, when the ConfigPy container is launched to point at the same Redis server.

### Built off of:
[JunosPyEz-OSSH-Server](https://pypi.org/project/junospyez-ossh-server/)

### Commands:
Update or omit the network flag as needed.
Update USERNAME and PASSWORD with the username and password used to SSH into your Juniper device.
Update the REDIS_URI with the IP address or Docker container name for your Redis server.
```
docker run --name configpy-node \
-d -p 9000:9000 \
--network production \
--rm natemellendorf/configpy-node USERNAME PASSWORD REDIS_URI
```


### Real world example:
For example, let's deploy everything we need to see this in action.

#### Deploy a Redis container
```
docker run --name redis \
-d -p 6379:6379 \
--network production \
--rm redis
```
#### Deploy a ConfigPy-Node container
```
docker run --name configpy-node \
-d -p 9000:9000 \
--network production \
--rm natemellendorf/configpy-node nate P@ssw0rd redis
```
Your Redis and ConfigPy-Node containers would now be connected.
You could confirm this by looking at the logs of the ConfigPy-Node container.
#### Deploy a ConfigPy container
```
docker run --name configpy \
-d -e REDIS_URI=redis \
-p 8080:5000 \
--network production \
--rm natemellendorf/configpy
```
You should be able to browse to the URL of your Docker host to access ConfigPy:
http://<DockerHost>:8080/
  
#### Configure your Juniper device
Remember to permit this traffic inbound on your mgmt interface.
```
set system services outbound-ssh client test device-id test-srx
set system services outbound-ssh client test services netconf
set system services outbound-ssh client test <DockerHost> port 9000
```

### Review logs from configpy-node:
ConfigPy-Node logs events automatically.
You can review these at the Docker CLI:
```
docker logs configpy-node
```
