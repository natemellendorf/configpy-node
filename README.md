# ConfigPy-Node
## Built off of:
[JunosPyEz-OSSH-Server](https://pypi.org/project/junospyez-ossh-server/)

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

### Commands:
Update or omit the network as needed
```
docker run --name configpy-node \
-d -p 9000:9000 \
--network production \
--rm natemellendorf/configpy-node USERNAME PASSWORD REDIS_URI
```

### Review logs from configpy-node:
ConfigPy-Node logs events automatically.
You can review these at the Docker CLI:
```
docker logs configpy-node
```
