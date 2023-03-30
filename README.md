# DynDns2 server for CloudFlare
This is a simple DynDns-server that responds to DynDns2-requests from clients and updates DNS-records through CloudFlare-API.
The server will match requests to known hosts and only forward requests to cloudflare for allowed hosts.
Allowed hosts can be setup using environment variables if only a few hosts are needed or through a yaml file that also allows individual username/password for each host.
It is designed to run as a docker container so all configuration are done through environment variables.

## Setup:
The server uses CloudFlares python library so some variables needs to be set to authenticate to the CloudFlare account

The simplest way to set this up is to generate a API-token from CloudFlare and set the variable ```CLOUDFLARE_API_TOKEN``` to this string.
The token must have read access to Zone/Zone and edit access to Zone/DNS.

```
CLOUDFLARE_API_TOKEN='long-api-token-string'
```

Other ways of authenticating is possible using

```
CLOUDFLARE_EMAIL=''
CLOUDFLARE_API_KEY=''
CLOUDFLARE_API_CERTKEY=''
```

Please see the documentation at https://github.com/cloudflare/python-cloudflare for more information of these settings.


By default the IP the client specifies in the request will be verified with the IP the source IP in the packet the server recieves so the client can't set it's DNS-record to some other IP that it's own IP.
```
VERIFY_SRC_IP=True

VERIFY_SRC_IP=False
```

Both the /ip-function and the source IP verification needs the original IP for the client, by default this will be the source IP from the packets the server recieves.
If a reverse proxy is used in front of the server the IP the server sees will just be the proxy servers IP so the default 'Client' setting will not work. In that case configure the proxy to pass the clients original IP through HTTP-headers, you can use either 'X-REAL-IP' or the 'X-FORWARDED-FOR' header as the source for the client IP.

```
CLIENT_IP_SRC='Client'

CLIENT_IP_SRC='X-REAL-IP'

CLIENT_IP_SRC='X-FORWARDED-FOR'
```

# Simple authentication
In simple authentication every host in the list will have the same client username and password.

```
SIMPLE_AUTH=True 
SIMPLE_HTTP_USER='username'
SIMPLE_HTTP_PASSWORD='password'

or

SIMPLE_AUTH=True 
SIMPLE_HTTP_USER='username'
SIMPLE_HTTP_PASSWORD_HASH='5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
```

Hosts are specified as just one host or a comma separated list of several hosts

```
SIMPLE_HOST_LIST='test.example.com'

or

SIMPLE_HOST_LIST='test1.example.com,test2.example.com,test3.example.com'
```

# File based authentication

To use file based authentication just set the variable to enable it and create a file at /config/hosts.yaml.

```
FILE_AUTH=True
```

In the yaml-file file every host is specified as

```yaml
# Example hosts.yaml-file
---
- host:
  hostname: test1.example.com
  username: user1
  password: password1

- host:
  hostname: test2.example.com
  username: user2
  password: password2

- host:
  hostname: test3.example.com
  username: user3
  password_hash: 5906AC361A137E2D286465CD6588EBB5AC3F5AE955001100BC41577C3D751764
```

Both simple and file authentication can be used at the same time, the server will go through both lists of hosts.

The hashed passwords are created using SHA256 and converted to hexadecimal. One can generate passwords in linux using:

```bash
echo -n 'password' | sha256sum
```
(the -n is super important to supress newline character at the end)