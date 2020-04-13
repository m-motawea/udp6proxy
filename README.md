# udp6proxy
Proxy UDP Traffic from IPv4 to IPv6 for WireGuard IPv6 Endpoints

# Build
```bash
$ go get github.com/m-motawea/udp6proxy
$ # Replace $GOPATH with ~/go if you didn't set it
$ cd $GOPATH/src/github.com/m-motawea/udp6proxy
$ go build
$ sudo cp upd6proxy /usr/bin/
```
# Running
Example configuration file
```toml
[Redis]
Address = "127.0.0.1"
Port = 6379
Password = ""
DB = 0
Prefix = ""
Update = 60

[[Endpoint]]
Name = "wg0"
RemoteAddress = "2604:a8:40:d0::1875:7102"
RemotePort = 23456
LocalPort = 12345
WireGuard = true

[[Endpoint]]
Name = "wg1"
RemoteAddress = "2704:b881:40:fe::1875:7002"
RemotePort = 23457
LocalPort = 12346
WireGuard = true
```
Then ```udp6proxy config.toml```

Please notice if you are using low numbered port like 80 or 443 you can use sudo or setcap before running the binary.

```sudo setcap CAP_NET_BIND_SERVICE=+eip udp6proxy```

Also, You need to run the server on a dual stack machine.

# config.toml
### [Redis]
define redis configuration which can be used to read endpoints configuration. ```Update``` is time in seconds before reloading the configuration from Redis.

### [[Endpoint]]
define the proxy settings for an endpoint.
  - ```Name```: must be unique to avoid overwriting configuration. it used as redis key.
  - ```RemoteAddress```: IPv6 address you need to proxy to. (the endpoint IP of wireguard peer)
  - ```RemotPort```: Port of the destination machine. (the endpoint port of wireguard peer)
  - ```LocalPort```: The server will listen on this port and proxy traffic to the remote IPv6 node.
  - ```WireGuard```: If set to true, the server will drop non-wireguard traffic.

# Data Representation in Redis:
```bash
127.0.0.1:6379> keys *
1) "wg0"
2) "wg1"
127.0.0.1:6379> get wg0
"{\"Name\":\"wg0\",\"WireGuard\":true,\"RemoteAddress\":\"::1\",\"RemotePort\":23456,\"LocalPort\":12345}"
```
