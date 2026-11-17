# caddy-public-ipv4

A Caddy matcher for requests from the server's public IPv4 address.

```caddyfile
@home public_ipv4
handle @home {
    respond "Hello from home"
}
```

It checks the direct connection address. Two external services independently report the server's public IPv4, and their answers must agree. Results are refreshed every five minutes and expire after ten minutes. If discovery fails, the last result is used until it expires; afterward the matcher stops matching. Requests never wait for discovery.

This can identify hairpin NAT clients when the router rewrites their source to the public IPv4. It also trusts anyone else whose connection reaches Caddy with the same source address, including anyone sharing that address through carrier-grade NAT. The discovery services see the server's public address and their hostnames need DNS resolution.

Build Caddy with the matcher:

```sh
xcaddy build --with github.com/fantattitude/caddy-public-ipv4
```
