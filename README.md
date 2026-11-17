# caddy-public-ipv4

A Caddy matcher for requests from the router's public IPv4 address.

```caddyfile
@home public_ipv4
handle @home {
    respond "Hello from home"
}
```

On Linux, it discovers the default gateway through UPnP and asks for its external IPv4 address. UPnP discovery uses UDP port 49190; the firewall must allow replies to that port. It only accepts responses and service URLs from the default gateway.

The address is refreshed every five minutes and expires after ten minutes. If discovery fails, the matcher stops matching until the next successful refresh. Requests never wait for discovery.

This can identify hairpin NAT clients when the router rewrites their source to its public IPv4. It also trusts anyone else whose connection reaches Caddy with that address, including anyone sharing it through carrier-grade NAT. If the router is behind another NAT, its WAN address may not be the internet-facing address.

```sh
xcaddy build --with github.com/fantattitude/caddy-public-ipv4
```
