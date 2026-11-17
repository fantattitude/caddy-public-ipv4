// Package publicipv4 matches a peer against the server's public IPv4 address.
package publicipv4

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() { caddy.RegisterModule(Matcher{}) }

// Matcher checks the direct peer against the recently observed public IPv4.
type Matcher struct{}

func (Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.matchers.public_ipv4", New: func() caddy.Module { return new(Matcher) }}
}
func (m *Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() || d.NextBlock(0) {
			return d.ArgErr()
		}
	}
	return nil
}
func (*Matcher) Provision(caddy.Context) error {
	sharedCache.get()
	return nil
}
func (m Matcher) Match(r *http.Request) bool {
	matched, err := m.MatchWithError(r)
	if err != nil {
		caddyhttp.SetVar(r.Context(), caddyhttp.MatcherErrorVarKey, err)
	}
	return matched
}
func (Matcher) MatchWithError(r *http.Request) (bool, error) {
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete"))
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, nil
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return false, nil
	}
	observed := sharedCache.get()
	return observed.IsValid() && observed == ip, nil
}

// A request never waits for the router. One shared cache is used by
// all matcher instances; a failed refresh clears the trusted address.
type addressCache struct {
	mu         sync.Mutex
	address    netip.Addr
	expires    time.Time
	next       time.Time
	refreshing bool
	lookup     func() (netip.Addr, error)
}

var sharedCache = &addressCache{lookup: discoverPublicIPv4}

func (c *addressCache) get() netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.refreshing && !now.Before(c.next) {
		c.refreshing = true
		go c.refresh()
	}
	if now.Before(c.expires) {
		return c.address
	}
	return netip.Addr{}
}
func (c *addressCache) refresh() {
	ip, err := c.lookup()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshing = false
	now := time.Now()
	if err != nil {
		c.address = netip.Addr{}
		c.expires = time.Time{}
		c.next = now.Add(time.Minute)
		return
	}
	c.address = ip
	c.expires = now.Add(10 * time.Minute)
	c.next = now.Add(5 * time.Minute)
}

var _ caddyfile.Unmarshaler = (*Matcher)(nil)
var _ caddy.Provisioner = (*Matcher)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Matcher)(nil)
