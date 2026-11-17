package publicipv4

import (
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestCacheClearsAfterFailures(t *testing.T) {
	c := &addressCache{address: netip.MustParseAddr("8.8.8.8"), expires: time.Now().Add(time.Minute), next: time.Now().Add(time.Hour), lookup: func() (netip.Addr, error) { return netip.Addr{}, errors.New("offline") }}
	c.refresh()
	if c.get().IsValid() {
		t.Fatal("failed refresh restored stale trust")
	}
}

func TestRejectsEarlyData(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.test", nil)
	r.TLS = &tls.ConnectionState{}
	if _, err := (Matcher{}).MatchWithError(r); err == nil {
		t.Fatal("early data must not bypass authentication")
	}
}
