package publicipv4

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type mockTransport struct{}

func (mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := "8.8.8.8\n"
	if r.URL.Host == "two.test" {
		body = "1.1.1.1\n"
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func TestLookupRequiresAgreement(t *testing.T) {
	client := &http.Client{Transport: mockTransport{}}
	if ip, err := lookupAgreement(client, []string{"https://one.test", "https://one.test"}); err != nil || ip.String() != "8.8.8.8" {
		t.Fatalf("agreement: %v %v", ip, err)
	}
	if _, err := lookupAgreement(client, []string{"https://one.test", "https://two.test"}); err == nil {
		t.Fatal("disagreement must fail")
	}
}

func TestCacheExpiresAfterFailures(t *testing.T) {
	c := &addressCache{address: netip.MustParseAddr("8.8.8.8"), expires: time.Now().Add(-time.Second), next: time.Now().Add(time.Hour), lookup: func() (netip.Addr, error) { return netip.Addr{}, errors.New("offline") }}
	if c.get().IsValid() {
		t.Fatal("expired address is still trusted")
	}
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
