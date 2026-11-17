//go:build linux

package publicipv4

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDefaultGateway(t *testing.T) {
	routes := "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 100 00000000\neth1 00000000 0101A8C0 0003 0 0 10 00000000\n"
	ip, name, err := parseDefaultGateway(strings.NewReader(routes))
	if err != nil || ip.String() != "192.168.1.1" || name != "eth1" {
		t.Fatalf("gateway: %v %s %v", ip, name, err)
	}
}
func TestOnlyGatewayLocation(t *testing.T) {
	gw := netip.MustParseAddr("10.0.0.1")
	for _, test := range []struct {
		url   string
		valid bool
	}{{"http://10.0.0.1:1900/igd.xml", true}, {"http://10.0.0.2/igd.xml", false}, {"http://10.0.0.1.evil.test/", false}, {"http://evil@10.0.0.1/", false}, {"https://10.0.0.1/", false}} {
		_, err := gatewayURL(test.url, gw)
		if (err == nil) != test.valid {
			t.Errorf("%s: %v", test.url, err)
		}
	}
}
func TestParseLocation(t *testing.T) {
	gw := netip.MustParseAddr("10.0.0.1")
	for _, tc := range []struct {
		response string
		valid    bool
	}{
		{"HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1:1900/igd.xml\r\n\r\n", true},
		{"HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.2:1900/igd.xml\r\n\r\n", false},
		{"HTTP/1.1 404 Not Found\r\nLOCATION: http://10.0.0.1/igd.xml\r\n\r\n", false},
	} {
		_, err := parseLocation(tc.response, gw)
		if (err == nil) != tc.valid {
			t.Errorf("response %q: %v", tc.response, err)
		}
	}
}
func TestDeviceServiceDiscovery(t *testing.T) {
	d := device{Devices: []device{{Devices: []device{{Services: []struct {
		Type    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	}{{Type: wanIPService, Control: "/ipc"}}}}}}}
	if d.control() != "/ipc" {
		t.Fatal("nested control URL not found")
	}
}
