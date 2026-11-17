//go:build linux

package publicipv4

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const discoveryPort = 49190
const wanIPService = "urn:schemas-upnp-org:service:WANIPConnection:1"

// defaultGateway chooses the lowest-metric active IPv4 default route.
func defaultGateway() (netip.Addr, string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, "", err
	}
	defer f.Close()
	return parseDefaultGateway(f)
}
func parseDefaultGateway(r io.Reader) (netip.Addr, string, error) {
	scan := bufio.NewScanner(r)
	var gateway netip.Addr
	var iface string
	var best uint64 = ^uint64(0)
	for scan.Scan() {
		f := strings.Fields(scan.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, e1 := strconv.ParseUint(f[3], 16, 32)
		metric, e2 := strconv.ParseUint(f[6], 10, 32)
		ip, e3 := strconv.ParseUint(f[2], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || flags&3 != 3 || ip == 0 || metric >= best {
			continue
		}
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], uint32(ip))
		gateway, iface, best = netip.AddrFrom4(raw), f[0], metric
	}
	if err := scan.Err(); err != nil {
		return netip.Addr{}, "", err
	}
	if !gateway.IsValid() {
		return netip.Addr{}, "", errors.New("no IPv4 default gateway")
	}
	return gateway, iface, nil
}

func discoverPublicIPv4() (netip.Addr, error) {
	gateway, ifaceName, err := defaultGateway()
	if err != nil {
		return netip.Addr{}, err
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	var local net.IP
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			local = ip.To4()
			break
		}
	}
	if local == nil {
		return netip.Addr{}, errors.New("default interface has no IPv4 address")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local, Port: discoveryPort})
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return netip.Addr{}, err
	}
	request := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if _, err = conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return netip.Addr{}, err
	}
	buf := make([]byte, 8192)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			return netip.Addr{}, err
		}
		peerIP, ok := netip.AddrFromSlice(peer.IP)
		if !ok || peerIP.Unmap() != gateway || peer.Port != 1900 {
			continue
		}
		location, err := parseLocation(string(buf[:n]), gateway)
		if err != nil {
			continue
		}
		ip, err := externalIP(location, gateway)
		if err != nil {
			return netip.Addr{}, err
		}
		current, _, err := defaultGateway()
		if err != nil || current != gateway {
			return netip.Addr{}, errors.New("default gateway changed during discovery")
		}
		return ip, nil
	}
}

func gatewayURL(raw string, gateway netip.Addr) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return nil, errors.New("invalid gateway URL")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Unmap() != gateway {
		return nil, errors.New("URL is not on the default gateway")
	}
	return u, nil
}
func parseLocation(data string, gateway netip.Addr) (*url.URL, error) {
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(data)), nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected SSDP response")
	}
	return gatewayURL(response.Header.Get("Location"), gateway)
}

type device struct {
	Services []struct {
		Type    string `xml:"serviceType"`
		Control string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []device `xml:"deviceList>device"`
}

func (d device) control() string {
	for _, s := range d.Services {
		if s.Type == wanIPService {
			return s.Control
		}
	}
	for _, sub := range d.Devices {
		if result := sub.control(); result != "" {
			return result
		}
	}
	return ""
}
func externalIP(location *url.URL, gateway netip.Addr) (netip.Addr, error) {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(location.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("device description: %s", resp.Status)
	}
	var description struct {
		Device  device `xml:"device"`
		URLBase string `xml:"URLBase"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&description); err != nil {
		return netip.Addr{}, err
	}
	base := location
	if description.URLBase != "" {
		base, err = gatewayURL(description.URLBase, gateway)
		if err != nil {
			return netip.Addr{}, err
		}
	}
	control := description.Device.control()
	if control == "" {
		return netip.Addr{}, errors.New("router has no WANIPConnection service")
	}
	rel, err := url.Parse(control)
	if err != nil {
		return netip.Addr{}, err
	}
	endpoint, err := gatewayURL(base.ResolveReference(rel).String(), gateway)
	if err != nil {
		return netip.Addr{}, err
	}
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint.String(), strings.NewReader(body))
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+wanIPService+`#GetExternalIPAddress"`)
	resp2, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("external IP request: %s", resp2.Status)
	}
	var result struct {
		Body struct {
			Response struct {
				IP string `xml:"NewExternalIPAddress"`
			} `xml:"GetExternalIPAddressResponse"`
		} `xml:"Body"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp2.Body, 1<<20)).Decode(&result); err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(result.Body.Response.IP))
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return netip.Addr{}, errors.New("router returned a non-public IPv4 address")
	}
	return ip, nil
}
