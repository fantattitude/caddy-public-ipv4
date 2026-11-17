//go:build !linux

package publicipv4

import (
	"errors"
	"net/netip"
)

func discoverPublicIPv4() (netip.Addr, error) {
	return netip.Addr{}, errors.New("public_ipv4 requires Linux")
}
