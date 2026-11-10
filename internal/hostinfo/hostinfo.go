// Package hostinfo gathers what an organisation's policy may ask the installed
// service to add to its report beyond the check results: the machine's own IP
// addresses and, where the OS can give one without asking anybody, its
// location. Nothing here goes online: the receiver sees the public address of
// the connection by itself.
package hostinfo

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"

	"github.com/ptrinh/bordercheck/internal/report"
)

// MaxIPs caps how many addresses a report carries; a laptop with Docker,
// VPNs and virtual machines can have dozens.
const MaxIPs = 16

// IPs returns the addresses of this machine's interfaces that are up, IPv4
// first, without loopback, link-local, multicast or unspecified addresses,
// sorted and capped at MaxIPs. nil when there are none.
func IPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					addrs = append(addrs, ip.Unmap())
				}
			}
		}
	}
	return filter(addrs)
}

func filter(addrs []netip.Addr) []string {
	var keep []netip.Addr
	for _, a := range addrs {
		a = a.WithZone("")
		if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		keep = append(keep, a)
	}
	slices.SortFunc(keep, func(a, b netip.Addr) int { return a.Compare(b) }) // IPv4 sorts before IPv6
	keep = slices.Compact(keep)
	if len(keep) > MaxIPs {
		keep = keep[:MaxIPs]
	}
	var out []string
	for _, a := range keep {
		out = append(out, a.String())
	}
	return out
}

// ErrNoLocation is returned where the OS cannot give a position without a
// permission prompt, admin rights or a request to a third party.
var ErrNoLocation = errors.New("location is not available")

// Location returns the device position when the OS can supply one under
// bordercheck's rules: no permission prompt, no admin rights, no third-party
// network request. No OS meets them today (see LocationSupport), so it always
// returns ErrNoLocation and the report carries no location; the receiver can
// still estimate one from the connection's public IP.
func Location(context.Context) (*report.Location, error) {
	return nil, ErrNoLocation
}

// LocationSupport says, for bordercheck status and the docs, why this OS gives
// no location.
func LocationSupport() string {
	switch runtime.GOOS {
	case "darwin":
		return "not available on macOS: Core Location needs an app bundle and a Location Services prompt"
	case "windows":
		return "not available on Windows: since 24H2 a desktop program reading the location API can raise a prompt"
	case "linux":
		return "not available on Linux: GeoClue can prompt through the desktop's agent and look nearby Wi-Fi up online"
	}
	return "not available on " + runtime.GOOS
}
