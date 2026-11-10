package hostinfo

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestFilter(t *testing.T) {
	var in []netip.Addr
	for _, s := range []string{"fe80::1%en0", "127.0.0.1", "::1", "2001:db8::5", "192.0.2.10", "169.254.3.4",
		"10.0.0.2", "ff02::1", "0.0.0.0", "10.0.0.2", "::"} {
		in = append(in, netip.MustParseAddr(s))
	}
	got := filter(in)
	want := []string{"10.0.0.2", "192.0.2.10", "2001:db8::5"}
	if !slices.Equal(got, want) {
		t.Errorf("filter = %v, want %v", got, want)
	}

	in = nil
	for i := range 40 {
		in = append(in, netip.MustParseAddr(fmt.Sprintf("10.1.0.%d", i+1)))
	}
	if got := filter(in); len(got) != MaxIPs || got[0] != "10.1.0.1" {
		t.Errorf("cap: %d addresses, first %v", len(got), got)
	}
	if filter(nil) != nil {
		t.Error("no addresses should give nil, so the field is left out")
	}
}

func TestIPsOnThisMachine(t *testing.T) {
	for _, s := range IPs() {
		a := netip.MustParseAddr(s)
		if a.IsLoopback() || a.IsLinkLocalUnicast() {
			t.Errorf("IPs returned %s", s)
		}
	}
}

func TestLocationNeverPrompts(t *testing.T) {
	loc, err := Location(t.Context())
	if loc != nil || !errors.Is(err, ErrNoLocation) || LocationSupport() == "" {
		t.Errorf("Location = %v, %v", loc, err)
	}
}
