package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateCIDR(t *testing.T) {
	tests := []struct {
		cidr    string
		private bool
		wantErr bool
	}{
		// RFC 1918 ranges and subnets — all private
		{"10.0.0.0/8", true, false},
		{"10.1.2.0/24", true, false},
		{"10.0.0.1/32", true, false},
		{"172.16.0.0/12", true, false},
		{"172.20.0.0/16", true, false},
		{"192.168.0.0/16", true, false},
		{"192.168.1.0/24", true, false},
		// IPv6 ULA (fc00::/7) — private
		{"fc00::/7", true, false},
		{"fd00::/8", true, false},
		{"fd12:3456:789a::/48", true, false},
		// Broad prefix spanning public space — not private
		// 10.0.0.0/2 covers 0.0.0.0–63.255.255.255
		{"10.0.0.0/2", false, false},
		// 172.16.0.0/11 extends beyond 172.31.255.255 into public
		// space (172.32.0.0 is public)
		{"172.16.0.0/11", false, false},
		// Public addresses
		{"8.8.8.8/32", false, false},
		{"1.0.0.0/8", false, false},
		{"0.0.0.0/0", false, false},
		{"2001:db8::/32", false, false},
		// CGNAT (100.64.0.0/10) — not RFC 1918, not private per
		// IsPrivate
		{"100.64.0.0/10", false, false},
		// Invalid CIDR strings
		{"not-a-cidr", false, true},
		{"10.0.0.0/33", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := isPrivateCIDR(tt.cidr)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.private, got)
		})
	}
}
