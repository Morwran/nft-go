package encoders

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type rejectEncoderTestSuite struct {
	suite.Suite
}

func (s *rejectEncoderTestSuite) Test_RejectEncodeIR() {
	testCases := []struct {
		name     string
		reject   *expr.Reject
		expected string
	}{
		{
			name: "tcp reset",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_TCP_RST,
				Code: 0,
			},
			expected: "reject with tcp reset 0",
		},
		{
			name: "icmpv4 (NFPROTO_IPV4)",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMP_UNREACH,
				Code: unix.NFPROTO_IPV4, // = 2
			},
			expected: "reject with icmp 2",
		},
		{
			name: "icmpv6 (NFPROTO_IPV6)",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMP_UNREACH,
				Code: unix.NFPROTO_IPV6, // = 10
			},
			expected: "reject with icmpv6 10",
		},
		{
			name: "icmpx non-port-unreach",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMPX_UNREACH,
				Code: 5,
			},
			expected: "reject with icmpx 5",
		},
		{
			name: "icmpx with port unreachable — silent (empty typeStr)",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMPX_UNREACH,
				Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH, // = 1
			},
			expected: "reject",
		},
		{
			name: "empty reject",
			reject: &expr.Reject{
				Type: 0,
				Code: 0,
			},
			expected: "reject",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &rejectEncoder{reject: tc.reject}
			ir, err := enc.EncodeIR(ctx)
			s.Require().NoError(err)
			s.Equal(tc.expected, ir.Format())
		})
	}
}

func Test_RejectEncoder(t *testing.T) {
	suite.Run(t, new(rejectEncoderTestSuite))
}
