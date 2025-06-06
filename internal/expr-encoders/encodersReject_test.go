package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type rejectEncoderViaRuleTestSuite struct {
	suite.Suite
}

func (s *rejectEncoderViaRuleTestSuite) Test_RejectEncodeViaRuleEncoder() {
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
				Code: unix.NFPROTO_IPV4,
			},
			expected: "reject with icmp 2",
		},
		{
			name: "icmpv6 (NFPROTO_IPV6)",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMP_UNREACH,
				Code: unix.NFPROTO_IPV6,
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
			name: "icmpx with port unreachable — silent",
			reject: &expr.Reject{
				Type: unix.NFT_REJECT_ICMPX_UNREACH,
				Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
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
			rule := &nftables.Rule{
				Exprs: []expr.Any{
					tc.reject,
				},
			}
			str, err := NewRuleExprEncoder(rule).Format()
			s.Require().NoError(err)
			s.Equal(tc.expected, str)
		})
	}
}

func Test_RejectEncoderViaRule(t *testing.T) {
	suite.Run(t, new(rejectEncoderViaRuleTestSuite))
}
