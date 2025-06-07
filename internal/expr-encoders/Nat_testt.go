package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type natIRExprTestSuite struct {
	suite.Suite
}

func (sui *natIRExprTestSuite) Test_NATEncodeIR_ExprBased() {
	testCases := []struct {
		name     string
		exprs    []expr.Any
		expected string
	}{
		{
			name: "tcp dport 8080 dnat to 192.168.0.1:8080",
			exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{0x1f, 0x90}}, // 8080
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  2,
					RegProtoMin: 3,
				},
			},
			expected: "tcp dport 8080 dnat ip to 192.168.0.1:8080",
		},
		{
			name: "tcp dport 443 redirect to :443",
			exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{0x01, 0xbb}}, // 443
				&expr.NAT{
					Type:        NATTypeRedir,
					Family:      unix.NFPROTO_IPV4,
					RegProtoMin: 2,
				},
			},
			expected: "tcp dport 443 redirect ip to :443",
		},
		{
			name: "ip protocol tcp masquerade to :1000 random",
			exprs: []expr.Any{
				&expr.NAT{
					Type:        NATTypeMASQ,
					Family:      unix.NFPROTO_IPV4,
					RegProtoMin: 1,
					Random:      true,
				},
			},
			expected: "ip protocol tcp masquerade to :1000 random",
		},
		{
			name: "tcp dport 5000 snat to 10.0.0.1-10.0.0.10:1000-2000",
			exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{0x13, 0x88}}, // 5000
				&expr.NAT{
					Type:        expr.NATTypeSourceNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  2,
					RegAddrMax:  3,
					RegProtoMin: 4,
					RegProtoMax: 5,
				},
			},
			expected: "tcp dport 5000 snat ip to 10.0.0.1-10.0.0.10:1000-2000",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rule := &nftables.Rule{
				Exprs: tc.exprs,
			}
			str, err := NewRuleExprEncoder(rule).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, str)
		})
	}
}

func Test_NATEncodeIR_ExprBased(t *testing.T) {
	suite.Run(t, new(natIRExprTestSuite))
}
