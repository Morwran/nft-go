package encoders

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type natCmpRulesetStyleTestSuite struct {
	suite.Suite
}

func (sui *natCmpRulesetStyleTestSuite) Test_TCPNATRules() {
	testCases := []struct {
		name     string
		setup    func(ctx *ctx) []expr.Any
		expected string
	}{
		{
			name: "tcp dport 8080 dnat to 192.168.0.1:8080",
			setup: func(ctx *ctx) []expr.Any {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "8080"})
				ctx.reg.Set(3, regVal{HumanExpr: "192.168.0.1"})
				ctx.reg.Set(4, regVal{HumanExpr: "8080"})

				return []expr.Any{
					&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
					&expr.Cmp{Register: 2, Op: expr.CmpOpEq, Data: []byte{0x1f, 0x90}},
					&expr.NAT{
						Type:        expr.NATTypeDestNAT,
						Family:      unix.NFPROTO_IPV4,
						RegAddrMin:  3,
						RegProtoMin: 4,
					},
				}
			},
			expected: "tcp dport 8080 dnat ip to 192.168.0.1:8080",
		},
		{
			name: "tcp dport 443 redirect to :443",
			setup: func(ctx *ctx) []expr.Any {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "443"})
				ctx.reg.Set(3, regVal{HumanExpr: "443"})

				return []expr.Any{
					&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
					&expr.Cmp{Register: 2, Op: expr.CmpOpEq, Data: []byte{0x01, 0xbb}},
					&expr.NAT{
						Type:        NATTypeRedir,
						Family:      unix.NFPROTO_IPV4,
						RegProtoMin: 3,
					},
				}
			},
			expected: "tcp dport 443 redirect ip to :443",
		},
		{
			name: "ip protocol tcp masquerade to :1000 random",
			setup: func(ctx *ctx) []expr.Any {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "1000"})

				return []expr.Any{
					&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
					&expr.NAT{
						Type:        NATTypeMASQ,
						Family:      unix.NFPROTO_IPV4,
						RegProtoMin: 2,
						Random:      true,
					},
				}
			},
			expected: "ip protocol tcp masquerade to :1000 random",
		},
		{
			name: "tcp dport 5000 snat to 10.0.0.1-10.0.0.10:1000-2000",
			setup: func(ctx *ctx) []expr.Any {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "5000"})
				ctx.reg.Set(3, regVal{HumanExpr: "10.0.0.1"})
				ctx.reg.Set(4, regVal{HumanExpr: "10.0.0.10"})
				ctx.reg.Set(5, regVal{HumanExpr: "1000"})
				ctx.reg.Set(6, regVal{HumanExpr: "2000"})

				return []expr.Any{
					&expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{unix.IPPROTO_TCP}},
					&expr.Cmp{Register: 2, Op: expr.CmpOpEq, Data: []byte{0x13, 0x88}},
					&expr.NAT{
						Type:        expr.NATTypeSourceNAT,
						Family:      unix.NFPROTO_IPV4,
						RegAddrMin:  3,
						RegAddrMax:  4,
						RegProtoMin: 5,
						RegProtoMax: 6,
					},
				}
			},
			expected: "tcp dport 5000 snat ip to 10.0.0.1-10.0.0.10:1000-2000",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			exprs := tc.setup(ctx)
			result := ""
			for i, ex := range exprs {
				var ir irNode
				var err error
				switch e := ex.(type) {
				case *expr.Cmp:
					ir, err = (&cmpEncoder{cmp: e}).EncodeIR(ctx)
				case *expr.NAT:
					ir, err = (&natEncoder{nat: e}).EncodeIR(ctx)
				}
				sui.Require().NoError(err)
				if i > 0 {
					result += " "
				}
				result += ir.Format()
			}
			sui.T().Logf("EXPECTED: %s", tc.expected)
			sui.T().Logf("ACTUAL:   %s", result)

			sui.Equal(tc.expected, result)
		})
	}
}

func Test_NatCmpRulesetStyle(t *testing.T) {
	suite.Run(t, new(natCmpRulesetStyleTestSuite))
}
