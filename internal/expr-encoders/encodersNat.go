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

func (sui *natCmpRulesetStyleTestSuite) Test_TCPDnatAndRedirect() {
	testCases := []struct {
		name     string
		setup    func(ctx *ctx) []irNode
		expected string
	}{
		{
			name: "tcp dport 8080 dnat to 192.168.0.1:8080",
			setup: func(ctx *ctx) []irNode {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "8080"})
				ctx.reg.Set(3, regVal{HumanExpr: "192.168.0.1"})
				ctx.reg.Set(4, regVal{HumanExpr: "8080"})

				protoCmp := &expr.Cmp{
					Register: 1,
					Op:       expr.CmpOpEq,
					Data:     []byte{unix.IPPROTO_TCP},
				}
				dportCmp := &expr.Cmp{
					Register: 2,
					Op:       expr.CmpOpEq,
					Data:     []byte{0x1f, 0x90}, // 8080
				}
				nat := &expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  3,
					RegProtoMin: 4,
				}

				protoIR, _ := (&cmpEncoder{cmp: protoCmp}).EncodeIR(ctx)
				dportIR, _ := (&cmpEncoder{cmp: dportCmp}).EncodeIR(ctx)
				natIR, _ := (&natEncoder{nat: nat}).EncodeIR(ctx)

				return []irNode{protoIR, dportIR, natIR}
			},
			expected: "tcp dport 8080 dnat ip to 192.168.0.1:8080",
		},
		{
			name: "tcp dport 443 redirect to :443",
			setup: func(ctx *ctx) []irNode {
				ctx.reg.Set(1, regVal{HumanExpr: "tcp"})
				ctx.reg.Set(2, regVal{HumanExpr: "443"})
				ctx.reg.Set(3, regVal{HumanExpr: "443"})

				protoCmp := &expr.Cmp{
					Register: 1,
					Op:       expr.CmpOpEq,
					Data:     []byte{unix.IPPROTO_TCP},
				}
				dportCmp := &expr.Cmp{
					Register: 2,
					Op:       expr.CmpOpEq,
					Data:     []byte{0x01, 0xbb}, // 443
				}
				nat := &expr.NAT{
					Type:        NATTypeRedir,
					Family:      unix.NFPROTO_IPV4,
					RegProtoMin: 3,
				}

				protoIR, _ := (&cmpEncoder{cmp: protoCmp}).EncodeIR(ctx)
				dportIR, _ := (&cmpEncoder{cmp: dportCmp}).EncodeIR(ctx)
				natIR, _ := (&natEncoder{nat: nat}).EncodeIR(ctx)

				return []irNode{protoIR, dportIR, natIR}
			},
			expected: "tcp dport 443 redirect ip to :443",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			irs := tc.setup(ctx)

			// Собираем строку
			result := ""
			for i, ir := range irs {
				if ir == nil {
					continue
				}
				if i > 0 {
					result += " "
				}
				result += ir.Format()
			}

			sui.Equal(tc.expected, result)
		})
	}
}

func Test_NatCmpRulesetStyle(t *testing.T) {
	suite.Run(t, new(natCmpRulesetStyleTestSuite))
}
