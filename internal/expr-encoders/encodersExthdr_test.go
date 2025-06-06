package encoders

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type exthdrIRTestSuite struct {
	suite.Suite
}

func (sui *exthdrIRTestSuite) Test_ExthdrEncodeIR() {
	testData := []struct {
		name     string
		exthdr   *expr.Exthdr
		regSetup func(ctx *ctx)
		expected string
	}{
		{
			name: "read IPv6 option into register (no IR)",
			exthdr: &expr.Exthdr{
				Op:           expr.ExthdrOpIpv6,
				Type:         1,
				Flags:        unix.NFT_EXTHDR_F_PRESENT,
				DestRegister: 1,
			},
			expected: "",
		},
		{
			name: "compare with RHS via register (ip option)",
			exthdr: &expr.Exthdr{
				Op:             expr.ExthdrOpIpv6,
				Type:           5,
				Offset:         12,
				Len:            1,
				SourceRegister: 3,
			},
			regSetup: func(ctx *ctx) {
				ctx.reg.Set(3, regVal{HumanExpr: "0xab"})
			},
			expected: "ip option @5,12,1 set 0xab",
		},
		{
			name: "compare with RHS via register (tcp option)",
			exthdr: &expr.Exthdr{
				Op:             expr.ExthdrOpTcpopt,
				Type:           2,
				Offset:         4,
				Len:            1,
				SourceRegister: 4,
			},
			regSetup: func(ctx *ctx) {
				ctx.reg.Set(4, regVal{HumanExpr: "0x42"})
			},
			expected: "tcp option @2,4,1 set 0x42",
		},
		{
			name: "unknown Op → fallback to exthdr",
			exthdr: &expr.Exthdr{
				Op:             99,
				Type:           9,
				Offset:         1,
				Len:            1,
				SourceRegister: 5,
			},
			regSetup: func(ctx *ctx) {
				ctx.reg.Set(5, regVal{HumanExpr: "value"})
			},
			expected: "exthdr @9,1,1 set value",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			if tc.regSetup != nil {
				tc.regSetup(ctx)
			}
			enc := &exthdrEncoder{extdhdr: tc.exthdr}
			ir, err := enc.EncodeIR(ctx)

			if tc.expected == "" {
				sui.Require().ErrorIs(err, ErrNoIR)
				sui.Require().Nil(ir)
			} else {
				sui.Require().NoError(err)
				sui.Require().Equal(tc.expected, ir.Format())
			}
		})
	}
}

func Test_ExthdrEncodeIR(t *testing.T) {
	suite.Run(t, new(exthdrIRTestSuite))
}
