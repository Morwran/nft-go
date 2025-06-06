package encoders

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type exthdrEncoderTestSuite struct {
	suite.Suite
}

func (sui *exthdrEncoderTestSuite) Test_ExthdrEncodeIR_ValidOnly() {
	testCases := []struct {
		name     string
		exthdr   *expr.Exthdr
		regSetup func(ctx *ctx)
		expected string
	}{
		{
			name: "tcp option present → store to register",
			exthdr: &expr.Exthdr{
				Op:           expr.ExthdrOpTcpopt,
				Type:         2,
				Flags:        unix.NFT_EXTHDR_F_PRESENT,
				DestRegister: 1,
			},
			expected: "", // EncodeIR вернёт nil, ErrNoIR
		},
		{
			name: "ipv6 option present → store to register",
			exthdr: &expr.Exthdr{
				Op:           expr.ExthdrOpIpv6,
				Type:         1,
				Flags:        unix.NFT_EXTHDR_F_PRESENT,
				DestRegister: 2,
			},
			expected: "", // тоже вернёт nil, ErrNoIR
		},
		{
			name: "exthdr read and compare (source + rhs)",
			exthdr: &expr.Exthdr{
				Type:           4,
				Offset:         8,
				Len:            2,
				SourceRegister: 3,
			},
			regSetup: func(ctx *ctx) {
				ctx.reg.Set(3, regVal{HumanExpr: "0x1234"})
			},
			expected: "exthdr @4,8,2 set 0x1234",
		},
	}

	for _, tc := range testCases {
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

func Test_ExthdrEncoder(t *testing.T) {
	suite.Run(t, new(exthdrEncoderTestSuite))
}
