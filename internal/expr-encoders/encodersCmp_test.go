package encoders

import (
	"testing"

	"github.com/Morwran/nft-go/pkg/protocols"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type cmpEncoderAdvancedTestSuite struct {
	suite.Suite
}

func (sui *cmpEncoderAdvancedTestSuite) Test_CmpEncodeIR() {
	testCases := []struct {
		name     string
		setup    func(ctx *ctx) *expr.Cmp
		expected string
	}{
		{
			name: "ct state != established",
			setup: func(ctx *ctx) *expr.Cmp {
				ct := &expr.Ct{Key: expr.CtKeySTATE, Register: 1}
				ctx.reg.Set(1, regVal{
					HumanExpr: "ct state",
					Expr:      ct,
				})
				return &expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{byte(CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
				}
			},
			expected: "ct state != established",
		},
		{
			name: "payload ip version != 5",
			setup: func(ctx *ctx) *expr.Cmp {
				pl := &expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				}
				bw := &expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				}
				cmp := &expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 2,
					Data:     []byte{0x50},
				}

				ctx.reg.Set(1, regVal{
					HumanExpr: "ip version",
					Expr:      pl,
				})
				ctx.reg.Set(2, regVal{
					HumanExpr: "ip version",
					Expr:      bw,
				})

				return cmp
			},
			expected: "ip version != 5",
		},

		{
			name: "ip version == 4",
			setup: func(ctx *ctx) *expr.Cmp {
				pl := &expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				}
				bw := &expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				}
				cmp := &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 2,
					Data:     []byte{0x40},
				}
				ctx.reg.Set(1, regVal{
					HumanExpr: "ip version",
					Expr:      pl,
				})
				ctx.reg.Set(2, regVal{
					HumanExpr: "ip version",
					Expr:      bw,
				})
				return cmp
			},
			expected: "ip version 4",
		},
		{
			name: "ip version == 6",
			setup: func(ctx *ctx) *expr.Cmp {
				pl := &expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				}
				bw := &expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				}
				cmp := &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 2,
					Data:     []byte{0x60},
				}
				ctx.reg.Set(1, regVal{
					HumanExpr: "ip version",
					Expr:      pl,
				})
				ctx.reg.Set(2, regVal{
					HumanExpr: "ip version",
					Expr:      bw,
				})
				return cmp
			},
			expected: "ip version 6",
		},
		{
			name: "meta cpu == 3",
			setup: func(ctx *ctx) *expr.Cmp {
				meta := &expr.Meta{Key: expr.MetaKeyCPU, Register: 1}
				ctx.reg.Set(1, regVal{
					HumanExpr: "meta cpu",
					Expr:      meta,
				})
				return &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{3},
				}
			},
			expected: "meta cpu 3",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			ctx := &ctx{
				hdr: new(protocols.ProtoDescPtr),
			}
			cmp := tc.setup(ctx)
			enc := &cmpEncoder{cmp: cmp}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func Test_CmpEncoderAdvanced(t *testing.T) {
	suite.Run(t, new(cmpEncoderAdvancedTestSuite))
}
