package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type cmpEncoderExprBasedTestSuite struct {
	suite.Suite
}

func (sui *cmpEncoderExprBasedTestSuite) Test_CmpEncodeIR_ExprBased() {
	testCases := []struct {
		name     string
		exprs    []expr.Any
		expected string
	}{
		{
			name: "ct state != established",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{byte(CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
				},
			},
			expected: "ct state != established",
		},
		{
			name: "payload ip version != 5",
			exprs: []expr.Any{
				&expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 2,
					Data:     []byte{0x50},
				},
			},
			expected: "ip version != 5",
		},
		{
			name: "ip version == 4",
			exprs: []expr.Any{
				&expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 2,
					Data:     []byte{0x40},
				},
			},
			expected: "ip version 4",
		},
		{
			name: "ip version == 6",
			exprs: []expr.Any{
				&expr.Payload{
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
					DestRegister: 1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 2,
					Data:     []byte{0x60},
				},
			},
			expected: "ip version 6",
		},
		{
			name: "meta cpu == 3",
			exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyCPU, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{3},
				},
			},
			expected: "meta cpu 3",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rule := &nftables.Rule{Exprs: tc.exprs}
			str, err := NewRuleExprEncoder(rule).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, str)
		})
	}
}

func Test_CmpEncodeIR_ExprBased(t *testing.T) {
	suite.Run(t, new(cmpEncoderExprBasedTestSuite))
}
