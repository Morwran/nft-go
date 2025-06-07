package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type payloadEncoderNftWithVerdictTestSuite struct {
	suite.Suite
}

func (sui *payloadEncoderNftWithVerdictTestSuite) Test_PayloadExprToString_WithVerdict() {
	testData := []struct {
		name     string
		exprs    []expr.Any
		expected string
		nft      string
	}{
		{
			name: "match ip saddr accept",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{192, 168, 1, 1},
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			expected: "ip saddr 192.168.1.1 accept",
			nft:      "ip saddr 192.168.1.1 accept",
		},
		{
			name: "match ip daddr drop",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{10, 0, 0, 1},
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			expected: "ip daddr 10.0.0.1 drop",
			nft:      "ip daddr 10.0.0.1 drop",
		},
		{
			name: "match th dport accept",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x00, 0x50}, // port 80
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			expected: "th dport 80 accept",
			nft:      "tcp dport 80 accept",
		},

		{
			name: "match ip version 4 accept",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{0x40}, // version 4 << 4
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			expected: "ip version 4 accept",
		},
		{
			name: "match ip version != 6 drop",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       0,
					Len:          1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            1,
					Mask:           []byte{0xF0},
					Xor:            []byte{0x00},
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{0x60}, // version 6 << 4
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
			expected: "ip version != 6 drop",
		},
		{
			name: "bitwise mask+xor+accept on dport",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   2,
					Len:            2,
					Mask:           []byte{0xFF, 0xFF},
					Xor:            []byte{0x00, 0x10},
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 2,
					Data:     []byte{0x01, 0x50},
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			expected: "th dport 336 accept",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			rule := nftables.Rule{Exprs: tc.exprs}
			str, err := NewRuleExprEncoder(&rule).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, str)
		})
	}
}

func Test_PayloadEncoderWithVerdict(t *testing.T) {
	suite.Run(t, new(payloadEncoderNftWithVerdictTestSuite))
}
