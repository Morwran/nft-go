package encoders

import (
	"testing"

	"github.com/google/nftables"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type ctEncoderAdvancedTestSuite struct {
	suite.Suite
}

func (sui *ctEncoderAdvancedTestSuite) Test_CtEncodeIR_Complex() {
	testData := []struct {
		name     string
		exprs    []expr.Any
		expected string
	}{
		{
			name: "ct state new,established",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{byte(CtStateBitNEW | CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
				},
			},
			expected: "ct state established,new",
		},
		{
			name: "ct direction original",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
			},
			expected: "ct direction original",
		},
		{
			name: "ct expiration 5s",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeyEXPIRATION, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x88, 0x13, 0x00, 0x00}},
			},
			expected: "ct expiration 5s",
		},
		{
			name: "ct protocol tcp",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeyPROTOCOL, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			},
			expected: "ct protocol tcp",
		},
		{
			name: "ct mark set 42",
			exprs: []expr.Any{
				&expr.Immediate{Register: 1, Data: []byte{42, 0, 0, 0}},
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
			},
			expected: "ct mark set 42",
		},
		{
			name: "ct status snat,dnat,confirmed,assured",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x3C, 0x00, 0x00, 0x00, 0, 0, 0, 0}},
			},
			expected: "ct status assured,confirmed,snat,dnat",
		},
		{
			name: "ct state != established,invalid",
			exprs: []expr.Any{
				&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     []byte{byte(CtStateBitESTABLISHED | CtStateBitINVALID), 0, 0, 0, 0, 0, 0, 0},
				},
			},
			expected: "ct state != invalid,established",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			rule := nftables.Rule{Exprs: tc.exprs}
			str, err := NewRuleExprEncoder(&rule).Format()
			sui.Require().NoError(err)

			expectedNorm := tc.expected

			actualNorm := str
			sui.Require().Equal(expectedNorm, actualNorm)
		})
	}
}

func Test_CtEncoderAdvanced(t *testing.T) {
	suite.Run(t, new(ctEncoderAdvancedTestSuite))
}
