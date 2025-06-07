package encoders

import (
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type dynsetIRExprTestSuite struct {
	suite.Suite
}

func (sui *dynsetIRExprTestSuite) Test_DynsetEncodeIR_ExprBased() {
	testData := []struct {
		name     string
		exprs    []expr.Any
		expected string
	}{
		{
			name: "add to IPv4 set via Payload",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // ip saddr
					Len:          4,
				},
				&expr.Dynset{
					Operation: uint32(DynSetOPAdd),
					SetName:   "ipv4set",
					SrcRegKey: 1,
				},
			},
			expected: "add @ipv4set { ip saddr }",
		},
		{
			name: "add to set with timeout via Payload",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 2,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // ip saddr
					Len:          4,
				},
				&expr.Dynset{
					Operation: uint32(DynSetOPAdd),
					SetName:   "timeoutset",
					SrcRegKey: 2,
					Timeout:   5 * time.Second,
				},
			},
			expected: "add @timeoutset { ip saddr timeout 5s }",
		},
		{
			name: "update set with counter via Payload",
			exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 3,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // ip saddr
					Len:          4,
				},
				&expr.Dynset{
					Operation: uint32(DynSetOPUpdate),
					SetName:   "updset",
					SrcRegKey: 3,
					Exprs: []expr.Any{
						&expr.Counter{},
					},
				},
			},
			expected: "update @updset { ip saddr counter packets 0 bytes 0 }",
		},
	}

	for _, tc := range testData {
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

func Test_DynsetEncodeIR_Expr(t *testing.T) {
	suite.Run(t, new(dynsetIRExprTestSuite))
}
