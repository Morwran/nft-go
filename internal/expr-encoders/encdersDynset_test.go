package encoders

import (
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type dynsetIRTestSuite struct {
	suite.Suite
}

func (sui *dynsetIRTestSuite) Test_DynsetEncodeIR() {
	testData := []struct {
		name     string
		dynset   *expr.Dynset
		srcKey   string
		srcData  string
		expected string
	}{
		{
			name: "add to IPv4 set",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPAdd),
				SetName:   "testset",
				SrcRegKey: 1,
			},
			srcKey:   "ip saddr",
			expected: "add @testset { ip saddr }",
		},
		{
			name: "add to set with timeout",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPAdd),
				SetName:   "timeoutset",
				SrcRegKey: 2,
				Timeout:   10 * time.Second,
			},
			srcKey:   "ip saddr",
			expected: "add @timeoutset { ip saddr timeout 10s }",
		},
		{
			name: "update set with counter",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPUpdate),
				SetName:   "updset",
				SrcRegKey: 3,
				Exprs: []expr.Any{
					&expr.Counter{},
				},
			},
			srcKey:   "ip saddr",
			expected: "update @updset { ip saddr counter packets 0 bytes 0 }",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			reg := regHolder{}
			reg.Set(regID(tc.dynset.SrcRegKey), regVal{HumanExpr: tc.srcKey})
			if tc.dynset.SrcRegData != 0 {
				reg.Set(regID(tc.dynset.SrcRegData), regVal{HumanExpr: tc.srcData})
			}

			ctx := &ctx{
				reg:  reg,
				rule: &nftables.Rule{},
			}
			enc := &dynsetEncoder{dynset: tc.dynset}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func Test_DynsetEncodeIR(t *testing.T) {
	suite.Run(t, new(dynsetIRTestSuite))
}
