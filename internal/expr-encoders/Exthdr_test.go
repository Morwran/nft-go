package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type exthdrExprBasedTestSuite struct {
	suite.Suite
}

func (sui *exthdrExprBasedTestSuite) Test_ExthdrEncodeIR_ExprBased() {
	testData := []struct {
		name     string
		exprs    []expr.Any
		expected string
	}{
		{
			name: "read IPv6 option into register (no IR)",
			exprs: []expr.Any{
				&expr.Exthdr{
					Op:           expr.ExthdrOpIpv6,
					Type:         1,
					Flags:        unix.NFT_EXTHDR_F_PRESENT,
					DestRegister: 1,
				},
			},
			expected: "",
		},
		{
			name: "compare with RHS via register (ip option)",
			exprs: []expr.Any{
				&expr.Immediate{Register: 3, Data: []byte{0xab}},
				&expr.Exthdr{
					Op:             expr.ExthdrOpIpv6,
					Type:           5,
					Offset:         12,
					Len:            1,
					SourceRegister: 3,
				},
			},
			expected: "ip option @5,12,1 set 171",
		},
		{
			name: "compare with RHS via register (tcp option)",
			exprs: []expr.Any{
				&expr.Immediate{Register: 4, Data: []byte{0x42}},
				&expr.Exthdr{
					Op:             expr.ExthdrOpTcpopt,
					Type:           2,
					Offset:         4,
					Len:            1,
					SourceRegister: 4,
				},
			},
			expected: "tcp option @2,4,1 set B",
		},
		{
			name: "unknown Op → fallback to exthdr",
			exprs: []expr.Any{
				&expr.Immediate{Register: 5, Data: []byte("value")},
				&expr.Exthdr{
					Op:             99,
					Type:           9,
					Offset:         1,
					Len:            1,
					SourceRegister: 5,
				},
			},
			expected: "exthdr @9,1,1 set value",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			rule := &nftables.Rule{Exprs: tc.exprs}
			str, err := NewRuleExprEncoder(rule).Format()

			if tc.expected == "" {
				sui.Require().NoError(err)
				sui.Require().Empty(str)
			} else {
				sui.Require().NoError(err)
				sui.Require().Equal(tc.expected, str)
			}
		})
	}
}

func Test_ExthdrExprBased(t *testing.T) {
	suite.Run(t, new(exthdrExprBasedTestSuite))
}
