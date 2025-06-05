package encoders

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (sui *encodersTestSuite) Test_DupExprToString() {
	const tableName = "test"

	testData := []struct {
		name     string
		exprs    nftables.Rule
		preRun   func()
		expected string
	}{

		{
			name: "dup to address",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte("10.1.2.3")},
					&expr.Dup{RegAddr: 1},
				},
			},
			expected: "dup to 10.1.2.3",
		},
		{
			name: "dup to address and device",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte("192.168.1.10")},
					&expr.Immediate{Register: 2, Data: []byte("lo")},
					&expr.Dup{RegAddr: 1, RegDev: 2},
				},
			},
			expected: "dup to 192.168.1.10 device lo",
		},
	}

	for _, t := range testData {
		sui.Run(t.name, func() {
			if t.preRun != nil {
				t.preRun()
			}
			str, err := NewRuleExprEncoder(&t.exprs).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(t.expected, str)
		})
	}
}

// sudo nft add table ip test
// sudo nft add chain ip test prerouting '{ type filter hook prerouting priority 0; }'

// sudo nft add rule ip test prerouting dup to 10.1.2.3
// sudo nft add rule ip test prerouting dup to 192.168.1.10 device lo
