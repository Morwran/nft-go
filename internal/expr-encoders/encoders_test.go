package encoders

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type encodersTestSuite struct {
	suite.Suite
}

func (sui *encodersTestSuite) Test_MultipleExprToString() {
	const (
		tableName = "test"
		comment   = "test"
	)
	testData := []struct {
		name     string
		exprs    nftables.Rule
		preRun   func()
		expected string
	}{
		{
			name: "Expression 1",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expected: "meta l4proto tcp counter packets 0 bytes 0 log accept",
		},
		{
			name: "Expression 3",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         1,
						Offset:       0,
						Len:          1,
					},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            1,
						Mask:           []byte{240},
						Xor:            []byte{0},
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{80},
					},
				},
			},
			expected: "ip version != 5",
		},

		{
			name: "Expression 4",
			preRun: func() {
				var set setCache
				table := nftables.Table{Name: tableName}
				set.Put(
					setKey{
						tableName: table.Name,
						setName:   "ipSet",
						setId:     1,
					},
					setEntry{
						Set: nftables.Set{
							Table:   &table,
							Name:    "ipSet",
							KeyType: nftables.TypeIPAddr,
						},
						elems: []nftables.SetElement{
							{
								Key:         []byte(net.ParseIP("10.34.11.179").To4()),
								IntervalEnd: true,
							},
							{
								Key:         []byte(net.ParseIP("10.34.11.180").To4()),
								IntervalEnd: true,
							},
						},
					},
				)
				setsHolder.Store(set, nil)
			},
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          4,
					},

					&expr.Lookup{
						SourceRegister: 1,
						SetName:        "ipSet",
						SetID:          1,
					},
				},
			},
			expected: "ip daddr @ipSet",
		},
		{
			name: "Expression 5",
			preRun: func() {
				var set setCache
				table := nftables.Table{Name: tableName}
				set.Put(
					setKey{
						tableName: table.Name,
						setName:   "__set0",
					},
					setEntry{
						Set: nftables.Set{
							Table:     &table,
							Name:      "__set0",
							Anonymous: true,
							Constant:  true,
							KeyType:   nftables.TypeInetService,
						},
						elems: []nftables.SetElement{
							{
								Key:         binaryutil.BigEndian.PutUint16(80),
								IntervalEnd: true,
							},
							{
								Key:         binaryutil.BigEndian.PutUint16(443),
								IntervalEnd: true,
							},
						},
					},
				)
				setsHolder.Store(set, nil)
			},
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          4,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{93, 184, 216, 34},
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          4,
					},
					&expr.Lookup{
						SourceRegister: 1,
						SetName:        "__set0",
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
				},
			},
			expected: "ip daddr != 93.184.216.34 meta l4proto tcp dport {80,443} meta l4proto tcp",
		},
		{
			name: "Expression 7",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{0, 80},
					},
				},
			},
			expected: "th dport != 80",
		},
		{
			name: "Expression 8",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       1,
						Register: 1,
						Data:     []byte{0, 80},
					},
				},
			},
			expected: "meta l4proto tcp dport != 80",
		},
		{
			name: "Expression 9",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       0,
						Len:          2,
					},
					&expr.Cmp{
						Op:       5,
						Register: 1,
						Data:     []byte{0, 80},
					},
					&expr.Cmp{
						Op:       3,
						Register: 1,
						Data:     []byte{0, 100},
					},
				},
			},
			expected: "meta l4proto tcp sport >= 80 sport <= 100",
		},

		{
			name: "Expression 10",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, Register: 1, SourceRegister: true},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       16,
						Len:          1,
					},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{10},
					},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_UDP},
					},
				},
			},
			expected: "meta nftrace set 1 ip daddr 10.0.0.0/8 meta l4proto udp",
		},

		{
			name: "Expression 11",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{unix.IPPROTO_ICMP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       0,
						Len:          1,
					},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{0},
					},
				},
			},
			expected: "meta l4proto icmp type echo-reply",
		},

		{
			name: "Expression 11",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1},
					&expr.Bitwise{
						SourceRegister: 1,
						DestRegister:   1,
						Len:            4,
						Mask:           []byte{6, 0, 0, 0},
						Xor:            []byte{0, 0, 0, 0},
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpNeq,
						Data:     []byte{0, 0, 0, 0},
					},
				},
			},
			expected: "ct state established,related",
		},
		{
			name: "Expression 12",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyEXPIRATION},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{232, 3, 0, 0},
					},
				},
			},
			expected: "ct expiration 1s",
		},
		{
			name: "Expression 13",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{0},
					},
				},
			},
			expected: "ct direction original",
		},
		{
			name: "Expression 14",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyL3PROTOCOL},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{unix.NFPROTO_IPV4},
					},
				},
			},
			expected: "ct l3proto ipv4",
		},
		{
			name: "Expression 15",
			exprs: nftables.Rule{
				Table: &nftables.Table{Name: tableName},
				Exprs: []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyPROTOCOL},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{unix.IPPROTO_TCP},
					},
				},
			},
			expected: "ct protocol tcp",
		},
	}
	for _, t := range testData {
		sui.Run(t.name, func() {
			if t.preRun != nil {
				t.preRun()
			}
			str, err := NewRuleExprEncoder(&t.exprs).Format()
			sui.Require().NoError(err)
			fmt.Println(str)
			sui.Require().Equal(t.expected, str)
		})
	}
}

func (sui *encodersTestSuite) Test_MultipleExprToJSON() {
	testData := []struct {
		name    string
		exprs   nftables.Rule
		expJson []byte
	}{
		{
			name: "Expression 1",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expJson: []byte(`[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"counter":{"bytes":0,"packets":0}},{"log":null},{"accept":null}]`),
		},
		{
			name: "Expression 2",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						Data:     []byte("lo"),
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
			},
			expJson: []byte(`[{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"mangle":{"key":{"meta":{"key":"nftrace"}},"value":1}},{"goto":{"target":"FW-OUT"}}]`),
		},
	}
	for _, t := range testData {
		sui.Run(t.name, func() {
			b, err := NewRuleExprEncoder(&t.exprs).MarshalJSON()
			sui.Require().NoError(err)
			fmt.Println(string(b))
			sui.Require().Equal(t.expJson, b)
		})
	}
}

func Test_Encoders(t *testing.T) {
	suite.Run(t, new(encodersTestSuite))
}
