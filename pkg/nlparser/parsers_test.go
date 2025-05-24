package nlparser

import (
	"net"
	"testing"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	userdata "github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type (
	ConnMock struct {
		*nftLib.Conn
	}
	Recorder struct {
		requests []netlink.Message
	}
)

var comment = "{`names`:[`rule1`,`rule2`],`IPv`:4}"

// Conn opens an nftables connection that records netlink messages into the
// Recorder.
func (r *Recorder) Conn() (*ConnMock, error) {
	conn, err := nftLib.New(nftLib.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			r.requests = append(r.requests, req...)

			acks := make([]netlink.Message, 0, len(req))
			for _, msg := range req {
				if msg.Header.Flags&netlink.Acknowledge != 0 {
					acks = append(acks, netlink.Message{
						Header: netlink.Header{
							Length:   4,
							Type:     netlink.Error,
							Sequence: msg.Header.Sequence,
							PID:      msg.Header.PID,
						},
						Data: []byte{0, 0, 0, 0},
					})
				}
			}
			return acks, nil
		}))
	if err != nil {
		return nil, err
	}

	return &ConnMock{conn}, err
}

// Requests returns the recorded netlink messages (typically nftables requests).
func (r *Recorder) Requests() []netlink.Message {
	return r.requests
}

// NewRecorder returns a ready-to-use Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

func Test_Parsers(t *testing.T) {
	rec := NewRecorder()
	c, err := rec.Conn()
	if err != nil {
		t.Fatal(err)
	}

	tbl := &nftLib.Table{
		Family: nftLib.TableFamilyIPv4,
		Name:   "filter",
	}
	c.AddTable(tbl)

	chain := &nftLib.Chain{
		Name:  "output",
		Table: tbl,
	}
	c.AddChain(chain)
	set := &nftLib.Set{
		Name:     "ipSet",
		Table:    tbl,
		KeyType:  nftLib.TypeIPAddr,
		Constant: true,
		Interval: true,
	}
	setElems := []nftLib.SetElement{
		{
			Key: []byte(net.ParseIP("10.34.11.179").To4()),
		},
		{
			Key:         []byte(net.ParseIP("10.34.11.180").To4()),
			IntervalEnd: true,
		},
	}
	if err := c.AddSet(set, setElems); err != nil {
		t.Fatal(err)
	}

	rule := &nftLib.Rule{
		Handle: 5,
		Table:  tbl,
		Chain:  chain,
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
		UserData: userdata.AppendString([]byte(nil), userdata.TypeComment, comment),
	}
	c.AddRule(rule)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	const NlSubsysMask uint16 = 0xf00
	for _, msg := range rec.Requests() {
		msgType := uint16(msg.Header.Type) & ^NlSubsysMask
		switch msgType {
		case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
			gotTbl, err := TableFromMsg(msg)
			require.NoError(t, err)
			require.Equal(t, tbl, gotTbl)
		case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
			gotChain, err := ChainFromMsg(msg)
			require.NoError(t, err)
			require.Equal(t, chain, gotChain)
		case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
			gotRule, err := RuleFromMsg(msg)
			require.NoError(t, err)
			require.EqualValues(t, rule, gotRule)
		case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
			gotSet, err := SetFromMsg(msg)
			require.NoError(t, err)
			require.Equal(t, set, gotSet)
		case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
			gotElem, err := SetElemsFromMsg(msg)
			require.NoError(t, err)
			require.Equal(t, setElems[0], gotElem.Elems[0])
		}
	}
}
