package nlparser

import (
	"encoding/binary"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func RuleFromMsg(msg netlink.Message) (*nftLib.Rule, error) {
	var r nftLib.Rule
	fam := nftLib.TableFamily(msg.Data[0])
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = &nftLib.Table{
				Name:   ad.String(),
				Family: fam,
			}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &nftLib.Chain{
				Table: r.Table,
				Name:  ad.String(),
			}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				exprs, err := ParseExprMsgFunc(byte(fam), b)
				if err != nil {
					return err
				}
				r.Exprs = make([]expr.Any, len(exprs))
				for i := range exprs {
					r.Exprs[i] = exprs[i].(expr.Any)
				}
				return nil
			})
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = ad.Bytes()
		}
	}
	return &r, ad.Err()
}
