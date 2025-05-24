package nlparser

import (
	nftLib "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TableFromMsg(msg netlink.Message) (*nftLib.Table, error) {
	var t nftLib.Table

	t.Family = nftLib.TableFamily(msg.Data[0])

	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TABLE_NAME:
			t.Name = ad.String()
		case unix.NFTA_TABLE_USE:
			t.Use = ad.Uint32()
		case unix.NFTA_TABLE_FLAGS:
			if t.Flags = ad.Uint32(); t.Flags != 0 {
				f0 := binaryutil.NativeEndian.Uint32(binaryutil.BigEndian.PutUint32(unix.NFT_TABLE_F_DORMANT))
				if t.Flags&f0 != 0 {
					t.Flags = unix.NFT_TABLE_F_DORMANT
				}
			}
		}
	}

	return &t, nil
}
