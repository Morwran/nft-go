package nlparser

import (
	"encoding/binary"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func ChainFromMsg(msg netlink.Message) (*nftLib.Chain, error) {
	var c nftLib.Chain
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CHAIN_NAME:
			c.Name = ad.String()
		case unix.NFTA_TABLE_NAME:
			c.Table = &nftLib.Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			c.Table.Family = nftLib.TableFamily(msg.Data[0])
		case unix.NFTA_CHAIN_TYPE:
			c.Type = nftLib.ChainType(ad.String())
		case unix.NFTA_CHAIN_POLICY:
			policy := nftLib.ChainPolicy(binaryutil.BigEndian.Uint32(ad.Bytes()))
			c.Policy = &policy
		case unix.NFTA_CHAIN_HOOK:
			ad.Do(func(b []byte) error {
				c.Hooknum, c.Priority, err = hookFromMsg(b)
				return err
			})
		case unix.NFTA_CHAIN_HANDLE:
			c.Handle = binaryutil.BigEndian.Uint64(ad.Bytes())
		}
	}

	return &c, nil
}

func hookFromMsg(b []byte) (*nftLib.ChainHook, *nftLib.ChainPriority, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, nil, err
	}

	ad.ByteOrder = binary.BigEndian

	var hooknum nftLib.ChainHook
	var prio nftLib.ChainPriority

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_HOOK_HOOKNUM:
			hooknum = nftLib.ChainHook(ad.Uint32())
		case unix.NFTA_HOOK_PRIORITY:
			prio = nftLib.ChainPriority(ad.Uint32()) //nolint:gosec
		}
	}

	return &hooknum, &prio, nil
}
