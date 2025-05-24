package nlparser

import (
	"encoding/binary"
	"fmt"
	"time"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type (
	SetElems struct {
		Table   *nftLib.Table
		SetName string
		SetId   uint32
		Elems   []nftLib.SetElement
	}

	setElemDecoder nftLib.SetElement
)

func SetElemsFromMsg(msg netlink.Message) (*SetElems, error) {
	var set SetElems

	fam := msg.Data[0]
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		b := ad.Bytes()
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_LIST_TABLE:
			set.Table = &nftLib.Table{Name: ad.String(), Family: nftLib.TableFamily(fam)}
		case unix.NFTA_SET_ELEM_LIST_SET:
			set.SetName = ad.String()
		case unix.NFTA_SET_ELEM_LIST_SET_ID:
			set.SetId = ad.Uint32()
		case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
			ad, err := netlink.NewAttributeDecoder(b)
			if err != nil {
				return nil, err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				var elem setElemDecoder
				if ad.Type() == unix.NFTA_LIST_ELEM {
					ad.Do(elem.decode(fam))
					if ad.Err() != nil {
						return nil, ad.Err()
					}
					set.Elems = append(set.Elems, nftLib.SetElement(elem))
				}
			}
		}
	}

	return &set, nil
}

func (s *setElemDecoder) decode(fam byte) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return fmt.Errorf("failed to create nested attribute decoder: %v", err)
		}
		ad.ByteOrder = binary.BigEndian

		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_SET_ELEM_KEY:
				s.Key, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case nftLib.NFTA_SET_ELEM_KEY_END:
				s.KeyEnd, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_DATA:
				s.Val, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_FLAGS:
				flags := ad.Uint32()
				s.IntervalEnd = (flags & unix.NFT_SET_ELEM_INTERVAL_END) != 0
			case unix.NFTA_SET_ELEM_TIMEOUT:
				s.Timeout = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPIRATION:
				s.Expires = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPR:
				elems, err := ParseExprBytesFunc(fam, ad, ad.Bytes())
				if err != nil {
					return err
				}

				for _, elem := range elems {
					switch item := elem.(type) {
					case *expr.Counter:
						s.Counter = item
					}
				}
			}
		}
		return ad.Err()
	}
}

func decodeElement(d []byte) ([]byte, error) {
	ad, err := netlink.NewAttributeDecoder(d)
	if err != nil {
		return nil, fmt.Errorf("failed to create nested attribute decoder: %v", err)
	}
	ad.ByteOrder = binary.BigEndian
	var b []byte
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_KEY:
			fallthrough
		case unix.NFTA_SET_ELEM_DATA:
			b = ad.Bytes()
		}
	}
	if err = ad.Err(); err != nil {
		return nil, err
	}
	return b, nil
}
