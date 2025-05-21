package nlparser

import (
	"encoding/binary"
	"fmt"
	"time"

	nftLib "github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	MagicTypeInvalid uint32 = iota
	MagicTypeVerdict
	MagicTypeNFProto
	MagicTypeBitmask
	MagicTypeInteger
	MagicTypeString
	MagicTypeLLAddr
	MagicTypeIPAddr
	MagicTypeIP6Addr
	MagicTypeEtherAddr
	MagicTypeEtherType
	MagicTypeARPOp
	MagicTypeInetProto
	MagicTypeInetService
	MagicTypeICMPType
	MagicTypeTCPFlag
	MagicTypeDCCPPktType
	MagicTypeMHType
	MagicTypeTime
	MagicTypeMark
	MagicTypeIFIndex
	MagicTypeARPHRD
	MagicTypeRealm
	MagicTypeClassID
	MagicTypeUID
	MagicTypeGID
	MagicTypeCTState
	MagicTypeCTDir
	MagicTypeCTStatus
	MagicTypeICMP6Type
	MagicTypeCTLabel
	MagicTypePktType
	MagicTypeICMPCode
	MagicTypeICMPV6Code
	MagicTypeICMPXCode
	MagicTypeDevGroup
	MagicTypeDSCP
	MagicTypeECN
	MagicTypeFIBAddr
	MagicTypeBoolean
	MagicTypeCTEventBit
	MagicTypeIFName
	MagicTypeIGMPType
	MagicTypeTimeDate
	MagicTypeTimeHour
	MagicTypeTimeDay
	MagicTypeCGroupV2
)

var nftDatatypesByMagic = map[uint32]nftLib.SetDatatype{
	MagicTypeVerdict:     nftLib.TypeVerdict,
	MagicTypeNFProto:     nftLib.TypeNFProto,
	MagicTypeBitmask:     nftLib.TypeBitmask,
	MagicTypeInteger:     nftLib.TypeInteger,
	MagicTypeString:      nftLib.TypeString,
	MagicTypeLLAddr:      nftLib.TypeLLAddr,
	MagicTypeIPAddr:      nftLib.TypeIPAddr,
	MagicTypeIP6Addr:     nftLib.TypeIP6Addr,
	MagicTypeEtherAddr:   nftLib.TypeEtherAddr,
	MagicTypeEtherType:   nftLib.TypeEtherType,
	MagicTypeARPOp:       nftLib.TypeARPOp,
	MagicTypeInetProto:   nftLib.TypeInetProto,
	MagicTypeInetService: nftLib.TypeInetService,
	MagicTypeICMPType:    nftLib.TypeICMPType,
	MagicTypeTCPFlag:     nftLib.TypeTCPFlag,
	MagicTypeDCCPPktType: nftLib.TypeDCCPPktType,
	MagicTypeMHType:      nftLib.TypeMHType,
	MagicTypeTime:        nftLib.TypeTime,
	MagicTypeMark:        nftLib.TypeMark,
	MagicTypeIFIndex:     nftLib.TypeIFIndex,
	MagicTypeARPHRD:      nftLib.TypeARPHRD,
	MagicTypeRealm:       nftLib.TypeRealm,
	MagicTypeClassID:     nftLib.TypeClassID,
	MagicTypeUID:         nftLib.TypeUID,
	MagicTypeGID:         nftLib.TypeGID,
	MagicTypeCTState:     nftLib.TypeCTState,
	MagicTypeCTDir:       nftLib.TypeCTDir,
	MagicTypeCTStatus:    nftLib.TypeCTStatus,
	MagicTypeICMP6Type:   nftLib.TypeICMP6Type,
	MagicTypeCTLabel:     nftLib.TypeCTLabel,
	MagicTypePktType:     nftLib.TypePktType,
	MagicTypeICMPCode:    nftLib.TypeICMPCode,
	MagicTypeICMPV6Code:  nftLib.TypeICMPV6Code,
	MagicTypeICMPXCode:   nftLib.TypeICMPXCode,
	MagicTypeDevGroup:    nftLib.TypeDevGroup,
	MagicTypeDSCP:        nftLib.TypeDSCP,
	MagicTypeECN:         nftLib.TypeECN,
	MagicTypeFIBAddr:     nftLib.TypeFIBAddr,
	MagicTypeBoolean:     nftLib.TypeBoolean,
	MagicTypeCTEventBit:  nftLib.TypeCTEventBit,
	MagicTypeIFName:      nftLib.TypeIFName,
	MagicTypeIGMPType:    nftLib.TypeIGMPType,
	MagicTypeTimeDate:    nftLib.TypeTimeDate,
	MagicTypeTimeHour:    nftLib.TypeTimeHour,
	MagicTypeTimeDay:     nftLib.TypeTimeDay,
	MagicTypeCGroupV2:    nftLib.TypeCGroupV2,
}

func SetFromMsg(msg netlink.Message) (*nftLib.Set, error) {
	var set nftLib.Set
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_NAME:
			set.Name = ad.String()
		case unix.NFTA_SET_TABLE:
			set.Table = &nftLib.Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			set.Table.Family = nftLib.TableFamily(msg.Data[0])
		case unix.NFTA_SET_ID:
			set.ID = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_TIMEOUT:
			set.Timeout = time.Millisecond * time.Duration(binary.BigEndian.Uint64(ad.Bytes())) //nolint:gosec
			set.HasTimeout = true
		case unix.NFTA_SET_FLAGS:
			flags := ad.Uint32()
			set.Constant = (flags & unix.NFT_SET_CONSTANT) != 0
			set.Anonymous = (flags & unix.NFT_SET_ANONYMOUS) != 0
			set.Interval = (flags & unix.NFT_SET_INTERVAL) != 0
			set.IsMap = (flags & unix.NFT_SET_MAP) != 0
			set.HasTimeout = (flags & unix.NFT_SET_TIMEOUT) != 0
			set.Concatenation = (flags & nftLib.NFT_SET_CONCAT) != 0
		case unix.NFTA_SET_KEY_TYPE:
			nftMagic := ad.Uint32()
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return nil, fmt.Errorf("could not determine data type: %w", err)
			}
			set.KeyType = dt
		case unix.NFTA_SET_KEY_LEN:
			set.KeyType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_DATA_TYPE:
			nftMagic := ad.Uint32()
			// Special case for the data type verdict, in the message it is stored as 0xffffff00 but it is defined as 1
			if nftMagic == 0xffffff00 { //nolint:mnd
				set.KeyType = nftLib.TypeVerdict
				break
			}
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return nil, fmt.Errorf("could not determine data type: %w", err)
			}
			set.DataType = dt
		case unix.NFTA_SET_DATA_LEN:
			set.DataType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		}
	}
	return &set, nil
}

func parseSetDatatype(magic uint32) (nftLib.SetDatatype, error) {
	types := make([]nftLib.SetDatatype, 0, 32/nftLib.SetConcatTypeBits) //nolint:mnd
	for magic != 0 {
		t := magic & nftLib.SetConcatTypeMask
		magic = magic >> nftLib.SetConcatTypeBits
		dt, ok := nftDatatypesByMagic[t]
		if !ok {
			return nftLib.TypeInvalid, fmt.Errorf("could not determine data type %+v", dt)
		}
		// Because we start with the last type, we insert the later types at the front.
		types = append([]nftLib.SetDatatype{dt}, types...)
	}

	dt, err := nftLib.ConcatSetType(types...)
	if err != nil {
		return nftLib.TypeInvalid, fmt.Errorf("could not create data type: %w", err)
	}
	return dt, nil
}
