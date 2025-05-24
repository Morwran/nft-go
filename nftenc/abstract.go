package nftenc

import "fmt"

type Encoder interface {
	fmt.Stringer
	MarshalJSON() ([]byte, error)
	Format() (string, error)
	MustString() string
}
