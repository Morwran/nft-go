package encoders

import (
	"math"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type connlimitEncoderTestSuite struct {
	suite.Suite
}

func (sui *connlimitEncoderTestSuite) Test_ConnlimitEncodeIR() {
	testCases := []struct {
		name      string
		connlimit *expr.Connlimit
		expected  string
	}{
		{
			name:      "basic count",
			connlimit: &expr.Connlimit{Count: 5, Flags: 0},
			expected:  "ct count 5",
		},
		{
			name:      "with inv flag",
			connlimit: &expr.Connlimit{Count: 10, Flags: unix.NFT_LIMIT_F_INV},
			expected:  "ct count over 10",
		},
		{
			name:      "zero count",
			connlimit: &expr.Connlimit{Count: 0, Flags: 0},
			expected:  "ct count 0",
		},
		{
			name:      "max uint32 count",
			connlimit: &expr.Connlimit{Count: math.MaxUint32, Flags: 0},
			expected:  "ct count 4294967295",
		},
		{
			name:      "unknown flags fallback to over",
			connlimit: &expr.Connlimit{Count: 1, Flags: 123456}, // любые ненулевые
			expected:  "ct count over 1",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &connlimitEncoder{connlimit: tc.connlimit}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func Test_ConnlimitEncoder(t *testing.T) {
	suite.Run(t, new(connlimitEncoderTestSuite))
}
