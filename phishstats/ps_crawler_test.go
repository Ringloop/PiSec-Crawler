package phishstats

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const phishStatsPrefix = `######################################################################################
# PhishScore | PhishStats                                                            #
# Score ranges: 0-2 likely 2-4 suspicious 4-6 phishing 6-10 omg phishing!            #
# Ranges may be adjusted without notice. List updated every 90 minutes. Do not crawl #
# too much at the risk of being blocked.                                             #
# Many Phishing websites are legitimate websites that have been hacked, so keep that #
# in mind before blocking everything. Feed is provided as is, without any warrant.   #
# CSV: Date,Score,URL,IP                                                             #
######################################################################################`

func TestReadData(t *testing.T) {

	res, error := ReadData()
	require.Nil(t, error)
	require.NotNil(t, res)
	require.True(t, strings.HasPrefix(res, phishStatsPrefix))

}
