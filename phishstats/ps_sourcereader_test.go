package phishstats

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	phishStatsPrefix = `######################################################################################
# PhishScore | PhishStats                                                            #
# Score ranges: 0-2 likely 2-4 suspicious 4-6 phishing 6-10 omg phishing!            #
# Ranges may be adjusted without notice. List updated every 90 minutes. Do not crawl #
# too much at the risk of being blocked.                                             #
# Many Phishing websites are legitimate websites that have been hacked, so keep that #
# in mind before blocking everything. Feed is provided as is, without any warrant.   #
# CSV: Date,Score,URL,IP                                                             #
######################################################################################`

	singleCsvString = `# CSV: Date,Score,URL,IP
"2022-03-03 13:38:33","1.4","www.my-ip.com","131.223.43.4"`

	realCsvString = `######################################################################################
# PhishScore | PhishStats                                                            #
# Score ranges: 0-2 likely 2-4 suspicious 4-6 phishing 6-10 omg phishing!            #
# Ranges may be adjusted without notice. List updated every 90 minutes. Do not crawl #
# too much at the risk of being blocked.                                             #
# Many Phishing websites are legitimate websites that have been hacked, so keep that #
# in mind before blocking everything. Feed is provided as is, without any warrant.   #
# CSV: Date,Score,URL,IP                                                             #
######################################################################################
"2022-02-02 13:39:21","1.40","http://www.spirltswap.digital/","185.137.235.119"
"2022-02-02 13:39:18","4.50","http://wordpress.massolutions.pro/dlh.php","173.249.1.245"
"2022-02-02 13:39:15","5.80","http://webmail.ionos-services.de.gerdiken.com/data/Webmail_Ionos_login.htm","217.160.0.222"
"2022-02-02 13:38:50","5.50","https://www.spk-panel.de/privatkunden/legitimation.php","104.21.4.12"
"2022-02-02 13:38:49","6.20","https://www.bankmillenium-pl.com/login.php","104.21.8.72"
"2022-02-02 13:38:48","4.80","https://ww.interbak.prestamos.pe.zenoaks.com/","103.21.59.208"
"2022-02-02 13:38:33","5.00","https://updateattonlineserver.weebly.com/","199.34.228.54"`
)

func TestReadData(t *testing.T) {

	res, error := ReadData()
	require.Nil(t, error)
	require.NotNil(t, res)
	require.True(t, strings.HasPrefix(res, phishStatsPrefix))

}

func TestParseBasicCsv(t *testing.T) {
	localCsvString := `# CSV: Date,Score,URL,IP
"20220223","1.4","www.my-ip.com","131.223.43.4"`

	keys, data, err := ExtractCsvData(localCsvString)

	require.Equal(t, err, nil)
	require.Equal(t, len(keys), 4)
	require.Equal(t, keys[0], "Date")
	require.Equal(t, keys[1], "Score")
	require.Equal(t, keys[2], "URL")
	require.Equal(t, keys[3], "IP")

	require.Equal(t, data, "Date, Score, URL, IP\n\"20220223\",\"1.4\",\"www.my-ip.com\",\"131.223.43.4\"")

}

func TestParseCsvTestString(t *testing.T) {

	_, data, err := ExtractCsvData(realCsvString)

	require.Equal(t, err, nil)

	psData := ParseCsvData(data)
	referenceScore := 1.4
	referenceURL := "http://www.spirltswap.digital/"
	referenceIP := "185.137.235.119"

	referenceDate, dateErr := time.Parse(date_layout, "2022-02-02 13:39:21")
	require.Equal(t, dateErr, nil)

	require.Equal(t, psData[0].Date.Time, referenceDate)
	require.Equal(t, psData[0].Score, referenceScore)
	require.Equal(t, psData[0].Url, referenceURL)
	require.Equal(t, psData[0].IpAddress, referenceIP)

	referenceScore = 5.5
	referenceURL = "https://www.spk-panel.de/privatkunden/legitimation.php"
	referenceIP = "104.21.4.12"

	referenceDate, dateErr = time.Parse(date_layout, "2022-02-02 13:38:50")
	require.Equal(t, dateErr, nil)

	require.Equal(t, psData[3].Date.Time, referenceDate)
	require.Equal(t, psData[3].Score, referenceScore)
	require.Equal(t, psData[3].Url, referenceURL)
	require.Equal(t, psData[3].IpAddress, referenceIP)

}

func TestParseCsvValues(t *testing.T) {

	csvString := `# CSV: Date,Score,URL,IP
"2022-03-03 13:38:33","1.4","www.my-ip.com","131.223.43.4"`

	_, data, err := ExtractCsvData(csvString)

	require.Equal(t, err, nil)

	psData := ParseCsvData(data)
	referenceScore := 1.4
	referenceURL := "www.my-ip.com"
	referenceIP := "131.223.43.4"

	referenceDate, dateErr := time.Parse(date_layout, "2022-03-03 13:38:33")
	require.Equal(t, dateErr, nil)

	require.Equal(t, psData[0].Date.Time, referenceDate)
	require.Equal(t, psData[0].Score, referenceScore)
	require.Equal(t, psData[0].Url, referenceURL)
	require.Equal(t, psData[0].IpAddress, referenceIP)

}

func TestGetIndicatorFromData(t *testing.T) {

	_, data, err := ExtractCsvData(singleCsvString)

	require.Equal(t, err, nil)

	psData := ParseCsvData(data)
	indicator := GetIndicatorFromData(psData[0])

	referenceScore := 14
	referenceURL := "www.my-ip.com"
	referenceIP := "131.223.43.4"

	require.Equal(t, indicator.Reliability, referenceScore)
	require.Equal(t, indicator.Url, referenceURL)
	require.Equal(t, indicator.Ip, referenceIP)

}

func TestGetSingleUrlBulkData(t *testing.T) {

	_, data, err := ExtractCsvData(singleCsvString)

	require.Equal(t, err, nil)

	psData := ParseCsvData(data)
	bulkData := GetBulkRequestsFromData(psData)

	referenceScore := 14
	referenceURL := "www.my-ip.com"
	referenceIP := "131.223.43.4"

	require.Equal(t, len(bulkData), 1)
	require.Equal(t, len(bulkData[0].Indicators), 1)
	require.Equal(t, bulkData[0].Source, "PhishStats")
	require.Equal(t, bulkData[0].Indicators[0].Reliability, referenceScore)
	require.Equal(t, bulkData[0].Indicators[0].Url, referenceURL)
	require.Equal(t, bulkData[0].Indicators[0].Ip, referenceIP)

}

func TestGetMultipleUrlBulkData(t *testing.T) {

	_, data, err := ExtractCsvData(realCsvString)

	require.Equal(t, err, nil)

	psData := ParseCsvData(data)
	bulkData := GetBulkRequestsFromData(psData)

	referenceScore := 14
	referenceURL := "http://www.spirltswap.digital/"
	referenceIP := "185.137.235.119"

	require.Equal(t, len(bulkData), 1)
	require.Equal(t, len(bulkData[0].Indicators), 7)
	require.Equal(t, bulkData[0].Source, "PhishStats")
	require.Equal(t, bulkData[0].Indicators[0].Reliability, referenceScore)
	require.Equal(t, bulkData[0].Indicators[0].Url, referenceURL)
	require.Equal(t, bulkData[0].Indicators[0].Ip, referenceIP)

}
