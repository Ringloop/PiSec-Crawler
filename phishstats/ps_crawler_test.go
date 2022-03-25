package phishstats

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const MOCK_DATA_FILE = "phishstats_sourcefile.csv"

func ReadDataFromMockFile() (string, error) {

	file, err := os.Open(MOCK_DATA_FILE)
	if err != nil {
		log.Panicf("failed reading file: %s", err)
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)

	dataString := string(data)

	return dataString, err
}

func TestGetBulkRequests(t *testing.T) {

	stringData, dataErr := ReadDataFromMockFile()
	if dataErr != nil {
		panic(dataErr)
	}

	requests := GetBulkRequests(stringData)

	totalRequests := 0

	for _, elem := range requests {

		totalRequests = totalRequests + len(elem.Indicators)

	}

	require.Equal(t, len(requests), 429)
	require.Equal(t, totalRequests, 42838)

}
