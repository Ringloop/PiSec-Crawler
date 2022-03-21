package source

import (
	"encoding/csv"
	"log"
	"os"
)

// Defining an interface so that functionality of 'readConfig()' can be mocked
type Source interface {
	ReadSourceData() ([]Indicator, error)
}

type Reader struct {
	SourceAddress string
}

//Brain server structure
type UrlsBulkRequest struct {
	Indicators []Indicator `json:"indicators"`
	Source     string
}

type Indicator struct {
	Url         string `json:"url"`
	Date        int64  `json:"date"`
	Ip          string `json:"ip"`
	Reliability int    `json:"reliability"`
}

// type SourceData struct {
// 	date      time.Time //This should be a long representing distance from epoch
// 	score     float32   //to be long (should be a percentage)
// 	url       string
// 	ipAddress string
// }

// 'reader' implementing the Interface
// Function to read from actual file
func (r *Reader) ReadSourceData() ([]Indicator, error) {

	csvFile, err := os.Open(r.SourceAddress)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer csvFile.Close()

	csvLines, err := csv.NewReader(csvFile).ReadAll()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	println(csvLines)

	return []Indicator{}, nil
}
