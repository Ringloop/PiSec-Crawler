package source

import (
	"encoding/csv"
	"log"
	"os"
	"time"
)

// Defining an interface so that functionality of 'readConfig()' can be mocked
type Source interface {
	ReadSourceData() ([]SourceData, error)
}

type Reader struct {
	SourceAddress string
}

type SourceData struct {
	date      time.Time
	score     float32
	url       string
	ipAddress string
}

// 'reader' implementing the Interface
// Function to read from actual file
func (r *Reader) ReadSourceData() ([]SourceData, error) {

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

	return []SourceData{}, nil
}
