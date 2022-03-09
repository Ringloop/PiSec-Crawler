package phishstats

import (
	"encoding/csv"
	"io"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
)

type PhishstatsSource struct {
	UrlAddress string
}

type DateTime struct {
	time.Time
}

type PsSourceData struct {
	Date      DateTime `csv:"Date"`
	Score     float64  `csv:"Score"`
	Url       string   `csv:"URL"`
	IpAddress string   `csv:"IP"`
}

const (
	date_layout = "2006-01-02 15:04:05"
)

// Convert the CSV string as internal date
func (date *DateTime) UnmarshalCSV(csv string) (err error) {

	date.Time, err = time.Parse(date_layout, csv)
	return err
}

func ExtractCsvData(data string) ([]string, string, error) {

	var realData string
	var keys []string

	data_array := strings.Split(data, "\n")
	for index, row := range data_array {
		if strings.HasPrefix(row, "# CSV: ") {
			row = strings.Trim(row, "#")
			keysString := strings.Split(row, ":")
			keys = strings.Split(keysString[1], ",")
			for i := range keys {
				keys[i] = strings.Trim(keys[i], " ")
			}
		} else if !strings.HasPrefix(row, "#") {
			realData = strings.Join(keys[:], ", ")
			realData += "\n" + strings.Join(data_array[index:], "\n")
			break
		}
	}
	return keys, realData, nil
}

func ParseCsvData(data string) []PsSourceData {

	var psData []PsSourceData

	gocsv.SetCSVReader(func(in io.Reader) gocsv.CSVReader {
		r := csv.NewReader(in)
		r.TrimLeadingSpace = true
		r.LazyQuotes = true
		return r
	})

	if err := gocsv.UnmarshalString(data, &psData); err != nil {
		panic(err)
	}

	return psData

}
