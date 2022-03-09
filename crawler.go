package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
)

type ps_data struct {
	date  string `json:"date"` //Last date of visualization
	url   string `json:"url"`
	ip    string `json:"ip"`
	score string `json:"score"`
}

func readCSVFromUrl(url string) ([][]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1
	reader.Comma = ','
	data, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	url := "https://phishstats.info/phish_score.csv"
	data, err := readCSVFromUrl(url)
	if err != nil {
		panic(err)
	}

	index := 0
	treatList := []ps_data{}

	for _, row := range data {

		// skip header
		if row[0][0] == '#' {
			continue
		}

		treat := ps_data{
			date:  row[0],
			score: row[1],
			url:   row[2],
			ip:    row[3],
		}
		treatList = append(treatList, treat)

		index++

	}

	fmt.Println("Readed ", index, " records")

	// for _, treat := range treatList {
	// 	fmt.Println(treat)
	// }

}
