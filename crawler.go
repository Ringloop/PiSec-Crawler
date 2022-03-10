package main

import (
	"PiSec-Crawler/phishstats"
	"encoding/json"
	"fmt"
)

func main() {

	stringData, dataErr := phishstats.ReadData()
	if dataErr != nil {
		panic(dataErr)
	}

	_, data, err := phishstats.ExtractCsvData(stringData)

	if err != nil {
		panic(err)
	}

	psData := phishstats.ParseCsvData(data)
	for _, ps := range psData {
		jsonPs, err := json.Marshal(ps)
		if err != nil {
			fmt.Printf("Error: %s", err)
			return
		}
		fmt.Println(string(jsonPs))
	}

}
