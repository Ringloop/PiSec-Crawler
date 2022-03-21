package main

import (
	"PiSec-Crawler/phishstats"
	"PiSec-Crawler/source"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const serverUrl = "http://164.68.107.9:8080/api/v1/indicator/url"

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

	client := &http.Client{}

	for _, ps := range psData {

		bRequest := &source.UrlsBulkRequest{
			Source: "PhishStats",
			Indicators: []source.Indicator{
				phishstats.GetIndicatorFromData(ps),
			},
		}

		jsonPs, err := json.Marshal(bRequest)

		request, error := http.NewRequest("POST", serverUrl, bytes.NewBuffer(jsonPs))
		if error != nil {
			panic(error)
		}
		request.Header.Set("Content-Type", "application/json; charset=UTF-8")

		fmt.Println("going to send data to server: ", ps)

		response, error := client.Do(request)
		if error != nil {
			panic(error)
		}
		defer response.Body.Close()

		fmt.Println("response Status:", response.Status)
		fmt.Println("response Headers:", response.Header)
		body, _ := ioutil.ReadAll(response.Body)
		fmt.Println("response Body:", string(body))

		if err != nil {
			fmt.Printf("Error: %s", err)
			return
		}
	}

}
