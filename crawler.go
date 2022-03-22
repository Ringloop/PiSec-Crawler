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

const SERVERURL = "http://164.68.107.9:8080/api/v1/indicator/url"

func getBulkRequests() []source.UrlsBulkRequest {

	stringData, dataErr := phishstats.ReadData()
	if dataErr != nil {
		panic(dataErr)
	}

	_, data, err := phishstats.ExtractCsvData(stringData)

	if err != nil {
		panic(err)
	}

	psData := phishstats.ParseCsvData(data)
	return phishstats.GetBulkRequests(psData)
}

func getJsonFromRequest(bRequest source.UrlsBulkRequest) []byte {
	jsonPs, err := json.Marshal(bRequest)
	if err != nil {
		panic(err)
	}
	return jsonPs
}

func getHttpRequest(jsonPs []byte) *http.Request {
	request, error := http.NewRequest("POST", SERVERURL, bytes.NewBuffer(jsonPs))
	if error != nil {
		panic(error)
	}

	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	return request
}

func getMessageForServer(bRequest source.UrlsBulkRequest) *http.Request {
	jsonPs := getJsonFromRequest(bRequest)
	request := getHttpRequest(jsonPs)
	return request
}

func sendRequestsToPiSecServer(client *http.Client, bRequest source.UrlsBulkRequest) {

	fmt.Println("going to send data to server: ", bRequest)

	request := getMessageForServer(bRequest)

	response, error := client.Do(request)
	if error != nil {
		panic(error)
	}
	defer response.Body.Close()

	fmt.Println("response Status:", response.Status)
	fmt.Println("response Headers:", response.Header)
	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println("response Body:", string(body))

}

func main() {

	client := &http.Client{}
	requests := getBulkRequests()

	for _, bRequest := range requests {
		sendRequestsToPiSecServer(client, bRequest)
	}
}
