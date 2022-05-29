package main

import (
	"PiSec-Crawler/phishstats"
	"net/http"
)

func main() {

	client := &http.Client{}

	stringData, dataErr := phishstats.ReadData()
	if dataErr != nil {
		panic(dataErr)
	}

	requests := phishstats.GetBulkRequests(stringData)

	for _, bRequest := range requests {
		phishstats.SendRequestsToPiSecServer(client, bRequest)
	}
}
