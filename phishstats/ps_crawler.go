package phishstats

import (
	"fmt"
	"io"
	"net/http"
)

const url = "https://phishstats.info/phish_score.csv"

func ReadData() (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		bodyString := string(bodyBytes)
		return bodyString, nil
	}

	return "", fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
}
