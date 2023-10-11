package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func PostToSplunk(QueryResults []byte, table string) error {
	SplunkUri := os.Getenv("SplunkUri")
	SplunkToken := os.Getenv("SplunkToken")

	jsonStr := string(QueryResults)

	// Parse JSON array
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return err
	}

	// Create payload slice
	var payload []map[string]interface{}
	for _, item := range items {
		payload = append(payload, map[string]interface{}{
			"event":      item,
			"sourcetype": table,
		})
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", SplunkUri, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", SplunkToken))
	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with custom transport to disable SSL verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Send HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
