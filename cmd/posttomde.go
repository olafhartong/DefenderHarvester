package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func PostDataToMDE(accessToken string, endpoint string, requestBody []byte, sentinel bool, table string, files bool, splunk bool, debug bool, location string) error {
	resource := fmt.Sprintf("https://%s.securitycenter.windows.com", location)
	url := resource + endpoint

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0 OS/10.0.22621")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if debug {
		var prettyJSON bytes.Buffer
		error := json.Indent(&prettyJSON, body, "", "\t")
		if error != nil {
			log.Println("JSON parse error: ", error)
			return error
		}
		fmt.Printf("%s\n", prettyJSON.Bytes())
	}

	if files {
		runTime := time.Now().Format("20060102-150405")
		filename := runTime + "-" + table + ".json"
		log.Printf("↳ Writing to %s\n", filename)
		err = os.WriteFile(filename, body, 0644)
		if err != nil {
			return fmt.Errorf("failed to write response body to file: %w", err)
		}
	}

	if splunk {
		jsondata, _ := json.Marshal(body)
		log.Printf("Sending events to Splunk\n")
		PostToSplunk(jsondata, table)
	}

	if sentinel && table != "" {
		err = SendToSentinel(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Sentinel: %w", err)
		}
	}

	return nil
}
