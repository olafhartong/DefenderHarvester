package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type TimelineData struct {
	Items []interface{} `json:"Items"`
	Prev  string        `json:"Prev"`
	Next  string        `json:"Next"`
}

func GetTimelineData(accessToken string, endpoint string, queryParams string, sentinel bool, table string, files bool, from string, splunk bool, debug bool) (*TimelineData, error) {
	resource := "https://wdatpprd-weu.securitycenter.windows.com"
	url := resource + endpoint + queryParams

	timelineData := &TimelineData{}
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("request failed with status code %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		tempData := &TimelineData{}
		err = json.Unmarshal(body, &tempData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
		}

		timelineData.Items = append(timelineData.Items, tempData.Items...)

		if tempData.Prev == "" {
			log.Printf("Done, retrieved %d events\n", len(timelineData.Items))
			break
		}
		url = resource + "/api/detection/experience/timeline" + tempData.Prev
		// fmt.Println("retrieving next from > ", url)
		log.Printf("Running, retrieved %d events\n", len(timelineData.Items))
	}

	if debug {
		fmt.Printf("%+v\n", timelineData)
	}

	if files {
		runTime := time.Now().Format("20060102-150405")
		filename := runTime + "-" + table + ".json"
		data, _ := json.MarshalIndent(timelineData.Items, "", "  ")
		log.Printf("Writing %d events to %s\n", len(timelineData.Items), filename)
		os.WriteFile(filename, data, 0644)
	}

	if splunk {
		log.Printf("Sending %d events to Splunk\n", len(timelineData.Items))
		jsondata, _ := json.Marshal(timelineData.Items)
		PostToSplunk(jsondata, table)
	}

	if sentinel {
		batchSize := 1000
		numBatches := (len(timelineData.Items) + batchSize - 1) / batchSize
		log.Printf("Sending %d events to Sentinel in %d batches\n", len(timelineData.Items), numBatches)

		for i := 0; i < numBatches; i++ {
			start := i * batchSize
			end := (i + 1) * batchSize
			if end > len(timelineData.Items) {
				end = len(timelineData.Items)
			}
			batch := timelineData.Items[start:end]
			body, err := json.Marshal(batch)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal response body: %w", err)
			}
			if !json.Valid(body) {
				return nil, fmt.Errorf("invalid JSON in batch %d", i)
			}
			SendToSentinel(body, table)
		}
	}

	return timelineData, nil
}
