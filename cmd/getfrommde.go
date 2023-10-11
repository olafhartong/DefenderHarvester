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

type MachineActions struct {
	Value   []interface{} `json:"value"`
	Results []interface{} `json:"Results"`
}

type MachineGroups struct {
	Items []interface{} `json:"items"`
}

func GetDataFromMDE(accessToken string, endpoint string, queryParams string, sentinel bool, table string, files bool, splunk bool) error {
	resource := "https://wdatpprd-weu.securitycenter.windows.com"
	url := resource + endpoint + queryParams

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

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

	if files {
		runTime := time.Now().Format("20060102-150405")
		filename := runTime + "-" + table + ".json"
		log.Printf("↳ Writing to %s\n", filename)
		err = os.WriteFile(filename, body, 0644)
		if err != nil {
			return fmt.Errorf("failed to write response body to file: %w", err)
		}
	}

	if splunk && table == "MdeMachineActions" {
		var ma MachineActions
		if err := json.Unmarshal(body, &ma); err != nil {
			return err
		}
		body, err = json.Marshal(ma.Results)
		if err != nil {
			return err
		}
		log.Printf("Sending events to Splunk\n")
		err = PostToSplunk(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Splunk: %w", err)
		}
	} else if splunk && table == "MdeMachineGroups" {
		var ma MachineGroups
		if err := json.Unmarshal(body, &ma); err != nil {
			return err
		}
		body, err = json.Marshal(ma.Items)
		if err != nil {
			return err
		}
		log.Printf("Sending events to Splunk\n")
		err = PostToSplunk(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Splunk: %w", err)
		}
	} else if splunk && table != "" {
		log.Printf("Sending events to Splunk\n")
		err = PostToSplunk(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Splunk: %w", err)
		}
	} else {
		return nil
	}

	if sentinel && table == "MdeMachineActions" {
		var ma MachineActions
		if err := json.Unmarshal(body, &ma); err != nil {
			return err
		}
		body, err = json.Marshal(ma.Results)
		if err != nil {
			return err
		}
		err = SendToSentinel(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Sentinel: %w", err)
		}
	} else if sentinel && table == "MdeMachineGroups" {
		var ma MachineGroups
		if err := json.Unmarshal(body, &ma); err != nil {
			return err
		}
		body, err = json.Marshal(ma.Items)
		if err != nil {
			return err
		}
		err = SendToSentinel(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Sentinel: %w", err)
		}
	} else if sentinel && table != "" {
		err = SendToSentinel(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Sentinel: %w", err)
		}
	} else {
		return nil
	}

	return nil
}

func GetDataFromMDEAPI(accessToken string, endpoint string, queryParams string, sentinel bool, table string, files bool, splunk bool) error {
	resource := "https://api-eu.securitycenter.windows.com"
	url := resource + endpoint + queryParams

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

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
		log.Printf("Sending events to Splunk\n")
		err = PostToSplunk(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Splunk: %w", err)
		}
	}

	if sentinel && table != "" {
		var ma MachineActions
		if err := json.Unmarshal(body, &ma); err != nil {
			return err
		}
		body, err = json.Marshal(ma.Value)
		if err != nil {
			return err
		}
		err = SendToSentinel(body, table)
		if err != nil {
			return fmt.Errorf("failed to write response body to Sentinel: %w", err)
		}
	} else {
		return nil
	}

	return nil
}
