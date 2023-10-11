package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func SendToSentinel(QueryResults []byte, table string) error {
	log.Println("↳ Sending data to Sentinel table:", table)

	customerId := os.Getenv("SentinelWorkspaceID")
	sharedKey := os.Getenv("SentinelSharedKey")
	logName := table
	timeStampField := "DateValue"

	dateString := time.Now().UTC().Format(time.RFC1123)
	dateString = strings.Replace(dateString, "UTC", "GMT", -1)

	stringToHash := "POST\n" + strconv.Itoa(len(QueryResults)) + "\napplication/json\n" + "x-ms-date:" + dateString + "\n/api/logs"
	hashedString, err := SentinelBuildSignature(stringToHash, sharedKey)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	signature := "SharedKey " + customerId + ":" + hashedString
	url := "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(QueryResults)))
	if err != nil {
		return err
	}

	req.Header.Add("Log-Type", logName)
	req.Header.Add("Authorization", signature)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-ms-date", dateString)
	req.Header.Add("time-generated-field", timeStampField)

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error sending data to Sentinel: ", err.Error())
		return err
	}
	if resp.StatusCode != 200 {
		log.Println("Error sending data to Sentinel: ", resp.Status)
		return err
	}

	return resp.Body.Close()
}

func SentinelBuildSignature(message, secret string) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
