package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/olafhartong/defenderharvester/cmd"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func main() {
	var lookback int
	var location string
	var sentinel bool
	var splunk bool
	var files bool
	var schema bool
	var timeline bool
	var machineID string
	var machineActions bool
	var customDetections bool
	var featureSettings bool
	var suppressionRules bool
	var machineGroups bool
	var connectedApps bool
	var executedQueries bool
	var alertServiceSettings bool
	var dataExportSettings bool
	var debug bool
	var accessToken string
	var token string
	flag.IntVar(&lookback, "lookback", 1, "set the number of hours to query from the applicable sources")
	flag.StringVar(&location, "location", "weu", "set the Azure region to query, default is weu. Get yours via the dev tools in your browser, see the blog or in the README.")
	flag.BoolVar(&sentinel, "sentinel", false, "enable sending to Sentinel")
	flag.BoolVar(&splunk, "splunk", false, "enable sending to Splunk")
	flag.BoolVar(&files, "files", false, "enable writing to files")
	flag.BoolVar(&schema, "schema", false, "write the MDE schema reference to a file - will never write to Sentinel")
	flag.BoolVar(&timeline, "timeline", false, "gather the Timeline for a MachineId (requires -machineid and -lookback)")
	flag.StringVar(&machineID, "machineid", "", "set the MachineId to query the timeline for")
	flag.BoolVar(&machineActions, "machineactions", false, "enable querying the MachineActions / LiveResponse actions")
	flag.BoolVar(&customDetections, "customdetections", false, "enable querying the Custom Detection state")
	flag.BoolVar(&featureSettings, "featuresettings", false, "enable querying the Advanced Feature Settings")
	flag.BoolVar(&suppressionRules, "suppressionrules", false, "enable querying the Suppression rule Settings")
	flag.BoolVar(&machineGroups, "machinegroups", false, "enable querying the Machine Groups")
	flag.BoolVar(&connectedApps, "connectedapps", false, "enable querying the Connected App Statistics")
	flag.BoolVar(&executedQueries, "executedqueries", false, "enable querying the Executed Queries")
	flag.BoolVar(&alertServiceSettings, "alertservicesettings", false, "enable querying the M365 XDR Alert Service Settings")
	flag.BoolVar(&dataExportSettings, "dataexportsettings", false, "enable querying the M365 XDR Data Export Settings")
	flag.StringVar(&accessToken, "accesstoken", "", "bring your own access token")
	flag.BoolVar(&debug, "debug", false, "Provide debugging output")
	flag.Parse()

	fmt.Println("             ;@@@@;")
	fmt.Println("        '??@@@@%%@@@%?+.")
	fmt.Println("      '@@@@@@@@%%@@@@@@@@'")
	fmt.Println("     .@@@@@@@@@%%@@@@@@@@@'")
	fmt.Println("   ;@@@@@@@@@@@@%%@@@@@@@@@@+")
	fmt.Println("  '?@@@@@@#%%%%%%%%%%#@@@@@@?'")
	fmt.Println("   ?+';@@@@^^@@@@@@^^@@@+'+?")
	fmt.Println("      ;@@@'  '@@@@'  '@@@+")
	fmt.Println("       ;#@@@-@@@@@@-@@@%;	DefenderHarvester v0.9.9 - by Olaf Hartong")
	fmt.Println("        .?@@@@----@@@@?.	 ↳ Collects interesting events from MDE/M365D, of which")
	fmt.Println("          '+?%@@@@%?+'		   most are sadly only available on the ServiceAPI :|")
	fmt.Println("              .;;.")
	fmt.Println("")

	if accessToken != "" {
		log.Println("Using provided access token ...")
		token = accessToken
	} else {
		log.Println("Getting access token ...")
		accessToken, err := getToken()
		if err != nil {
			log.Fatalln(err)
		}
		token = accessToken
	}

	if schema {
		log.Println("Retrieving MDE schema reference ...")
		schemaEndpoint := "/api/ine/huntingservice/schema"
		APIlocation := "m365d-hunting-api-prd-" + location
		schemaQueryParams := ""
		hostname := getM365XDRDomainName(APIlocation, schemaEndpoint)
		if err := cmd.GetDataFromMDE(token, schemaEndpoint, schemaQueryParams, false, "MdeSchemaReference", true, false, debug, hostname); err != nil {
			log.Fatalln(err)
		}
		return
	}

	from := time.Now().UTC().Add(-time.Duration(lookback) * time.Hour).Format(time.RFC3339Nano)
	fromURL := url.QueryEscape(from)

	now := time.Now().UTC().Format("2006-01-02T15:04:05.999Z")
	nowURL := url.QueryEscape(now)
	log.Println("Starting run ...")
	log.Printf("Lookback set to %d hours\n", lookback)
	log.Printf("Querying From: %s to: %s\n", from, now)

	if timeline {
		log.Printf("Retrieving Timeline events for %s ...", machineID)
		log.Printf("Depending on the lookback, this can take a while, get some %s", "☕")
		TLEndpoint := fmt.Sprintf("/api/detection/experience/timeline/machines/%s/events/?machineId=%s&doNotUseCache=false&forceUseCache=false&fromDate=%s&pageSize=1000", machineID, machineID, fromURL)
		TLQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, TLEndpoint)
		if _, err := cmd.GetTimelineData(token, TLEndpoint, TLQueryParams, sentinel, "MdeTimeline", true, from, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if machineActions {
		log.Println("Retrieving Action Center History ...")
		ACendpoint := "/api/autoir/actioncenterui/history-actions"
		ACqueryParams := fmt.Sprintf("/?useMtpApi=true&pageIndex=1&fromDate=%s&toDate=%s&sortByField=eventTime&sortOrder=Descending", fromURL, nowURL)
		APIlocation := "m365d-autoir-ac-prd-" + location
		hostname := getM365XDRDomainName(APIlocation, ACendpoint)
		if err := cmd.GetDataFromMDE(token, ACendpoint, ACqueryParams, sentinel, "MdeMachineActions", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}

		log.Println("Retrieving Machine Actions ...")
		MAEndpoint := "/api/machineactions?$filter=lastUpdateDateTimeUtc"
		MAquery := fmt.Sprintf(" ge %s", from)
		escapedQuery := url.QueryEscape(MAquery)
		MAQueryParams := strings.ReplaceAll(escapedQuery, "+", "%20")
		APIlocation = "wdatpprd-" + location
		hostname = getM365XDRDomainName(APIlocation, MAEndpoint)
		if err := cmd.GetDataFromMDEAPI(token, MAEndpoint, MAQueryParams, sentinel, "MdeMachineActionsApi", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if customDetections {
		log.Println("Retrieving Custom Detection state ...")
		CDendpoint := "/api/ine/huntingservice/rules"
		CDqueryParams := "?pageIndex=1&pageSize=1000&sortOrder=Descending"
		APIlocation := "m365d-hunting-api-prd-" + location
		hostname := getM365XDRDomainName(APIlocation, CDendpoint)
		if err := cmd.GetDataFromMDE(token, CDendpoint, CDqueryParams, sentinel, "MdeCustomDetectionState", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if featureSettings {
		log.Println("Retrieving Advanced Feature Settings ...")
		tenantEndpoint := "/api/settings/GetAdvancedFeaturesSetting"
		tenantQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, tenantEndpoint)
		if err := cmd.GetDataFromMDE(token, tenantEndpoint, tenantQueryParams, sentinel, "MdeAdvancedFeatureSettings", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if suppressionRules {
		log.Println("Retrieving Advanced Feature Settings ...")
		tenantEndpoint := "/api/ine/suppressionrulesservice/suppressionRules"
		tenantQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, tenantEndpoint)
		if err := cmd.GetDataFromMDE(token, tenantEndpoint, tenantQueryParams, sentinel, "MdeAdvancedFeatureSettings", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if machineGroups {
		log.Println("Retrieving Machine Groups ...")
		settingsEndpoint := "/rbac/machine_groups"
		settingsQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, settingsEndpoint)
		if err := cmd.GetDataFromMDE(token, settingsEndpoint, settingsQueryParams, sentinel, "MdeMachineGroups", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if connectedApps {
		log.Println("Retrieving Connected App Statistics ...")
		conAppsEndpoint := "/api/cloud/portal/apps/all"
		conAppsQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, conAppsEndpoint)
		if err := cmd.GetDataFromMDE(token, conAppsEndpoint, conAppsQueryParams, sentinel, "MdeConnectedAppStats", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if executedQueries {
		log.Println("Retrieving Executed Queries Scheduled/API/Portal ...")
		ranQueriesEndpoint := "/api/ine/huntingservice/reports"
		query := fmt.Sprintf(`{"startTime":"%s","endTime":"%s"}`, from, now)
		ranQueriesQueryParams := []byte(query)
		APIlocation := "m365d-hunting-api-prd-" + location
		hostname := getM365XDRDomainName(APIlocation, ranQueriesEndpoint)
		if err := cmd.PostDataToMDE(token, ranQueriesEndpoint, ranQueriesQueryParams, sentinel, "MdeExecutedQueries", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if alertServiceSettings {
		log.Println("Retrieving M365 XDR Alert Service Settings ...")
		// hostname default: m365duseprd-weu3.securitycenter.windows.com
		alertServiceSettingsEndpoint := "/api/ine/alertsapiservice/workloads/disabled"
		alertServiceSettingsQueryParams := "?includeDetails=true"
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, alertServiceSettingsEndpoint)
		if err := cmd.GetDataFromMDEAPI(token, alertServiceSettingsEndpoint, alertServiceSettingsQueryParams, sentinel, "M365AlertServiceSettings", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}

	if dataExportSettings {
		log.Println("Retrieving Data Export Settings ...")
		// location default: api-eu.securitycenter.windows.com
		dataExportSettingsEndpoint := "/api/dataexportsettings"
		dataExportSettingsQueryParams := ""
		APIlocation := "wdatpprd-" + location
		hostname := getM365XDRDomainName(APIlocation, dataExportSettingsEndpoint)
		if err := cmd.GetDataFromMDEAPI(token, dataExportSettingsEndpoint, dataExportSettingsQueryParams, sentinel, "M365DataExportSettings", files, splunk, debug, hostname); err != nil {
			log.Fatalln(err)
		}
	}
}

func getToken() (string, error) {
	resource := "https://securitycenter.microsoft.com/mtp"
	tokenCredential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create credential: %w", err)
	}
	token, err := tokenCredential.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{resource + "/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return token.Token, nil
}

func getM365XDRDomainName(location string, url string) string {
	if strings.Contains(location, "wdatpprd-weu3") {
		if url == "/api/dataexportsettings" || strings.Contains(url, "/api/machineactions") {
			return "api-eu"
		} else if url == "/api/ine/alertsapiservice/workloads/disabled" {
			return "m365duseprd-weu3"
		} else if url == "/api/settings/GetAdvancedFeaturesSetting" {
			return "wdatpprd-eu3"
		} else {
			return location
		}
	} else if strings.Contains(location, "wdatpprd-weu") {
		if url == "/api/dataexportsettings" || strings.Contains(url, "/api/machineactions") {
			return "api-eu"
		} else if url == "/api/ine/alertsapiservice/workloads/disabled" {
			return "m365duseprd-weu"
		} else if url == "/api/settings/GetAdvancedFeaturesSetting" {
			return "wdatpprd-eu"
		} else {
			return location
		}
	} else if strings.Contains(location, "wdatpprd-eus3") {
		if url == "/api/dataexportsettings" || strings.Contains(url, "/api/machineactions") {
			return "api-us"
		} else if url == "/api/ine/alertsapiservice/workloads/disabled" {
			return "m365duseprd-eus3"
		} else if url == "/api/settings/GetAdvancedFeaturesSetting" {
			return "wdatpprd-us3"
		} else {
			return location
		}
	} else if strings.Contains(location, "wdatpprd-eus") {
		if url == "/api/dataexportsettings" || strings.Contains(url, "/api/machineactions") {
			return "api-us"
		} else if url == "/api/ine/alertsapiservice/workloads/disabled" {
			return "m365duseprd-eus"
		} else if url == "/api/settings/GetAdvancedFeaturesSetting" {
			return "wdatpprd-us"
		} else {
			return location
		}
	} else {
		return location
	}
}
