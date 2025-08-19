[![license](https://img.shields.io/github/license/olafhartong/DefenderHarvester.svg?style=flat-square)](https://github.com/olafhartong/DefenderHarvester/blob/main/LICENSE)
![Maintenance](https://img.shields.io/maintenance/yes/2024.svg?style=flat-square)
[![Twitter](https://img.shields.io/twitter/follow/olafhartong.svg?style=social&label=Follow)](https://twitter.com/olafhartong)


![Defender Harvester](defenderharvester-logo.png)
# Defender Harvester

## NOTICE: Microsoft has added additional protection on the service APIs this tool is leveraging. This prevents us from bypassing the API proxy and essentially kills this tool for now. I'm investigating a workaround.

This tools tries to expose a lot of telemetry that is not easily accessible in any searchable form.

Sadly this not available over the publicly supported API, so this tool uses the internal API to get the data. Also the Unified Audit logs does not have this data, so this tool is the only way to get it. (that I am aware of)

More information in this blog post; [Microsoft Defender for Endpoint Internals 0x05 - Telemetry for sensitive actions](https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x05-telemetry-for-sensitive-actions-1b90439f5c25)

**NOTE:**
All data is collected from the MDE Service API, and is not supported by Microsoft. Use at your own risk.

# Installation

Make sure to have the following installed:
- [Azure Cli](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)

Defender Harvester is published through [releases](https://github.com/olafhartong/DefenderHarvester/releases/latest) or can be installed through Go:
```bash
go install github.com/olafhartong/defenderharvester@latest
```

# Getting Started

Log in to Azure with an account that has access to M365D / MDE:
```bash
az login --use-device-code
```

In order to write to Sentinel you need the following environment variables set:

```bash
export SentinelWorkspaceID=<workspace id>
export SentinelSharedKey="<sentinel shared key>"
```

or in PowerShell:
```powershell
$env:SentinelWorkspaceID="<workspace id>"
$env:Sentinel
```

For Splunk you need create an HTTP Event Collector (HEC) endpoint and the following environment variables set:

```bash
export SplunkUri=<splunk host>
export SplunkToken=<hec token>
```

or in PowerShell:
```powershell
$env:SplunkUri="<splunk host>"
$env:Splunk
```

# Usage

```
Usage of defenderharvester.exe:
  -accesstoken string
    	bring your own access token
  -alertservicesettings
    	enable querying the M365 XDR Alert Service Settings
  -connectedapps
    	enable querying the Connected App Statistics
  -customdetections
    	enable querying the Custom Detection state
  -dataexportsettings
    	enable querying the M365 XDR Data Export Settings
  -debug
    	Provide debugging output
  -executedqueries
    	enable querying the Executed Queries
  -featuresettings
    	enable querying the Advanced Feature Settings
  -files
    	enable writing to files
  -location string
    	set the Azure region to query, default is weu. Get yours via the dev tools in your browser, see the blog or in the README. (default "weu")
  -lookback int
    	set the number of hours to query from the applicable sources (default 1)
  -machineactions
    	enable querying the MachineActions / LiveResponse actions
  -machinegroups
    	enable querying the Machine Groups
  -machineid string
    	set the MachineId to query the timeline for
  -schema
    	write the MDE schema reference to a file - will never write to Sentinel
  -sentinel
    	enable sending to Sentinel
  -splunk
    	enable sending to Splunk
  -suppressionrules
    	enable querying the Suppression rule Settings
  -timeline
    	gather the Timeline for a MachineId (requires -machineid and -lookback)
```

## Get the MDE Schema reference in JSON

This will be written to a file, no point in ingesting this into Sentinel.
```
./defenderharvester -schema
```

## Get all interesting data from MDE

You can get the following events from MDE:
- (automated) LiveResponse events (MdeMachineActions)
- The state of your custom detections (MdeCustomDetectionState)
- Advanced feature settings (MdeAdvancedFeatureSettings)
- Suppression rules (MdeSuppressionRules)
- Configured Machine Groups (MdeMachineGroups)
- Connected App Registrations, and their use (MdeConnectedAppStats)
- All executed queries Scheduled/API/Portal (MdeExecutedQueries)
- Timeline events for devices (MdeTimelineEvents)
- The schema reference

This can be collected into files with the `-files` flag, or sent to Sentinel with the `-sentinel` flag, or both.

For example;
```bash
./defenderharvester -lookback 1 -machinections -files -sentinel
```

## Get the timeline for a MachineId and send it to Sentinel

You can get the timeline for a MachineId with the `-timeline` flag, this requires the `-machineid` and `-lookback` flags to be set.
This will be collected into a file and optionally can be sent to Sentinel with the `-sentinel` flag, where it will end up in the MdeTimeline table.
```bash
./defenderharvester -lookback 1 -machineid <machineid> -timeline -sentinel
```

## Comply with device filtered Conditional Access Policy

```powershell
# Use TokenTacticsV2 to get a 24h valid access token
Get-AzureToken -Client Custom -ClientID 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -Scope "https://securitycenter.microsoft.com/mtp/.default" -UseCAE

./defenderharvester.exe -location wdatpprd-weu3 -debug -accesstoken $response.access_token -schema

```


