[![license](https://img.shields.io/github/license/olafhartong/DefenderHarvester.svg?style=flat-square)](https://github.com/olafhartong/DefenderHarvester/blob/main/LICENSE)
![Maintenance](https://img.shields.io/maintenance/yes/2023.svg?style=flat-square)
[![Twitter](https://img.shields.io/twitter/follow/olafhartong.svg?style=social&label=Follow)](https://twitter.com/olafhartong)


![Defender Harvester](defenderharvester-logo.png)
# Defender Harvester

This tools tries to expose a lot of telemetry that is not easily accessible in any searchable form.

Sadly this not available over the publicly supported API, so this tool uses the internal API to get the data. Also the Unified Audit logs does not have this data, so this tool is the only way to get it. (that I am aware of)

More information in this blog post; [Microsoft Defender for Endpoint Internals 0x05 - Telemetry for sensitive actions](https://medium.com/@olafhartong)

**NOTE:**
All data is collected from the MDE Service API, and is not supported by Microsoft. Use at your own risk.

# Getting Started

Make sure to have the following installed:
- [Azure Cli](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)

Log in to Azure with an account that has access to M365D / MDE:
```bash
az login --use-device-code
```

In order to write to Sentinel you need the following environment variables set:

```bash
export SentinelWorkspaceID=<workspace id>
export SentinelSharedKey="<sentinel shared key>"
```

For Splunk you need create an HTTP Event Collector (HEC) endpoint and the following environment variables set:

```bash
export SplunkUri=<splunk host>
export SplunkToken=<hec token>
```

```
Usage of ./defenderharvester:
  -connectedapps
    	enable querying the Connected App Statistics
  -customdetections
    	enable querying the Custom Detection state
  -executedqueries
    	enable querying the Executed Queries
  -featuresettings
    	enable querying the Advanced Feature Settings
  -files
    	enable writing to files
  -lookback int
    	set the number of hours to query from the applicable sources (default 1)
  -machineactions
    	enable querying the MachineActions / LiveResponse actions
  -machinegroups
    	enable querying the Machine Groups
  -machineid string
    	set the MachineId to query the timeline for
  -schema
    	enable writing the MDE schema reference to a file - will never write to Sentinel
  -sentinel
    	enable sending to Sentinel
  -splunk
    	enable sending to Splunk
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
- Configured Machine Groups (MdeMachineGroups)
- Connected App Registrations, and their use (MdeConnectedAppStats)
- All executed queries Scheduled/API/Portal (MdeExecutedQueries)
- Timeline events for devices (MdeTimelineEvens)
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
