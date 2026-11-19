Hourly Cloud Identity Engine check for Cortex XSOAR. Alerts when an NGFW has not synced CIE directory data within the threshold, when the firewall logs a CIE or syslog failure, or when expected CIE syslog stops.

Schedule it as a time-triggered job with cron `0 * * * *`. The playbook closes its own job incident after every run. Findings stay open on a **CIE Sync Failure** incident. Do not attach this playbook to that incident type.

Full communication diagram, API role, and job steps are in the pack README and the repository README.

## Dependencies

### Integrations

* Palo Alto Networks PAN-OS (Panorama or firewall)

### Scripts

* CIESyncHealthCheck

### Commands

* panorama or pan-os
* getIncidents
* getList
* setList
* createList
* createNewIncident
* setIncident
* closeInvestigation
* send-mail (only when NotifyEmail is set)
* xdr-xql-generic-query (only when the heartbeat source is xsiam-xql)

## Inputs

| Name | Description | Default |
| --- | --- | --- |
| Devices | `name:serial` pairs. Empty queries the integration instance. |  |
| Using | PAN-OS integration instance name. |  |
| ApiCommand | `panorama` or `pan-os`. | panorama |
| UseTarget | Pass serials as the API target. | true |
| SyncMaxAgeMinutes | Age that means a missed sync. | 60 |
| SyslogMaxAgeMinutes | Age that means silent syslog. | 60 |
| SyslogHeartbeatSource | `xsoar-incidents`, `pan-os-log`, `xsiam-xql`, or `disabled`. | xsoar-incidents |
| SyslogHeartbeatQuery | Query that should return CIE syslog. | type:"CIE Syslog" |
| DeviceTimeOffsetMinutes | Firewall clock offset from UTC, in minutes. | 0 |
| NotifyEmail | Alert email. Empty skips mail. |  |
| AlertIncidentType | Incident type for findings. | CIE Sync Failure |
| StateListName | List that stores update counters. | CIE-Sync-Monitor-State |
| CheckFirewallLogs | Read `cas-message` and `syslog-conn-status`. | true |
| QueryEachDevice | Query logs on each firewall instead of Panorama. | false |

## Outputs

| Path | Description |
| --- | --- |
| CIE.Health.Status | Healthy or Alert. |
| CIE.Health.AlertIncidentID | Open CIE Sync Failure incident. |
| CIE.Health.Summary | Markdown report for the run. |
