Checks Cloud Identity Engine sync on Palo Alto Networks firewalls and whether CIE syslog is still arriving.

The automation is the check inside the **CIE - Sync and Syslog Monitor** playbook. Run that playbook from an hourly job. A missed sync, a CIE error, a syslog disconnect, or a silent syslog heartbeat opens or updates one **CIE Sync Failure** incident.

API keys stay in the PAN-OS integration instance. This automation only passes operational `show` commands and log queries.

## Arguments

| Argument | Default | Description |
| --- | --- | --- |
| devices |  | `name:serial` pairs separated by commas. Leave empty to query the integration instance itself. |
| using |  | PAN-OS or Panorama instance name. |
| api_command | panorama | `panorama` or `pan-os`. |
| use_target | true | Send the serial as the API target. Turn this off for a firewall instance. |
| sync_max_age_minutes | 60 | Alert when the newest sync evidence is at least this old. |
| syslog_max_age_minutes | 60 | Alert when the heartbeat has no events in this window. |
| syslog_heartbeat_source | xsoar-incidents | `xsoar-incidents`, `pan-os-log`, `xsiam-xql`, or `disabled`. |
| syslog_heartbeat_query | type:"CIE Syslog" | Query that should return at least one CIE syslog event per window. |
| device_time_offset_minutes | 0 | Firewall clock offset from UTC, in minutes. US Eastern Standard Time is -300. |
| notify_email |  | Address for the alert summary. |
| alert_incident_type | CIE Sync Failure | Incident type for findings. |
| state_list_name | CIE-Sync-Monitor-State | List used to remember update counters. |
| check_firewall_logs | true | Query `cas-message` and `syslog-conn-status`. |
| query_each_device | false | Query system logs on each serial instead of once on Panorama. |

## Outputs

`CIE.Health.Status` is `Healthy` or `Alert`. `CIE.Health.AlertIncidentID` is the open finding. `CIE.Health.Summary` is the markdown report.
