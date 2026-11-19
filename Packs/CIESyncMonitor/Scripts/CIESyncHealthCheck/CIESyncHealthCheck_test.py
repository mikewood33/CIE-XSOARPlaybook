"""Unit tests for the Cloud Identity Engine sync and syslog check."""

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

demisto_stub = types.ModuleType("demistomock")
demisto_stub.executeCommand = lambda name, args: []
demisto_stub.incident = lambda: {"id": "job"}
demisto_stub.args = lambda: {}
demisto_stub.debug = lambda message: None
demisto_stub.error = lambda message: None
sys.modules["demistomock"] = demisto_stub

common_stub = types.ModuleType("CommonServerPython")


class CommandResults:  # pylint: disable=too-few-public-methods
    def __init__(self, **kwargs):
        self.kwargs = kwargs


common_stub.CommandResults = CommandResults
common_stub.return_results = lambda result: None
common_stub.return_error = lambda message: (_ for _ in ()).throw(RuntimeError(message))
sys.modules["CommonServerPython"] = common_stub

import CIESyncHealthCheck as health  # noqa: E402


NOW = datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc)


def at_minutes(minutes: int) -> str:
    return (NOW - timedelta(minutes=minutes)).strftime("%Y/%m/%d %H:%M:%S")


class Commander:
    def __init__(self, stats: str, incidents_total: int = 1, logs: list | None = None, state: dict | None = None):
        self.stats = stats
        self.incidents_total = incidents_total
        self.logs = logs or []
        self.state = state if state is not None else {"version": 1, "devices": {}}
        self.calls: list[tuple[str, dict]] = []
        self.created: list[dict] = []

    def __call__(self, name: str, args: dict):
        self.calls.append((name, dict(args)))
        if name == "getList":
            return [{"Type": 1, "Contents": json.dumps(self.state)}]
        if name in {"setList", "createList"}:
            if name == "setList":
                self.state = json.loads(args["listData"])
            return [{"Type": 1, "Contents": "ok"}]
        if name == "getIncidents":
            query = args.get("query", "")
            if "CIE Sync Failure" in query:
                return [{"Type": 1, "Contents": {"data": [], "total": 0}}]
            data = [{"id": "9", "details": "cie heartbeat"}] if self.incidents_total else []
            return [{"Type": 1, "Contents": {"data": data, "total": self.incidents_total}}]
        if name == "createNewIncident":
            self.created.append(args)
            return [{"Type": 1, "Contents": {"id": "42", "name": args.get("name")}}]
        if name == "panorama":
            if args.get("type") == "log":
                return [{"Type": 1, "Contents": {"response": {"@status": "success", "result": self._log_result()}}}]
            return [{"Type": 1, "Contents": self.stats}]
        if name in {"setIncident", "send-mail", "linkIncidents"}:
            return [{"Type": 1, "Contents": "ok"}]
        raise AssertionError(f"unexpected command {name}")

    def _log_result(self) -> dict:
        if not self.logs:
            return {"job": {"id": "10", "status": "FIN"}, "log": {"logs": {"@count": "0"}}}
        return {
            "job": {"id": "10", "status": "FIN"},
            "log": {"logs": {"@count": str(len(self.logs)), "entry": self.logs}},
        }

    def names(self) -> list[str]:
        return [name for name, _args in self.calls]


def base_args(**overrides) -> dict:
    args = {
        "devices": "edge",
        "use_target": "false",
        "api_command": "panorama",
        "sync_max_age_minutes": "60",
        "syslog_max_age_minutes": "60",
        "syslog_heartbeat_source": "disabled",
        "check_firewall_logs": "false",
        "device_time_offset_minutes": "0",
        "notify_email": "",
    }
    args.update(overrides)
    return args


def stats_text(last_success: str, total: int = 6) -> str:
    return "\n".join(
        [
            "Dir Sync Profile : corp-cie",
            "Last Query (Total Time Taken): 271.246232ms",
            f"Total Updates : {total}",
            "No of Full Group Queries : 4",
            "No of Incr Group Queries : 2",
            f"Last success time: {last_success}",
        ]
    )


def test_parse_timestamp_applies_firewall_offset():
    parsed = health.parse_timestamp("2026/11/19 15:00:00", -300)
    assert parsed == datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc)


def test_cli_sample_extracts_profile_time_and_counter():
    signals = health.signals_from_payload(stats_text(at_minutes(20)), "cie", 0)
    assert len(signals) == 1
    assert signals[0].profile == "corp-cie"
    assert signals[0].counter == 6
    assert signals[0].last_success == NOW - timedelta(minutes=20)


def test_xml_statistics_extract_epoch_and_ignore_unrelated_group_mapping():
    moment = NOW - timedelta(minutes=15)
    payload = f"""
    <response status="success">
      <result>
        <entry name="corp-cie">
          <last-update-time>{int(moment.timestamp())}</last-update-time>
          <total-updates>8</total-updates>
          <last-error></last-error>
        </entry>
      </result>
    </response>
    """
    signals = health.signals_from_payload(payload, "cie", 0)
    assert signals[0].profile == "corp-cie"
    assert signals[0].counter == 8
    assert abs((signals[0].last_success - moment).total_seconds()) < 2

    ldap = "Group Mapping(vsys1, type: active-directory): corp\nLast update time: 2020/01/01 00:00:00\n"
    assert health.signals_from_payload(ldap, "group-mapping", 0) == []


def test_panos_error_response_is_reported():
    payload = {"response": {"@status": "error", "msg": {"line": "invalid command"}}}
    assert health.panos_error_message(payload) == "invalid command"


def test_classify_cas_message_and_syslog_connection():
    assert health.classify_system_log({"eventid": "cas-message", "opaque": "certificate expired"}) == "cas_message"
    assert (
        health.classify_system_log({"eventid": "syslog-conn-status", "opaque": "syslog connection failed to 10.0.0.5"})
        == "syslog_down"
    )
    assert (
        health.classify_system_log({"eventid": "syslog-conn-status", "opaque": "syslog connection established"}) is None
    )


def test_fresh_sync_is_healthy_and_stores_state():
    commander = Commander(stats_text(at_minutes(20)))
    result = health.run_check(base_args(), commander, NOW, "job-1", lambda _seconds: None)
    assert result["Status"] == "Healthy"
    assert result["AlertCount"] == 0
    assert result["Devices"][0]["Sync"] == "fresh"
    assert "createNewIncident" not in commander.names()
    assert commander.state["devices"]["edge"]["profiles"]["corp-cie"]["counter"] == 6
    assert "No sync or syslog findings" in result["Summary"]
    assert "15:00:00 ET" in result["Summary"]


def test_stale_timestamp_opens_one_alert():
    commander = Commander(stats_text(at_minutes(95)))
    result = health.run_check(
        base_args(notify_email="soc@example.com", devices="edge:012345", use_target="true"),
        commander,
        NOW,
        "job-1",
        lambda _seconds: None,
    )
    assert result["Status"] == "Alert"
    assert result["Severity"] == "High"
    assert result["AlertIncidentID"] == "42"
    assert result["Alerts"][0]["Kind"] == "sync_stale"
    assert commander.created[0]["type"] == "CIE Sync Failure"
    assert commander.created[0]["severity"] == "High"
    assert any(name == "send-mail" and args["to"] == "soc@example.com" for name, args in commander.calls)
    op_calls = [args for name, args in commander.calls if name == "panorama" and args.get("type") == "op"]
    assert op_calls[0]["target"] == "012345"


def test_counter_baseline_then_stale_when_it_does_not_increase():
    text = "Dir Sync Profile : corp-cie\nTotal Updates : 6\n"
    commander = Commander(text)
    first = health.run_check(base_args(), commander, NOW, "job-1", lambda _seconds: None)
    assert first["Status"] == "Healthy"
    assert first["Devices"][0]["Sync"] == "baseline"
    assert "createNewIncident" not in commander.names()

    second = health.run_check(base_args(), commander, NOW + timedelta(minutes=90), "job-2", lambda _seconds: None)
    assert second["Status"] == "Alert"
    assert any(alert["Kind"] == "sync_stale" for alert in second["Alerts"])


def test_counter_increase_stays_healthy():
    commander = Commander("Dir Sync Profile : corp-cie\nTotal Updates : 6\n")
    health.run_check(base_args(), commander, NOW, "job-1", lambda _seconds: None)
    commander.stats = "Dir Sync Profile : corp-cie\nTotal Updates : 7\n"
    result = health.run_check(base_args(), commander, NOW + timedelta(minutes=90), "job-2", lambda _seconds: None)
    assert result["Status"] == "Healthy"
    assert result["Devices"][0]["Sync"] == "fresh"


def test_cas_message_is_critical_even_when_sync_is_fresh():
    commander = Commander(
        stats_text(at_minutes(10)),
        logs=[{"eventid": "cas-message", "opaque": "Cloud Identity Engine certificate expired", "device_name": "edge"}],
    )
    result = health.run_check(base_args(check_firewall_logs="true"), commander, NOW, "job-1", lambda _seconds: None)
    assert result["Severity"] == "Critical"
    assert any(alert["Kind"] == "cas_message" for alert in result["Alerts"])


def test_missing_syslog_heartbeat_alerts():
    commander = Commander(stats_text(at_minutes(10)), incidents_total=0)
    result = health.run_check(
        base_args(syslog_heartbeat_source="xsoar-incidents", syslog_heartbeat_query='type:"CIE Syslog"'),
        commander,
        NOW,
        "job-1",
        lambda _seconds: None,
    )
    assert any(alert["Kind"] == "syslog_silent" for alert in result["Alerts"])
    incident_queries = [args["query"] for name, args in commander.calls if name == "getIncidents"]
    assert any('type:"CIE Syslog"' in query and "occurred:>=" in query for query in incident_queries)


def test_sync_failure_text_in_heartbeat_is_critical():
    commander = Commander(stats_text(at_minutes(10)), incidents_total=1)
    commander_call = commander.__call__

    def incidents(name, args):
        if name == "getIncidents" and "CIE Sync Failure" not in args.get("query", ""):
            commander.calls.append((name, dict(args)))
            return [
                {
                    "Type": 1,
                    "Contents": {"data": [{"id": "9", "details": "event_state=SYNC_FAILURE directory corp"}], "total": 1},
                }
            ]
        return commander_call(name, args)

    result = health.run_check(
        base_args(syslog_heartbeat_source="xsoar-incidents"),
        incidents,
        NOW,
        "job-1",
        lambda _seconds: None,
    )
    assert any(alert["Kind"] == "sync_failed" for alert in result["Alerts"])
    assert result["Severity"] == "Critical"


def test_explicit_firewall_error_is_sync_failed():
    text = "Dir Sync Profile : corp-cie\nLast success time: " + at_minutes(5) + "\nLast error: directory unreachable\n"
    commander = Commander(text)
    result = health.run_check(base_args(), commander, NOW, "job-1", lambda _seconds: None)
    assert any(alert["Kind"] == "sync_failed" for alert in result["Alerts"])


def test_bad_api_command_does_not_call_the_firewall():
    commander = Commander(stats_text(at_minutes(5)))
    result = health.run_check(base_args(api_command="ssh"), commander, NOW, "job-1", lambda _seconds: None)
    assert result["Alerts"][0]["Kind"] == "configuration"
    assert "panorama" not in commander.names()
    assert "createNewIncident" in commander.names()


def test_existing_alert_is_updated_instead_of_created():
    commander = Commander(stats_text(at_minutes(120)))
    original = commander.__call__

    def routed(name, args):
        if name == "getIncidents" and "CIE Sync Failure" in args.get("query", ""):
            commander.calls.append((name, dict(args)))
            return [{"Type": 1, "Contents": {"data": [{"id": "7"}, {"id": "3"}], "total": 2}}]
        return original(name, args)

    result = health.run_check(base_args(), routed, NOW, "job-1", lambda _seconds: None)
    assert result["AlertIncidentID"] == "3"
    assert not commander.created
    assert any(name == "setIncident" and args.get("id") == "3" for name, args in commander.calls)


def test_created_incident_id_is_read_from_entry_context():
    commander = Commander(stats_text(at_minutes(120)))
    original = commander.__call__

    def routed(name, args):
        if name == "createNewIncident":
            commander.calls.append((name, dict(args)))
            commander.created.append(args)
            return [{"Type": 1, "Contents": "Incident created", "EntryContext": {"CreatedIncidentID": "88"}}]
        return original(name, args)

    result = health.run_check(base_args(), routed, NOW, "job-1", lambda _seconds: None)
    assert result["AlertIncidentID"] == "88"


def test_op_command_error_is_a_check_error_not_a_healthy_result():
    commander = Commander(stats_text(at_minutes(5)))
    original = commander.__call__

    def routed(name, args):
        if name == "panorama" and args.get("type") == "op":
            commander.calls.append((name, dict(args)))
            return [{"Type": 4, "Contents": "API key invalid"}]
        return original(name, args)

    result = health.run_check(base_args(), routed, NOW, "job-1", lambda _seconds: None)
    assert result["Status"] == "Alert"
    assert result["Devices"][0]["Sync"] == "error"
    assert "API key invalid" in result["Devices"][0]["Detail"]
