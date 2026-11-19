"""Check Cloud Identity Engine sync to PAN-OS firewalls and CIE syslog freshness.

An hourly Cortex XSOAR job runs this automation. It reads firewall operational
data through the Palo Alto Networks PAN-OS integration, compares that evidence
with the previous run, and opens or updates one CIE Sync Failure incident when
a firewall has not synced within the threshold or expected CIE syslog has stopped.
"""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import demistomock as demisto
from CommonServerPython import CommandResults, return_error, return_results

CIE_STATS_CMD = (
    "<show><user><cloud-identity-engine><statistics><all></all></statistics>"
    "</cloud-identity-engine></user></show>"
)
GROUP_STATS_CMD = "<show><user><group-mapping><statistics></statistics></group-mapping></user></show>"
FAILURE_LOG_QUERY = "((eventid eq 'cas-message') or (eventid eq 'syslog-conn-status'))"
DEFAULT_HEARTBEAT_QUERY = 'type:"CIE Syslog"'
DEFAULT_PANOS_HEARTBEAT_QUERY = "(opaque contains 'Cloud Identity')"
STATE_VERSION = 1
MAX_RESPONSE_CHARS = 2_000_000
HEARTBEAT_SOURCES = ("xsoar-incidents", "pan-os-log", "xsiam-xql", "disabled")
API_COMMANDS = ("panorama", "pan-os")
BENIGN_ERROR_VALUES = {"", "0", "none", "n/a", "na", "ok", "success", "succeeded", "-", "null", "no error"}
FAILURE_WORDS = (
    "fail",
    "failed",
    "failure",
    "down",
    "error",
    "lost",
    "unreachable",
    "disconnect",
    "refused",
    "timed out",
    "timeout",
)
KIND_TITLES = {
    "configuration": "Configuration",
    "sync_failed": "Sync failed",
    "sync_stale": "Sync older than the threshold",
    "cas_message": "Firewall logged a Cloud Identity Engine error",
    "syslog_down": "Syslog connection failed",
    "syslog_silent": "No CIE syslog in the window",
    "sync_check_error": "Could not read sync status",
    "syslog_check_error": "Could not read syslog",
}
KIND_RANK = {
    "configuration": 0,
    "sync_failed": 1,
    "cas_message": 2,
    "syslog_down": 3,
    "sync_stale": 4,
    "syslog_silent": 5,
    "sync_check_error": 6,
    "syslog_check_error": 7,
}
DEVICE_RANK = {"error": 0, "failed": 1, "stale": 2, "baseline": 3, "fresh": 4}
TIMESTAMP_RE = re.compile(
    r"(?im)^(?P<label>[A-Za-z][A-Za-z0-9_ ()/-]{0,80}?)\s*[:=]\s*"
    r"(?P<value>\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?|\d{10,13})\s*$"
)
COUNTER_RE = re.compile(
    r"(?im)^(?P<label>total[-\s_]*updates|no\.?\s*of\s*full\s*group\s*queries|"
    r"no\.?\s*of\s*incr\s*group\s*queries|full[-\s_]*group[-\s_]*quer(?:y|ies)|"
    r"incr(?:emental)?[-\s_]*group[-\s_]*quer(?:y|ies)|"
    r"num[-\s_]*full[-\s_]*quer(?:y|ies)|num[-\s_]*incr[-\s_]*quer(?:y|ies))"
    r"\s*[:=]\s*(?P<value>\d+)\s*$"
)
ERROR_RE = re.compile(
    r"(?im)^(?P<label>last[-\s_]*(?:error|failure|action[-\s_]*msg)|"
    r"failure[-\s_]*(?:reason|message))\s*[:=]\s*(?P<value>.*?)\s*$"
)
PROFILE_RE = re.compile(r"(?im)^dir(?:ectory)?\s*sync\s*profile\s*[:=]\s*(?P<name>.+?)\s*$")
CIE_TEXT_RE = re.compile(r"cloud[-\s]identity|\bcie\b", re.IGNORECASE)
INTERESTING_TOKENS = ("time", "update", "quer", "error", "fail", "success", "profile", "msg")

Commander = Callable[[str, dict[str, Any]], Any]
Sleeper = Callable[[float], None]


@dataclass
class Alert:
    kind: str
    device: str
    profile: str
    detail: str
    last_success: datetime | None = None

    def as_dict(self) -> dict[str, str]:
        if self.kind not in KIND_TITLES:
            raise KeyError(f"Unknown CIE alert kind: {self.kind}")
        return {
            "Kind": self.kind,
            "Title": KIND_TITLES[self.kind],
            "Device": self.device,
            "Profile": self.profile,
            "Detail": self.detail,
            "LastSuccess": isoformat(self.last_success),
        }


@dataclass
class SyncSignal:
    profile: str
    source: str
    last_success: datetime | None
    counter: int | None
    error: str | None

    def has_evidence(self) -> bool:
        return self.last_success is not None or self.counter is not None or bool(self.error)


@dataclass
class DeviceReport:
    name: str
    serial: str
    sync: str
    detail: str
    last_success: str
    counter: str

    def as_dict(self) -> dict[str, str]:
        return {
            "Name": self.name,
            "Serial": self.serial,
            "Sync": self.sync,
            "Detail": self.detail,
            "LastSuccess": self.last_success,
            "Counter": self.counter,
        }


def eastern_zone() -> timezone | ZoneInfo:
    try:
        return ZoneInfo("America/New_York")
    except ZoneInfoNotFoundError:
        return timezone.utc


def isoformat(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone(timezone.utc).isoformat()


def format_time(value: datetime | None) -> str:
    if value is None:
        return ""
    utc = value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    local = value.astimezone(eastern_zone()).strftime("%Y-%m-%d %H:%M:%S ET")
    return f"{local} ({utc})"


def as_bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_int(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    return int(str(value).strip())


def parse_devices(raw: str) -> list[tuple[str, str]]:
    devices: list[tuple[str, str]] = []
    for part in re.split(r"[,;\n]+", raw or ""):
        token = part.strip()
        if not token:
            continue
        if ":" in token:
            name, serial = token.split(":", 1)
            devices.append((name.strip() or serial.strip(), serial.strip()))
        else:
            devices.append((token, token))
    return devices


def parse_timestamp(value: str, offset_minutes: int) -> datetime | None:
    text = str(value).strip()
    if re.fullmatch(r"\d{10,13}", text):
        number = float(text)
        if len(text) >= 13:
            number = number / 1000.0
        parsed = datetime.fromtimestamp(number, tz=timezone.utc)
    else:
        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            parsed = None
        if parsed is None:
            bare = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", text).strip()
            for fmt in (
                "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y/%m/%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f",
            ):
                try:
                    parsed = datetime.strptime(bare, fmt)
                    break
                except ValueError:
                    continue
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc) - timedelta(minutes=offset_minutes)
        else:
            parsed = parsed.astimezone(timezone.utc)
    if parsed.year < 2000 or parsed.year > 2100:
        return None
    return parsed


def panos_query_time(moment: datetime, offset_minutes: int) -> str:
    local = moment.astimezone(timezone.utc) + timedelta(minutes=offset_minutes)
    return local.strftime("%Y/%m/%d %H:%M:%S")


def mentions_cie(text: str) -> bool:
    return CIE_TEXT_RE.search(text or "") is not None


def xml_to_obj(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        if element.attrib:
            result: dict[str, Any] = {"#text": element.text or ""}
            for key, value in element.attrib.items():
                result[f"@{key}"] = value
            return result
        return element.text or ""
    result: dict[str, Any] = {}
    for key, value in element.attrib.items():
        result[f"@{key}"] = value
    for child in children:
        value = xml_to_obj(child)
        if child.tag in result:
            existing = result[child.tag]
            if not isinstance(existing, list):
                result[child.tag] = [existing, value]
            else:
                existing.append(value)
        else:
            result[child.tag] = value
    return result


def parse_xml(text: str) -> dict[str, Any]:
    if len(text) > MAX_RESPONSE_CHARS:
        raise ValueError("PAN-OS response is too large to parse")
    root = ET.fromstring(text)
    return {root.tag: xml_to_obj(root)}


def coerce_payload(payload: Any) -> Any:
    if not isinstance(payload, str):
        return payload
    text = payload.strip()
    if not text:
        return payload
    if text.startswith("<"):
        try:
            return parse_xml(text)
        except (ET.ParseError, ValueError):
            return payload
    if text.startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return payload
    return payload


def dig(payload: Any, *path: str) -> Any:
    current = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def panos_error_message(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    response = payload.get("response") if isinstance(payload.get("response"), dict) else payload
    status = str(response.get("@status") or response.get("status") or "").lower()
    if status != "error":
        return None
    message = response.get("msg") or response.get("result") or "PAN-OS returned an error"
    return stringify(message)[:500]


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "line" in value:
            return stringify(value["line"])
        if "#text" in value and len(value) <= 2:
            return stringify(value["#text"])
    try:
        return json.dumps(value, default=str)
    except TypeError:
        return str(value)


def split_entries(entries: Any) -> tuple[list[str], list[Any]]:
    errors: list[str] = []
    payloads: list[Any] = []
    if entries is None:
        return ["command returned no result"], []
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return [f"unexpected command result: {stringify(entries)[:300]}"], []
    for entry in entries:
        if not isinstance(entry, dict):
            payloads.append(coerce_payload(entry))
            continue
        entry_type = entry.get("Type")
        if entry_type in (4, "error"):
            errors.append(stringify(entry.get("Contents"))[:500] or "command returned an error")
            continue
        contents = entry.get("Contents")
        if isinstance(contents, str) and contents.lower().startswith(("failed", "error:")):
            errors.append(contents[:500])
            continue
        context = entry.get("EntryContext") or {}
        if isinstance(context, dict) and "Panorama.Command" in context:
            payloads.append(coerce_payload(context["Panorama.Command"]))
        elif contents is not None:
            payloads.append(coerce_payload(contents))
    return errors, payloads


def call_command(commander: Commander, name: str, args: dict[str, Any]) -> Any:
    cleaned = {key: value for key, value in args.items() if value is not None and value != ""}
    try:
        return commander(name, cleaned)
    except Exception as exc:  # noqa: BLE001 - integrations raise their own error types
        return [{"Type": 4, "Contents": f"{name} failed: {exc}"}]


def interesting_key(key: str) -> bool:
    lowered = key.lower().lstrip("@")
    return any(token in lowered for token in INTERESTING_TOKENS)


def collect_records(node: Any, inherited_name: str = "") -> list[tuple[str, dict[str, Any]]]:
    records: list[tuple[str, dict[str, Any]]] = []
    if isinstance(node, list):
        for item in node:
            records.extend(collect_records(item, inherited_name))
        return records
    if not isinstance(node, dict):
        return records
    name = str(node.get("@name") or node.get("name") or node.get("profile") or inherited_name or "")
    leaves = {key: value for key, value in node.items() if not isinstance(value, (dict, list))}
    if any(interesting_key(key) for key in leaves):
        records.append((name or "default", leaves))
    for value in node.values():
        if isinstance(value, (dict, list)):
            records.extend(collect_records(value, name or inherited_name))
    return records


def leaves_to_text(name: str, leaves: dict[str, Any]) -> str:
    lines = []
    if name and name != "default":
        lines.append(f"profile: {name}")
    for key, value in leaves.items():
        lines.append(f"{key}: {stringify(value)}")
    return "\n".join(lines)


def signal_from_text(profile: str, text: str, source: str, offset_minutes: int) -> SyncSignal:
    profile_match = PROFILE_RE.search(text)
    if profile_match and (not profile or profile == "default"):
        profile = profile_match.group("name").strip()
    last_success: datetime | None = None
    for match in TIMESTAMP_RE.finditer(text):
        label = match.group("label").lower()
        if "next" in label or "time taken" in label or "total time" in label:
            continue
        if not any(token in label for token in ("last", "success", "update", "query", "time")):
            continue
        parsed = parse_timestamp(match.group("value"), offset_minutes)
        if parsed is None:
            continue
        if last_success is None or parsed > last_success:
            last_success = parsed
    total_updates: int | None = None
    partial_counters: list[int] = []
    for match in COUNTER_RE.finditer(text):
        label = match.group("label").lower()
        value = int(match.group("value"))
        if "total" in label and "update" in label:
            total_updates = value
        else:
            partial_counters.append(value)
    counter = total_updates
    if counter is None and partial_counters:
        counter = sum(partial_counters)
    error: str | None = None
    for match in ERROR_RE.finditer(text):
        value = match.group("value").strip()
        if value.lower() in BENIGN_ERROR_VALUES:
            continue
        error = value[:300]
        break
    return SyncSignal(profile or "default", source, last_success, counter, error)


def signals_from_payload(payload: Any, source: str, offset_minutes: int) -> list[SyncSignal]:
    payload = coerce_payload(payload)
    records = collect_records(payload)
    signals: list[SyncSignal] = []
    for name, leaves in records:
        text = leaves_to_text(name, leaves)
        if source == "group-mapping" and not mentions_cie(f"{name}\n{text}"):
            continue
        signal = signal_from_text(name, text, source, offset_minutes)
        if signal.has_evidence():
            signals.append(signal)
    if signals:
        return dedupe_signals(signals)
    text = payload if isinstance(payload, str) else stringify(payload)
    if source == "group-mapping" and not mentions_cie(text):
        return []
    signal = signal_from_text("default", text, source, offset_minutes)
    if signal.has_evidence():
        return [signal]
    return []


def dedupe_signals(signals: list[SyncSignal]) -> list[SyncSignal]:
    seen: set[tuple[Any, ...]] = set()
    unique: list[SyncSignal] = []
    for signal in signals:
        key = (
            signal.profile,
            signal.source,
            isoformat(signal.last_success),
            signal.counter,
            signal.error,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(signal)
    return unique


def merge_signals(signals: list[SyncSignal]) -> list[SyncSignal]:
    merged: dict[str, SyncSignal] = {}
    for signal in signals:
        current = merged.get(signal.profile)
        if current is None:
            merged[signal.profile] = signal
            continue
        last_success = current.last_success
        if signal.last_success is not None and (last_success is None or signal.last_success > last_success):
            last_success = signal.last_success
        counter = current.counter if current.source == "cie" else None
        source = current.source
        if signal.source == "cie":
            source = "cie"
            if signal.counter is not None:
                counter = signal.counter
        elif counter is None and current.source != "cie":
            counter = signal.counter if signal.counter is not None else current.counter
        error = current.error or signal.error
        merged[signal.profile] = SyncSignal(signal.profile, source, last_success, counter, error)
    return list(merged.values())


def age_minutes(now: datetime, earlier: datetime) -> float:
    return (now - earlier).total_seconds() / 60.0


def profile_state(counter: int | None, changed_at: datetime, last_success: datetime | None) -> dict[str, Any]:
    return {
        "counter": counter,
        "last_counter_change": isoformat(changed_at),
        "last_success": isoformat(last_success),
    }


def evaluate_profile(
    device: str,
    signal: SyncSignal,
    previous: dict[str, Any],
    now: datetime,
    max_age_minutes: int,
) -> tuple[Alert | None, dict[str, Any], str, str]:
    """Return an alert, the stored profile state, a status word, and a detail."""
    previous_counter = previous.get("counter")
    previous_change = parse_timestamp(str(previous.get("last_counter_change") or ""), 0)
    detail = ""
    status = "fresh"
    alert: Alert | None = None
    if signal.error:
        alert = Alert("sync_failed", device, signal.profile, f"Firewall reported: {signal.error}", signal.last_success)
        status = "failed"
        detail = signal.error
    elif signal.last_success is not None:
        age = age_minutes(now, signal.last_success)
        if age < -10:
            alert = Alert(
                "sync_check_error",
                device,
                signal.profile,
                f"Last sync time {format_time(signal.last_success)} is more than 10 minutes in the future. "
                "Check the firewall clock and DeviceTimeOffsetMinutes.",
                signal.last_success,
            )
            status = "error"
            detail = "device clock is ahead of XSOAR"
        elif age >= max_age_minutes:
            alert = Alert(
                "sync_stale",
                device,
                signal.profile,
                f"Last CIE sync evidence is {int(age)} minutes old (threshold {max_age_minutes}). "
                f"Last success {format_time(signal.last_success)}.",
                signal.last_success,
            )
            status = "stale"
            detail = f"{int(age)} minutes old"
        else:
            detail = f"synced {int(age)} minutes ago"
    elif signal.counter is not None:
        if previous_counter is None or previous_change is None:
            status = "baseline"
            detail = (
                f"Baselined update counter at {signal.counter}. "
                f"The next runs alert if it does not increase within {max_age_minutes} minutes."
            )
            previous_change = now
        elif signal.counter > int(previous_counter):
            detail = f"update counter increased from {previous_counter} to {signal.counter}"
            previous_change = now
        elif signal.counter < int(previous_counter):
            status = "baseline"
            detail = (
                f"Update counter reset from {previous_counter} to {signal.counter}. "
                "Treating this run as a new baseline."
            )
            previous_change = now
        else:
            age = age_minutes(now, previous_change)
            if age >= max_age_minutes:
                alert = Alert(
                    "sync_stale",
                    device,
                    signal.profile,
                    f"CIE update counter stayed at {signal.counter} for {int(age)} minutes "
                    f"(threshold {max_age_minutes}). No sync was observed.",
                    None,
                )
                status = "stale"
                detail = f"counter unchanged for {int(age)} minutes"
            else:
                detail = f"counter {signal.counter} unchanged for {int(age)} minutes, still inside the window"
    else:
        alert = Alert(
            "sync_check_error",
            device,
            signal.profile,
            "The firewall response did not include a CIE sync time or an update counter.",
            None,
        )
        status = "error"
        detail = "no sync time or counter"
    if signal.last_success is not None and status == "fresh":
        previous_change = now
    elif signal.last_success is not None and status == "stale" and previous_change is None:
        previous_change = signal.last_success
    stored_change = previous_change or now
    return alert, profile_state(signal.counter, stored_change, signal.last_success), status, detail


def evaluate_sync_signals(
    device: str,
    serial: str,
    signals: list[SyncSignal],
    previous_device_state: dict[str, Any],
    now: datetime,
    max_age_minutes: int,
) -> tuple[list[Alert], dict[str, Any], DeviceReport]:
    previous_profiles = previous_device_state.get("profiles") if isinstance(previous_device_state, dict) else {}
    if not isinstance(previous_profiles, dict):
        previous_profiles = {}
    alerts: list[Alert] = []
    new_profiles: dict[str, Any] = {}
    statuses: list[str] = []
    details: list[str] = []
    last_success: datetime | None = None
    counters: list[str] = []
    for signal in merge_signals(signals):
        previous = previous_profiles.get(signal.profile) if isinstance(previous_profiles.get(signal.profile), dict) else {}
        alert, state, status, detail = evaluate_profile(device, signal, previous, now, max_age_minutes)
        if alert is not None:
            alerts.append(alert)
        new_profiles[signal.profile] = state
        statuses.append(status)
        label = signal.profile if signal.profile != "default" else device
        details.append(f"{label}: {detail}" if detail else label)
        if signal.last_success is not None and (last_success is None or signal.last_success > last_success):
            last_success = signal.last_success
        if signal.counter is not None:
            counters.append(str(signal.counter))
    if not statuses:
        statuses = ["error"]
        details = ["no CIE evidence"]
    worst = min(statuses, key=lambda item: DEVICE_RANK.get(item, 99))
    report = DeviceReport(
        device,
        serial,
        worst,
        "; ".join(details),
        format_time(last_success),
        ", ".join(counters),
    )
    stored = {"profiles": new_profiles, "last_check": isoformat(now)}
    return alerts, stored, report


def log_blob(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return " ".join(f"{key}={stringify(value)}" for key, value in entry.items())
    return stringify(entry)


def log_device(entry: Any) -> str:
    if not isinstance(entry, dict):
        return "firewall"
    for key in ("device_name", "DeviceName", "serial", "DeviceSN", "serialnum", "host"):
        value = entry.get(key)
        if value:
            return str(value)
    return "firewall"


def classify_system_log(entry: Any) -> str | None:
    text = log_blob(entry)
    lowered = text.lower()
    event = ""
    if isinstance(entry, dict):
        event = str(entry.get("eventid") or entry.get("EventID") or "").lower()
    if "cas-message" in event or re.search(r"\bcas-message\b", lowered):
        return "cas_message"
    syslogish = "syslog-conn-status" in event or "syslog-conn-status" in lowered or "syslog connection" in lowered
    if syslogish and any(word in lowered for word in FAILURE_WORDS):
        return "syslog_down"
    return None


def alerts_from_logs(logs: list[Any]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Any]] = {}
    for entry in logs:
        kind = classify_system_log(entry)
        if kind is None:
            continue
        grouped.setdefault((kind, log_device(entry)), []).append(entry)
    alerts: list[Alert] = []
    for (kind, device), items in grouped.items():
        sample = log_blob(items[0])[:300]
        alerts.append(Alert(kind, device, "", f"{len(items)} event(s). First: {sample}", None))
    return alerts


def heartbeat_failure_text(records: list[Any]) -> str:
    for record in records:
        text = log_blob(record)
        lowered = text.lower()
        if "sync_failure" in lowered or "sync failure" in lowered:
            return text[:300]
    return ""


def find_job_id(payloads: list[Any]) -> str | None:
    for payload in payloads:
        if isinstance(payload, dict) and payload.get("JobID"):
            return str(payload["JobID"])
        job = dig(payload, "response", "result", "job")
        if job is None and isinstance(payload, dict):
            job = payload.get("job")
        if isinstance(job, (str, int)) and str(job).strip():
            return str(job).strip()
        if isinstance(job, dict) and job.get("id") is not None and "status" not in job:
            return str(job["id"])
    return None


def extract_logs(payloads: list[Any]) -> tuple[str | None, list[Any]]:
    status: str | None = None
    logs: list[Any] = []
    for payload in payloads:
        job = dig(payload, "response", "result", "job")
        if isinstance(job, dict) and job.get("status"):
            status = "Completed" if str(job.get("status")).upper() == "FIN" else "Pending"
        elif isinstance(payload, dict) and payload.get("Status"):
            status = "Completed" if str(payload.get("Status")).lower() == "completed" else str(payload.get("Status"))
        count = dig(payload, "response", "result", "log", "logs", "@count")
        entry = dig(payload, "response", "result", "log", "logs", "entry")
        if entry is None and isinstance(payload, dict):
            entry = payload.get("Logs")
        if isinstance(entry, dict):
            logs = [entry]
        elif isinstance(entry, list):
            logs = entry
        if str(count) == "0":
            status = "Completed"
            logs = []
    return status, logs


def fetch_system_logs(
    commander: Commander,
    api_command: str,
    query: str,
    using: str,
    target: str,
    sleep_fn: Sleeper,
) -> tuple[list[Any], str | None]:
    args: dict[str, Any] = {"type": "log", "log-type": "system", "query": query, "nlogs": "100", "using": using, "target": target}
    errors, payloads = split_entries(call_command(commander, api_command, args))
    if errors:
        return [], "; ".join(errors)
    status, logs = extract_logs(payloads)
    if status == "Completed":
        return logs, None
    job_id = find_job_id(payloads)
    if not job_id:
        return [], "Log query did not return a job id."
    last_status = status or "Pending"
    for _ in range(8):
        sleep_fn(3)
        poll_args = {"type": "log", "action": "get", "job-id": job_id, "using": using, "target": target}
        poll_errors, poll_payloads = split_entries(call_command(commander, api_command, poll_args))
        if poll_errors:
            return [], "; ".join(poll_errors)
        last_status, logs = extract_logs(poll_payloads)
        if last_status == "Completed":
            return logs, None
    return [], f"Log query job {job_id} was still {last_status}."


def incidents_query(base: str, since: datetime) -> str:
    stamp = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    time_clause = f'occurred:>="{stamp}"'
    text = (base or "").strip()
    if not text:
        return time_clause
    return f"({text}) and {time_clause}"


def incident_total(payloads: list[Any]) -> tuple[int | None, list[Any]]:
    for payload in payloads:
        if isinstance(payload, dict):
            data = payload.get("data")
            total = payload.get("total")
            if isinstance(data, list) or total is not None:
                count = int(total) if total is not None else len(data or [])
                return count, data if isinstance(data, list) else []
        if isinstance(payload, list):
            return len(payload), payload
    return None, []


def xql_records(payloads: list[Any]) -> list[Any]:
    records: list[Any] = []
    for payload in payloads:
        if isinstance(payload, list):
            records.extend(payload)
            continue
        if isinstance(payload, dict):
            for key in ("results", "data", "records"):
                value = payload.get(key)
                if isinstance(value, list):
                    records.extend(value)
                    break
    return records


def load_state(payloads: list[Any], errors: list[str]) -> tuple[dict[str, Any], str | None]:
    if errors:
        message = "; ".join(errors)
        if any(token in message.lower() for token in ("not found", "does not exist", "no such", "unknown list")):
            return {"version": STATE_VERSION, "devices": {}}, None
        return {"version": STATE_VERSION, "devices": {}}, message[:500]
    for payload in payloads:
        text = payload if isinstance(payload, str) else stringify(payload)
        if not str(text).strip():
            continue
        try:
            loaded = json.loads(text) if isinstance(text, str) else payload
        except json.JSONDecodeError:
            return {"version": STATE_VERSION, "devices": {}}, "CIE state list is not valid JSON. Starting a new baseline."
        if isinstance(loaded, dict) and isinstance(loaded.get("devices"), dict):
            return loaded, None
    return {"version": STATE_VERSION, "devices": {}}, None


def run_op(
    commander: Commander,
    api_command: str,
    command: str,
    source: str,
    using: str,
    target: str,
    offset_minutes: int,
) -> tuple[list[SyncSignal], str | None]:
    args = {"type": "op", "cmd": command, "using": using, "target": target}
    errors, payloads = split_entries(call_command(commander, api_command, args))
    if errors:
        return [], "; ".join(errors)
    signals: list[SyncSignal] = []
    panos_errors: list[str] = []
    for payload in payloads:
        message = panos_error_message(payload)
        if message:
            panos_errors.append(message)
            continue
        signals.extend(signals_from_payload(payload, source, offset_minutes))
    if signals:
        return signals, None
    if panos_errors:
        return [], "; ".join(panos_errors)
    hint = ""
    if payloads:
        hint = f" Response keys: {stringify(payloads[0])[:240]}"
    return [], f"No CIE sync time or update counter was found.{hint}"


def bounded_query(start: datetime, offset_minutes: int, expression: str) -> str:
    stamp = panos_query_time(start, offset_minutes)
    body = expression.strip()
    if not body:
        return f"(receive_time geq '{stamp}')"
    return f"(receive_time geq '{stamp}') and ({body})"


def build_summary(
    now: datetime,
    status: str,
    sync_max_age: int,
    syslog_max_age: int,
    devices: list[DeviceReport],
    alerts: list[Alert],
    syslog_line: str,
    alert_id: str,
) -> str:
    lines = [
        "### CIE sync and syslog check",
        "",
        f"Checked at {format_time(now)}.",
        f"Sync threshold: {sync_max_age} minutes. Syslog threshold: {syslog_max_age} minutes.",
        f"Status: {status}.",
        "",
        "| Device | Sync | Last success | Counter | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    if not devices:
        lines.append("| none | skipped |  |  | No firewall was checked. |")
    for device in devices:
        detail = device.detail.replace("|", "/")
        lines.append(
            f"| {device.name} | {device.sync} | {device.last_success or '-'} | {device.counter or '-'} | {detail} |"
        )
    lines.extend(["", "Syslog: " + syslog_line, ""])
    if alerts:
        lines.append("| Finding | Device | Detail |")
        lines.append("| --- | --- | --- |")
        ordered = sorted(alerts, key=lambda item: KIND_RANK.get(item.kind, 99))
        for alert in ordered:
            title = KIND_TITLES[alert.kind]
            where = alert.device or "-"
            if alert.profile:
                where = f"{where} / {alert.profile}"
            lines.append(f"| {title} | {where} | {alert.detail.replace('|', '/')} |")
    else:
        lines.append("No sync or syslog findings. The job incident will close.")
    if alert_id:
        lines.extend(["", f"Open alert incident: {alert_id}."])
    return "\n".join(lines)


def alert_incident_name(alerts: list[Alert]) -> str:
    kinds = []
    for alert in sorted(alerts, key=lambda item: KIND_RANK.get(item.kind, 99)):
        if alert.kind not in kinds:
            kinds.append(alert.kind)
    devices = []
    for alert in alerts:
        if alert.device and alert.device not in devices:
            devices.append(alert.device)
    kind_text = ", ".join(kinds[:3])
    if len(devices) == 1:
        return f"CIE alert: {kind_text} on {devices[0]}"
    return f"CIE alert: {len(alerts)} findings ({kind_text})"


def severity_for(alerts: list[Alert]) -> str:
    if any(alert.kind in {"sync_failed", "cas_message", "syslog_down"} for alert in alerts):
        return "Critical"
    if alerts:
        return "High"
    return "Low"


def configuration_problems(args: dict[str, Any]) -> list[str]:
    problems = []
    api_command = str(args.get("api_command") or "panorama").strip()
    if api_command not in API_COMMANDS:
        problems.append(f"api_command must be panorama or pan-os. Received {api_command!r}.")
    source = str(args.get("syslog_heartbeat_source") or "xsoar-incidents").strip()
    if source not in HEARTBEAT_SOURCES:
        problems.append(
            "syslog_heartbeat_source must be one of: " + ", ".join(HEARTBEAT_SOURCES) + f". Received {source!r}."
        )
    for name in ("sync_max_age_minutes", "syslog_max_age_minutes"):
        try:
            value = as_int(args.get(name), 60)
        except ValueError:
            problems.append(f"{name} must be a whole number of minutes.")
            continue
        if value < 1 or value > 10080:
            problems.append(f"{name} must be between 1 and 10080 minutes.")
    return problems


def empty_outputs(
    now: datetime,
    status: str,
    summary: str,
    alerts: list[Alert],
    devices: list[DeviceReport],
    alert_id: str,
    sync_max_age: int,
    syslog_max_age: int,
    syslog_info: dict[str, Any],
) -> dict[str, Any]:
    job_name = "CIE monitor filed an alert" if alerts else "CIE monitor healthy"
    close_notes = summary if len(summary) <= 4000 else summary[:4000]
    return {
        "Status": status,
        "CheckedAt": isoformat(now),
        "SyncMaxAgeMinutes": sync_max_age,
        "SyslogMaxAgeMinutes": syslog_max_age,
        "AlertCount": len(alerts),
        "Alerts": [alert.as_dict() for alert in alerts],
        "Devices": [device.as_dict() for device in devices],
        "Syslog": syslog_info,
        "Summary": summary,
        "AlertIncidentID": alert_id,
        "JobIncidentName": job_name,
        "CloseNotes": close_notes,
        "Severity": severity_for(alerts),
    }


def read_state(commander: Commander, list_name: str) -> tuple[dict[str, Any], str | None]:
    errors, payloads = split_entries(call_command(commander, "getList", {"listName": list_name}))
    return load_state(payloads, errors)


def save_state(commander: Commander, list_name: str, state: dict[str, Any]) -> str | None:
    body = json.dumps(state)
    errors, _payloads = split_entries(call_command(commander, "setList", {"listName": list_name, "listData": body}))
    if not errors:
        return None
    message = "; ".join(errors)
    if any(token in message.lower() for token in ("not found", "does not exist", "no such", "unknown list")):
        create_errors, _created = split_entries(call_command(commander, "createList", {"listName": list_name}))
        if create_errors and not any("exist" in item.lower() for item in create_errors):
            return "; ".join(create_errors)[:500]
        errors, _payloads = split_entries(call_command(commander, "setList", {"listName": list_name, "listData": body}))
        if errors:
            return "; ".join(errors)[:500]
        return None
    return message[:500]


def find_open_alert(commander: Commander, incident_type: str, current_id: str) -> tuple[str, str | None]:
    query = f'type:"{incident_type}" and -status:Closed'
    errors, payloads = split_entries(call_command(commander, "getIncidents", {"query": query, "size": "20"}))
    if errors:
        return "", "; ".join(errors)[:500]
    _count, data = incident_total(payloads)
    ids = []
    for incident in data:
        if not isinstance(incident, dict):
            continue
        incident_id = str(incident.get("id") or "")
        if incident_id and incident_id != current_id:
            ids.append(incident_id)
    if not ids:
        return "", None
    return min(ids, key=lambda item: int(item) if item.isdigit() else item), None


def file_alert(
    commander: Commander,
    alerts: list[Alert],
    summary: str,
    incident_type: str,
    current_id: str,
    notify_email: str,
) -> tuple[str, str | None]:
    name = alert_incident_name(alerts)
    severity = severity_for(alerts)
    existing, lookup_error = find_open_alert(commander, incident_type, current_id)
    notes = []
    if lookup_error:
        notes.append(f"Could not search for an existing alert: {lookup_error}")
    alert_id = existing
    if existing:
        errors, _payloads = split_entries(
            call_command(
                commander,
                "setIncident",
                {"id": existing, "name": name, "severity": severity, "details": summary[:12000]},
            )
        )
        if errors:
            notes.append("Could not update the open alert: " + "; ".join(errors))
    else:
        created = call_command(
            commander,
            "createNewIncident",
            {"name": name, "type": incident_type, "severity": severity, "details": summary[:12000]},
        )
        errors, payloads = split_entries(created)
        alert_id = extract_incident_id_from_entries(created) or extract_incident_id(payloads)
        if errors and not alert_id:
            notes.append("Could not create the alert incident: " + "; ".join(errors))
        elif not alert_id:
            notes.append("createNewIncident did not return an incident id.")
    if alert_id and current_id:
        call_command(commander, "linkIncidents", {"linkedIncidentIDs": alert_id})
    if notify_email:
        mail_errors, _mail_payloads = split_entries(
            call_command(
                commander,
                "send-mail",
                {
                    "to": notify_email,
                    "subject": name,
                    "body": summary[:12000],
                },
            )
        )
        if mail_errors:
            notes.append("Email notification failed: " + "; ".join(mail_errors))
    return alert_id, "; ".join(notes) if notes else None


def extract_incident_id(payloads: list[Any]) -> str:
    for payload in payloads:
        if isinstance(payload, dict):
            for key in ("id", "Id", "incidentId", "CreatedIncidentID"):
                if payload.get(key):
                    return str(payload[key])
            context_id = dig(payload, "EntryContext", "CreatedIncidentID")
            if context_id:
                return str(context_id)
        if isinstance(payload, int):
            return str(payload)
        if isinstance(payload, str) and payload.strip().isdigit():
            return payload.strip()
    return ""


def extract_incident_id_from_entries(entries: Any) -> str:
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        return ""
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        context = entry.get("EntryContext") or {}
        if isinstance(context, dict):
            for key in ("CreatedIncidentID", "id", "Id"):
                if context.get(key):
                    return str(context[key])
        contents = entry.get("Contents")
        found = extract_incident_id([] if contents is None else [contents])
        if found:
            return found
    return ""


def check_heartbeat(
    commander: Commander,
    source: str,
    query: str,
    since: datetime,
    api_command: str,
    using: str,
    offset_minutes: int,
    sleep_fn: Sleeper,
) -> tuple[dict[str, Any], list[Alert]]:
    if source == "disabled":
        return {"Source": source, "Count": "", "Detail": "Syslog silence check is disabled."}, []
    if source == "xsoar-incidents":
        full_query = incidents_query(query or DEFAULT_HEARTBEAT_QUERY, since)
        errors, payloads = split_entries(call_command(commander, "getIncidents", {"query": full_query, "size": "50"}))
        if errors:
            message = "; ".join(errors)[:500]
            return {"Source": source, "Count": "", "Detail": message}, [
                Alert("syslog_check_error", "syslog", "", f"Incident search failed: {message}", None)
            ]
        count, records = incident_total(payloads)
        if count is None:
            return {"Source": source, "Count": "", "Detail": "Incident search returned no total."}, [
                Alert("syslog_check_error", "syslog", "", "Incident search returned no total.", None)
            ]
        failure = heartbeat_failure_text(records)
        info = {
            "Source": source,
            "Count": count,
            "Detail": f"{count} incident(s) matched in the syslog window. Query: {full_query}",
        }
        alerts = []
        if failure:
            alerts.append(Alert("sync_failed", "syslog", "", f"CIE syslog reported SYNC_FAILURE. {failure}", None))
        if count == 0:
            alerts.append(
                Alert(
                    "syslog_silent",
                    "syslog",
                    "",
                    f"No incidents matched the CIE syslog heartbeat in the window. Query: {full_query}",
                    None,
                )
            )
        return info, alerts
    if source == "pan-os-log":
        expression = query or DEFAULT_PANOS_HEARTBEAT_QUERY
        logs, error = fetch_system_logs(
            commander,
            api_command,
            bounded_query(since, offset_minutes, expression),
            using,
            "",
            sleep_fn,
        )
        if error:
            return {"Source": source, "Count": "", "Detail": error}, [
                Alert("syslog_check_error", "syslog", "", f"PAN-OS heartbeat log query failed: {error}", None)
            ]
        failure = heartbeat_failure_text(logs)
        info = {"Source": source, "Count": len(logs), "Detail": f"{len(logs)} system log(s) matched the heartbeat query."}
        alerts = []
        if failure:
            alerts.append(Alert("sync_failed", "syslog", "", f"CIE syslog reported SYNC_FAILURE. {failure}", None))
        if not logs:
            alerts.append(
                Alert(
                    "syslog_silent",
                    "syslog",
                    "",
                    "No PAN-OS system logs matched the CIE heartbeat query in the window.",
                    None,
                )
            )
        return info, alerts
    if source == "xsiam-xql":
        errors, payloads = split_entries(call_command(commander, "xdr-xql-generic-query", {"query": query}))
        if errors:
            message = "; ".join(errors)[:500]
            return {"Source": source, "Count": "", "Detail": message}, [
                Alert("syslog_check_error", "syslog", "", f"XQL query failed: {message}", None)
            ]
        records = xql_records(payloads)
        failure = heartbeat_failure_text(records)
        info = {"Source": source, "Count": len(records), "Detail": f"XQL returned {len(records)} record(s)."}
        alerts = []
        if failure:
            alerts.append(Alert("sync_failed", "syslog", "", f"CIE log reported SYNC_FAILURE. {failure}", None))
        if not records:
            alerts.append(Alert("syslog_silent", "syslog", "", "XQL returned no CIE syslog records in the query.", None))
        return info, alerts
    raise ValueError(f"Unsupported syslog heartbeat source: {source}")


def check_device(
    commander: Commander,
    api_command: str,
    name: str,
    serial: str,
    use_target: bool,
    using: str,
    offset_minutes: int,
    now: datetime,
    max_age_minutes: int,
    previous_state: dict[str, Any],
) -> tuple[list[Alert], dict[str, Any], DeviceReport]:
    target = serial if use_target else ""
    cie_signals, cie_error = run_op(commander, api_command, CIE_STATS_CMD, "cie", using, target, offset_minutes)
    group_signals, group_error = run_op(
        commander, api_command, GROUP_STATS_CMD, "group-mapping", using, target, offset_minutes
    )
    signals = cie_signals + group_signals
    if not signals:
        detail = cie_error or group_error or "No CIE sync time or update counter was found."
        report = DeviceReport(name, serial, "error", detail, "", "")
        alert = Alert("sync_check_error", name, "", detail, None)
        return [alert], previous_state if isinstance(previous_state, dict) else {}, report
    note = ""
    if cie_error and not cie_signals:
        note = f"CIE statistics command failed ({cie_error}). Group-mapping evidence was used instead."
    alerts, stored, report = evaluate_sync_signals(name, serial, signals, previous_state, now, max_age_minutes)
    if note:
        report.detail = f"{note} {report.detail}".strip()
    return alerts, stored, report


def run_check(
    args: dict[str, Any],
    commander: Commander,
    now: datetime,
    incident_id: str,
    sleep_fn: Sleeper,
) -> dict[str, Any]:
    problems = configuration_problems(args)
    sync_max_age = 60
    syslog_max_age = 60
    if not problems:
        sync_max_age = as_int(args.get("sync_max_age_minutes"), 60)
        syslog_max_age = as_int(args.get("syslog_max_age_minutes"), 60)
    if problems:
        alerts = [Alert("configuration", "monitor", "", " ".join(problems), None)]
        summary = build_summary(now, "Alert", sync_max_age, syslog_max_age, [], alerts, "Not checked.", "")
        alert_id, file_note = file_alert(
            commander,
            alerts,
            summary,
            str(args.get("alert_incident_type") or "CIE Sync Failure").strip(),
            incident_id,
            str(args.get("notify_email") or "").strip(),
        )
        if file_note:
            summary = f"{summary}\n\nAlert filing: {file_note}"
        if alert_id:
            summary = build_summary(now, "Alert", sync_max_age, syslog_max_age, [], alerts, "Not checked.", alert_id)
            call_command(
                commander,
                "setIncident",
                {"id": alert_id, "details": summary[:12000], "severity": severity_for(alerts)},
            )
        outputs = empty_outputs(
            now,
            "Alert",
            summary,
            alerts,
            [],
            alert_id,
            sync_max_age,
            syslog_max_age,
            {"Source": "", "Count": "", "Detail": "Not checked."},
        )
        call_command(
            commander,
            "setIncident",
            {"name": outputs["JobIncidentName"], "severity": outputs["Severity"], "details": summary[:12000]},
        )
        return outputs

    api_command = str(args.get("api_command") or "panorama").strip()
    using = str(args.get("using") or "").strip()
    use_target = as_bool(args.get("use_target"), True)
    offset_minutes = as_int(args.get("device_time_offset_minutes"), 0)
    source = str(args.get("syslog_heartbeat_source") or "xsoar-incidents").strip()
    heartbeat_query = str(args.get("syslog_heartbeat_query") or "").strip()
    list_name = str(args.get("state_list_name") or "CIE-Sync-Monitor-State").strip()
    incident_type = str(args.get("alert_incident_type") or "CIE Sync Failure").strip()
    notify_email = str(args.get("notify_email") or "").strip()
    check_logs = as_bool(args.get("check_firewall_logs"), True)
    query_each_device = as_bool(args.get("query_each_device"), False)

    devices = parse_devices(str(args.get("devices") or ""))
    if not devices:
        devices = [(using or "firewall", "")]

    state, state_error = read_state(commander, list_name)
    previous_devices = state.get("devices") if isinstance(state.get("devices"), dict) else {}
    alerts: list[Alert] = []
    reports: list[DeviceReport] = []
    new_devices: dict[str, Any] = {}
    if state_error:
        alerts.append(Alert("sync_check_error", "monitor", "", f"Could not read the state list. {state_error}", None))

    for name, serial in devices:
        previous = previous_devices.get(name) if isinstance(previous_devices.get(name), dict) else {}
        device_alerts, stored, report = check_device(
            commander,
            api_command,
            name,
            serial,
            use_target and bool(serial),
            using,
            offset_minutes,
            now,
            sync_max_age,
            previous,
        )
        alerts.extend(device_alerts)
        reports.append(report)
        new_devices[name] = stored

    log_window = max(sync_max_age, syslog_max_age)
    log_start = now - timedelta(minutes=log_window)
    if check_logs:
        targets = [serial if query_each_device and use_target else "" for _name, serial in devices]
        if not query_each_device:
            targets = [""]
        seen_targets: list[str] = []
        for target in targets:
            if target in seen_targets:
                continue
            seen_targets.append(target)
            logs, error = fetch_system_logs(
                commander,
                api_command,
                bounded_query(log_start, offset_minutes, FAILURE_LOG_QUERY),
                using,
                target,
                sleep_fn,
            )
            if error:
                where = target or "panorama-or-firewall"
                alerts.append(
                    Alert(
                        "syslog_check_error",
                        where,
                        "",
                        f"Could not query system logs for cas-message and syslog-conn-status. {error}",
                        None,
                    )
                )
            else:
                alerts.extend(alerts_from_logs(logs))

    syslog_since = now - timedelta(minutes=syslog_max_age)
    syslog_info, syslog_alerts = check_heartbeat(
        commander,
        source,
        heartbeat_query,
        syslog_since,
        api_command,
        using,
        offset_minutes,
        sleep_fn,
    )
    alerts.extend(syslog_alerts)

    state["version"] = STATE_VERSION
    state["devices"] = new_devices
    save_error = save_state(commander, list_name, state)
    if save_error:
        alerts.append(Alert("sync_check_error", "monitor", "", f"Could not save the state list. {save_error}", None))

    status = "Alert" if alerts else "Healthy"
    alert_id = ""
    file_note = None
    if alerts:
        alert_id, file_note = file_alert(commander, alerts, "pending", incident_type, incident_id, "")
    summary = build_summary(now, status, sync_max_age, syslog_max_age, reports, alerts, str(syslog_info.get("Detail") or ""), alert_id)
    if file_note:
        summary = f"{summary}\n\nAlert filing: {file_note}"
    if alerts and (alert_id or notify_email):
        # Rebuild is unnecessary; update the open incident and send mail with the final summary.
        if alert_id:
            call_command(
                commander,
                "setIncident",
                {"id": alert_id, "details": summary[:12000], "severity": severity_for(alerts)},
            )
        if notify_email:
            mail_errors, _payloads = split_entries(
                call_command(
                    commander,
                    "send-mail",
                    {"to": notify_email, "subject": alert_incident_name(alerts), "body": summary[:12000]},
                )
            )
            if mail_errors:
                summary += "\n\nEmail notification failed: " + "; ".join(mail_errors)

    outputs = empty_outputs(now, status, summary, alerts, reports, alert_id, sync_max_age, syslog_max_age, syslog_info)
    job_errors, _job_payloads = split_entries(
        call_command(
            commander,
            "setIncident",
            {
                "name": outputs["JobIncidentName"],
                "severity": outputs["Severity"],
                "details": summary[:12000],
            },
        )
    )
    if job_errors:
        outputs["CloseNotes"] = f"{outputs['CloseNotes']}\n\nCould not update the job incident: {'; '.join(job_errors)}"[:4000]
    else:
        outputs["CloseNotes"] = summary[:4000]
        outputs["Summary"] = summary
    return outputs


def uncaught_failure(message: str, now: datetime) -> dict[str, Any]:
    alert = Alert("sync_check_error", "monitor", "", f"CIE monitor failed before it finished. {message[:500]}", None)
    summary = build_summary(now, "Alert", 60, 60, [], [alert], "Not checked.", "")
    summary += (
        "\n\nThe job incident still closes so the next hourly run is not blocked. "
        "Fix the error and run the playbook again."
    )
    return empty_outputs(now, "Alert", summary, [alert], [], "", 60, 60, {"Source": "", "Count": "", "Detail": "Not checked."})


def main() -> None:
    now = datetime.now(timezone.utc)
    try:
        incident = demisto.incident() or {}
        incident_id = str(incident.get("id") or "")
    except Exception:  # noqa: BLE001 - incident context is absent in some runners
        incident_id = ""
    try:
        outputs = run_check(demisto.args(), demisto.executeCommand, now, incident_id, time.sleep)
    except Exception as exc:  # noqa: BLE001 - keep the hourly job closing after an unexpected failure
        outputs = uncaught_failure(str(exc), now)
    try:
        return_results(
            CommandResults(
                outputs_prefix="CIE.Health",
                outputs=outputs,
                readable_output=outputs["Summary"],
                raw_response=outputs,
            )
        )
    except Exception as exc:  # noqa: BLE001 - publish the war-room error if result formatting fails
        return_error(f"Failed to publish CIE health results: {exc}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
