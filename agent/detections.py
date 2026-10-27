"""Deterministic, evidence-backed authentication detections.

Windows are inclusive at the configured boundary. All event timestamps must
already be timezone-aware (the schema enforces this before detection).
Confidence values are fixed rule-strength labels, not calibrated probabilities.
"""

from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass
import os
from datetime import timedelta

from agent.schemas import Finding, SecurityEvent, TimelineEvent

AUTH_TYPE = "authentication"
FAILURES = {"failure", "failed", "denied"}
SUCCESSES = {"success", "succeeded", "accepted"}


@dataclass(frozen=True)
class DetectionConfig:
    repeated_failures: int = 3
    repeated_window_minutes: int = 5
    success_after_failures: int = 3
    success_window_minutes: int = 10
    burst_failures: int = 10
    burst_window_minutes: int = 5
    multiple_account_count: int = 5
    multiple_account_window_minutes: int = 5

    @classmethod
    def from_environment(cls) -> "DetectionConfig":
        values = {
            "repeated_failures": int(os.getenv("SREEMA_RULE_REPEATED_THRESHOLD", "3")),
            "repeated_window_minutes": int(os.getenv("SREEMA_RULE_REPEATED_WINDOW_MINUTES", "5")),
            "success_after_failures": int(os.getenv("SREEMA_RULE_SUCCESS_THRESHOLD", "3")),
            "success_window_minutes": int(os.getenv("SREEMA_RULE_SUCCESS_WINDOW_MINUTES", "10")),
            "burst_failures": int(os.getenv("SREEMA_RULE_BURST_THRESHOLD", "10")),
            "burst_window_minutes": int(os.getenv("SREEMA_RULE_BURST_WINDOW_MINUTES", "5")),
            "multiple_account_count": int(os.getenv("SREEMA_RULE_MULTIPLE_ACCOUNT_THRESHOLD", "5")),
            "multiple_account_window_minutes": int(os.getenv("SREEMA_RULE_MULTIPLE_ACCOUNT_WINDOW_MINUTES", "5")),
        }
        if any(value < 1 for value in values.values()):
            raise ValueError("Detection thresholds and windows must be positive integers")
        if values["multiple_account_count"] < 2:
            raise ValueError("SREEMA_RULE_MULTIPLE_ACCOUNT_THRESHOLD must be at least 2")
        return cls(**values)

    def rules(self) -> list[dict]:
        return [
            {"id": "repeated-failures", "name": "Repeated failed authentication", "threshold": self.repeated_failures, "window_minutes": self.repeated_window_minutes, "severity": "medium", "confidence": 0.80, "description": "Failures for the same account and source."},
            {"id": "success-after-failures", "name": "Successful login after repeated failures", "threshold": self.success_after_failures, "window_minutes": self.success_window_minutes, "severity": "high", "confidence": 0.90, "description": "A successful login follows multiple failures for the same account and source."},
            {"id": "authentication-burst", "name": "Authentication failure burst", "threshold": self.burst_failures, "window_minutes": self.burst_window_minutes, "severity": "high", "confidence": 0.85, "description": "Many failures from one source IP across accounts."},
            {"id": "multiple-account-targeting", "name": "Failed authentication across accounts", "threshold": self.multiple_account_count, "window_minutes": self.multiple_account_window_minutes, "severity": "medium", "confidence": 0.82, "description": "Failures from one source IP target distinct usernames."},
        ]


def detect_repeated_failed_logins(
    events: list[SecurityEvent], threshold: int = 3, window_minutes: int = 5
) -> list[dict]:
    """Detect threshold failures for one account and source within a window."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")
    findings: list[dict] = []
    for group in _by_account_source(events).values():
        failures = sorted(
            (event for event in group if _outcome(event) in FAILURES),
            key=lambda event: event.timestamp,
        )
        for start, end in _window_indices(failures, window_minutes):
            if end - start >= threshold:
                matched = failures[start:end]
                findings.append(_finding(
                    "Repeated failed authentication attempts",
                    f"{len(matched)} failed authentication attempts for one account and source occurred within {window_minutes} minutes.",
                    "medium", 0.80, matched,
                    ["Review the authentication attempts and confirm whether they were authorised."],
                ))
                break
    return findings


def detect_success_after_repeated_failures(
    events: list[SecurityEvent], threshold: int = 3, window_minutes: int = 10
) -> list[dict]:
    """Detect a successful login preceded by threshold failures on same pair."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")
    findings: list[dict] = []
    for group in _by_account_source(events).values():
        ordered = sorted(group, key=lambda event: event.timestamp)
        failures = [event for event in ordered if _outcome(event) in FAILURES]
        failure_times = [event.timestamp for event in failures]
        for success in (event for event in ordered if _outcome(event) in SUCCESSES):
            left = bisect_left(failure_times, success.timestamp - timedelta(minutes=window_minutes))
            right = bisect_left(failure_times, success.timestamp)
            if right - left >= threshold:
                matching_failures = failures[left:right]
                findings.append(_finding(
                    "Successful login after repeated failures",
                    f"A successful authentication followed {len(matching_failures)} failed attempts for the same account and source within {window_minutes} minutes.",
                    "high", 0.90, [*matching_failures, success],
                    ["Verify the successful login with the account owner.", "Review nearby authentication activity."],
                ))
                break
    return findings


def detect_authentication_bursts(
    events: list[SecurityEvent], threshold: int = 10, window_minutes: int = 5
) -> list[dict]:
    """Detect a high failure rate from one source, across any accounts."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")
    groups: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in _auth_events(events):
        if event.source_ip and _outcome(event) in FAILURES:
            groups[event.source_ip].append(event)
    findings = []
    for group in groups.values():
        ordered = sorted(group, key=lambda event: event.timestamp)
        for start, end in _window_indices(ordered, window_minutes):
            if end - start >= threshold:
                matched = ordered[start:end]
                findings.append(_finding(
                    "Authentication failure burst from one source",
                    f"One source produced {len(matched)} failed authentication events within {window_minutes} minutes.",
                    "high", 0.85, matched,
                    ["Review the affected accounts and determine whether the source is expected."],
                ))
                break
    return findings


def detect_multiple_account_targeting(
    events: list[SecurityEvent], threshold: int = 5, window_minutes: int = 5
) -> list[dict]:
    """Detect one source failing authentication against distinct accounts."""
    if threshold < 2 or window_minutes < 1:
        raise ValueError("threshold must be at least 2 and window_minutes must be positive")
    groups: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in _auth_events(events):
        if event.source_ip and event.username and _outcome(event) in FAILURES:
            groups[event.source_ip].append(event)
    findings = []
    for group in groups.values():
        ordered = sorted(group, key=lambda event: event.timestamp)
        right = 0
        account_counts: Counter[str] = Counter()
        for start, first in enumerate(ordered):
            boundary = first.timestamp + timedelta(minutes=window_minutes)
            while right < len(ordered) and ordered[right].timestamp <= boundary:
                account_counts[ordered[right].username] += 1
                right += 1
            if len(account_counts) >= threshold:
                matched = ordered[start:right]
                findings.append(_finding(
                    "Failed authentication across multiple accounts",
                    f"One source had failed authentication events for {len({event.username for event in matched})} distinct accounts within {window_minutes} minutes.",
                    "medium", 0.82, matched,
                    ["Check whether the source is an approved identity test or a misconfigured client."],
                ))
                break
            account_counts[ordered[start].username] -= 1
            if account_counts[ordered[start].username] <= 0:
                del account_counts[ordered[start].username]
    return findings


def analyze_events(events: list[SecurityEvent], config: DetectionConfig | None = None) -> dict:
    """Run configured deterministic rules and return the analysis contract."""
    config = config or DetectionConfig()
    findings = [
        *detect_repeated_failed_logins(events, config.repeated_failures, config.repeated_window_minutes),
        *detect_success_after_repeated_failures(events, config.success_after_failures, config.success_window_minutes),
        *detect_authentication_bursts(events, config.burst_failures, config.burst_window_minutes),
        *detect_multiple_account_targeting(events, config.multiple_account_count, config.multiple_account_window_minutes),
    ]
    event_ids = {event.event_id for event in events}
    if any(not set(finding["evidence_event_ids"]).issubset(event_ids) for finding in findings):
        raise ValueError("Detection returned evidence IDs absent from input")
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = max((finding["severity"] for finding in findings), key=order.get, default="unknown")
    timeline = [
        TimelineEvent.model_validate({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "source": event.source,
            "username": event.username,
            "source_ip": event.source_ip,
            "outcome": event.outcome,
        }).model_dump(mode="json")
        for event in sorted(events, key=lambda item: item.timestamp)
    ]
    actions = list(dict.fromkeys(action for finding in findings for action in finding["recommended_actions"]))
    return {
        "summary": (
            f"Detected {len(findings)} configured pattern(s) across {len(events)} submitted events."
            if findings else f"No configured detection patterns matched {len(events)} submitted events."
        ),
        "severity": severity,
        "confidence": max((finding["confidence"] for finding in findings), default=0.0),
        "findings": findings,
        "timeline": timeline,
        "recommended_actions": actions,
        "limitations": [
            "Results are deterministic indicators and are not proof of compromise.",
            "Detection is limited to the implemented authentication rules and supplied events.",
        ],
    }


def _auth_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    return [event for event in events if event.event_type.casefold() == AUTH_TYPE]


def _by_account_source(events: list[SecurityEvent]) -> dict[tuple[str, str], list[SecurityEvent]]:
    groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in _auth_events(events):
        if event.username and event.source_ip and _outcome(event) in FAILURES | SUCCESSES:
            groups[(event.username, event.source_ip)].append(event)
    return groups


def _outcome(event: SecurityEvent) -> str:
    return (event.outcome or "").casefold()


def _window_indices(events: list[SecurityEvent], window_minutes: int):
    right = 0
    for left, first in enumerate(events):
        right = max(right, left)
        boundary = first.timestamp + timedelta(minutes=window_minutes)
        while right < len(events) and events[right].timestamp <= boundary:
            right += 1
        yield left, right


def _finding(title, rationale, severity, confidence, events, actions) -> dict:
    return Finding(
        title=title,
        rationale=rationale,
        severity=severity,
        confidence=confidence,
        evidence_event_ids=[event.event_id for event in events],
        recommended_actions=actions,
    ).model_dump(mode="json")
