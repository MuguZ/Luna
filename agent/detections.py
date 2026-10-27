
from datetime import timedelta

from agent.schemas import SecurityEvent


def detect_repeated_failed_logins(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    """
    Detect repeated failed authentication attempts for the same
    username and source IP within a time window.

    This is a suspicious-activity indicator, not proof of compromise.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    auth_failures = [
        event
        for event in events
        if event.event_type.lower() == "authentication"
        and (event.outcome or "").lower() == "failure"
        and event.username
        and event.source_ip
    ]

    groups: dict[tuple[str, str], list[SecurityEvent]] = {}

    for event in auth_failures:
        key = (event.username, event.source_ip)
        groups.setdefault(key, []).append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (username, source_ip), group in groups.items():
        ordered = sorted(group, key=lambda event: event.timestamp)

        for start_index, start_event in enumerate(ordered):
            matching = []

            for event in ordered[start_index:]:
                if event.timestamp - start_event.timestamp > window:
                    break
                matching.append(event)

            if len(matching) >= threshold:
                evidence_ids = [event.event_id for event in matching]

                findings.append({
                    "title": "Repeated failed authentication attempts",
                    "rationale": (
                        f"{len(matching)} failed authentication attempts "
                        f"for account {username} from {source_ip} occurred "
                        f"within {window_minutes} minutes. This may indicate "
                        "a brute-force attempt, but does not prove compromise."
                    ),
                    "severity": "medium",
                    "confidence": 0.8,
                    "evidence_event_ids": evidence_ids,
                })
                break

    return findings
