
from datetime import timedelta

from agent.schemas import SecurityEvent


def detect_repeated_failed_logins(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    groups: dict[tuple[str, str], list[SecurityEvent]] = {}

    for event in events:
        if (
            event.event_type.lower() == "authentication"
            and (event.outcome or "").lower() == "failure"
            and event.username
            and event.source_ip
        ):
            groups.setdefault(
                (event.username, event.source_ip), []
            ).append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (username, source_ip), group in groups.items():
        ordered = sorted(group, key=lambda event: event.timestamp)

        for start_index, start_event in enumerate(ordered):
            matching = [
                event
                for event in ordered[start_index:]
                if event.timestamp - start_event.timestamp <= window
            ]

            if len(matching) >= threshold:
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
                    "evidence_event_ids": [
                        event.event_id for event in matching
                    ],
                })
                break

    return findings


def detect_success_after_repeated_failures(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    groups: dict[tuple[str, str], list[SecurityEvent]] = {}

    for event in events:
        if (
            event.event_type.lower() == "authentication"
            and event.username
            and event.source_ip
        ):
            groups.setdefault(
                (event.username, event.source_ip), []
            ).append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (username, source_ip), group in groups.items():
        ordered = sorted(group, key=lambda event: event.timestamp)

        for index, event in enumerate(ordered):
            if (event.outcome or "").lower() != "success":
                continue

            previous_failures = [
                item
                for item in ordered[:index]
                if (item.outcome or "").lower() == "failure"
                and timedelta(0) <= event.timestamp - item.timestamp <= window
            ]

            if len(previous_failures) >= threshold:
                findings.append({
                    "title": (
                        "Successful authentication after repeated failures"
                    ),
                    "rationale": (
                        f"A successful login for account {username} "
                        f"from {source_ip} followed {len(previous_failures)} "
                        f"failed authentication attempts within "
                        f"{window_minutes} minutes. This may indicate "
                        "suspicious activity, but does not prove compromise."
                    ),
                    "severity": "high",
                    "confidence": 0.8,
                    "evidence_event_ids": [
                        item.event_id for item in previous_failures
                    ] + [event.event_id],
                })
                break

    return findings
