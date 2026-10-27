
from datetime import timezone
from pydantic import BaseModel, Field
from typing import Literal

from agent.schemas import validate_events
from agent.detections import (
    detect_repeated_failed_logins,
    detect_success_after_repeated_failures,
)


class InvestigationReport(BaseModel):
    summary: str
    severity: Literal["low", "medium", "high", "critical", "unknown"]
    confidence: float = Field(ge=0, le=1)
    findings: list[dict]
    timeline: list[dict]
    recommended_actions: list[str]
    limitations: list[str]


def run_investigation(
    events: list[dict],
    context: dict | None = None,
) -> dict:
    """Run a bounded, deterministic security investigation."""

    validated_events = validate_events(events)

    repeated_failures = detect_repeated_failed_logins(validated_events)
    success_after_failures = detect_success_after_repeated_failures(
        validated_events
    )

    raw_findings = repeated_failures + success_after_failures

    valid_ids = {event.event_id for event in validated_events}
    findings = []

    for finding in raw_findings:
        evidence_ids = [
            event_id
            for event_id in finding.get("evidence_event_ids", [])
            if event_id in valid_ids
        ]

        findings.append({
            "title": finding.get("title", "Suspicious authentication activity"),
            "rationale": finding.get("rationale", ""),
            "evidence_event_ids": evidence_ids,
            "confidence": finding.get("confidence", 0.5),
        })

    timeline = [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "source": event.source,
            "username": event.username,
            "source_ip": event.source_ip,
            "outcome": event.outcome,
        }
        for event in sorted(
            validated_events,
            key=lambda event: event.timestamp,
        )
    ]

    if findings:
        severity = "high"
        summary = (
            f"Detected {len(findings)} suspicious authentication pattern(s). "
            "These findings do not prove account compromise."
        )
        confidence = max(
            (float(f.get("confidence", 0.5)) for f in raw_findings),
            default=0.5,
        )
    else:
        severity = "unknown"
        summary = "No configured detection rule identified a suspicious pattern."
        confidence = 0.0

    report = InvestigationReport(
        summary=summary,
        severity=severity,
        confidence=confidence,
        findings=findings,
        timeline=timeline,
        recommended_actions=[
            "Review the supporting authentication events.",
            "Verify the activity with the authorised system owner.",
        ] if findings else [
            "Review the limitations of the configured detection rules."
        ],
        limitations=[
            "Deterministic rules only; no LLM was used.",
            "Confidence values are heuristic and not calibrated probabilities.",
            "Only the configured authentication patterns were investigated.",
        ],
    )

    return report.model_dump(mode="json")

