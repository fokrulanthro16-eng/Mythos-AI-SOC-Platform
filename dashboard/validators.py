"""dashboard/validators.py — Data quality validation for Mythos SOC records.

Each validator returns (is_valid: bool, errors: list[str]).
Call validate_dataset() to validate an entire collection at once.
"""

from __future__ import annotations

import re
from datetime import datetime

_VALID_SEVERITIES     = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_INC_STATUSES   = {"DETECTED", "INVESTIGATING", "CONTAINED", "MITIGATED", "RESOLVED"}
_VALID_CASE_STATUSES  = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}
_VALID_CASE_PRIORITIES = {"P1", "P2", "P3", "P4"}
_VALID_ANALYST_TIERS  = {"Tier 1", "Tier 2", "Tier 3"}
_VALID_CAMP_STATUSES  = {"ACTIVE", "INACTIVE", "DISRUPTED", "MONITORING"}
_VALID_SOPHIST        = {"basic", "intermediate", "advanced", "nation-state"}
_INC_ID_RE            = re.compile(r"^INC-\d{4}-\d{3,6}$")
_CAMP_ID_RE           = re.compile(r"^CAMP-[\w-]+$")
_CASE_ID_RE           = re.compile(r"^[0-9a-f-]{36}$")  # UUID
_EMAIL_RE             = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Incident validator
# ---------------------------------------------------------------------------


def validate_incident(record: dict) -> tuple[bool, list[str]]:
    """Validate a single incident record.  Returns (is_valid, errors)."""
    errors: list[str] = []
    iid = record.get("incident_id", "")

    if not iid:
        errors.append("incident_id is required")
    elif not _INC_ID_RE.match(iid):
        errors.append(f"incident_id '{iid}' does not match INC-YYYY-NNN format")

    severity = record.get("severity", "")
    if severity not in _VALID_SEVERITIES:
        errors.append(f"severity '{severity}' must be one of {sorted(_VALID_SEVERITIES)}")

    status = record.get("status", "")
    if status not in _VALID_INC_STATUSES:
        errors.append(f"status '{status}' must be one of {sorted(_VALID_INC_STATUSES)}")

    threat = record.get("threat_name", "")
    if not threat:
        errors.append("threat_name is required")

    created_raw = record.get("created_at", "")
    if not created_raw:
        errors.append("created_at is required")
    else:
        created = _parse_iso(created_raw)
        if created is None:
            errors.append(f"created_at '{created_raw}' is not valid ISO-8601")
        else:
            updated_raw = record.get("updated_at", "")
            if updated_raw:
                updated = _parse_iso(updated_raw)
                if updated is None:
                    errors.append(f"updated_at '{updated_raw}' is not valid ISO-8601")
                elif updated < created:
                    errors.append("updated_at must not be before created_at")

    conf = record.get("confidence_score")
    if conf is not None:
        try:
            f = float(conf)
            if not (0.0 <= f <= 1.0):
                errors.append(f"confidence_score {f} must be 0.0–1.0")
        except (TypeError, ValueError):
            errors.append(f"confidence_score '{conf}' must be numeric")

    risk = record.get("risk_score")
    if risk is not None:
        try:
            f = float(risk)
            if not (0.0 <= f <= 1.0):
                errors.append(f"risk_score {f} must be 0.0–1.0")
        except (TypeError, ValueError):
            errors.append(f"risk_score '{risk}' must be numeric")

    attr = record.get("attribution_confidence")
    if attr is not None:
        try:
            f = float(attr)
            if not (0.0 <= f <= 1.0):
                errors.append(f"attribution_confidence {f} must be 0.0–1.0")
        except (TypeError, ValueError):
            errors.append(f"attribution_confidence '{attr}' must be numeric")

    indicators = record.get("indicators")
    if indicators is not None and not isinstance(indicators, list):
        errors.append("indicators must be a list")

    techniques = record.get("attack_techniques")
    if techniques is not None:
        if not isinstance(techniques, list):
            errors.append("attack_techniques must be a list")
        else:
            for i, t in enumerate(techniques):
                if not isinstance(t, dict):
                    errors.append(f"attack_techniques[{i}] must be a dict")
                elif not t.get("technique_id"):
                    errors.append(f"attack_techniques[{i}] missing technique_id")

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Campaign validator
# ---------------------------------------------------------------------------


def validate_campaign(record: dict) -> tuple[bool, list[str]]:
    """Validate a single campaign record.  Returns (is_valid, errors)."""
    errors: list[str] = []
    cid = record.get("campaign_id", "")

    if not cid:
        errors.append("campaign_id is required")
    elif not _CAMP_ID_RE.match(cid):
        errors.append(f"campaign_id '{cid}' does not match CAMP-... format")

    if not record.get("name"):
        errors.append("name is required")

    if not record.get("threat_actor"):
        errors.append("threat_actor is required")

    status = record.get("status", "")
    if status and status not in _VALID_CAMP_STATUSES:
        errors.append(f"status '{status}' must be one of {sorted(_VALID_CAMP_STATUSES)}")

    soph = record.get("sophistication", "")
    if soph and soph not in _VALID_SOPHIST:
        errors.append(f"sophistication '{soph}' must be one of {sorted(_VALID_SOPHIST)}")

    for date_field in ("first_seen", "last_seen"):
        raw = record.get(date_field, "")
        if raw and _parse_iso(raw + "T00:00:00") is None:
            # Try plain date format YYYY-MM-DD
            try:
                datetime.strptime(raw, "%Y-%m-%d")
            except ValueError:
                errors.append(f"{date_field} '{raw}' must be YYYY-MM-DD")

    first_raw = record.get("first_seen", "")
    last_raw  = record.get("last_seen", "")
    if first_raw and last_raw:
        try:
            first = datetime.strptime(first_raw, "%Y-%m-%d")
            last  = datetime.strptime(last_raw,  "%Y-%m-%d")
            if last < first:
                errors.append("last_seen must not be before first_seen")
        except ValueError:
            pass

    ttps = record.get("ttps")
    if ttps is not None and not isinstance(ttps, list):
        errors.append("ttps must be a list")

    victims = record.get("estimated_victims")
    if victims is not None:
        try:
            n = int(victims)
            if n < 0:
                errors.append("estimated_victims must be non-negative")
        except (TypeError, ValueError):
            errors.append(f"estimated_victims '{victims}' must be an integer")

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Case validator
# ---------------------------------------------------------------------------


def validate_case(record: dict) -> tuple[bool, list[str]]:
    """Validate a single case record.  Returns (is_valid, errors)."""
    errors: list[str] = []

    if not record.get("id") and not record.get("case_number"):
        errors.append("case requires id or case_number")

    if not record.get("title"):
        errors.append("title is required")

    status = record.get("status", "")
    if status not in _VALID_CASE_STATUSES:
        errors.append(f"status '{status}' must be one of {sorted(_VALID_CASE_STATUSES)}")

    priority = record.get("priority", "")
    if priority and priority not in _VALID_CASE_PRIORITIES:
        errors.append(f"priority '{priority}' must be one of {sorted(_VALID_CASE_PRIORITIES)}")

    created_raw  = record.get("created_at", "")
    resolved_raw = record.get("resolved_at", "")

    if created_raw:
        created = _parse_iso(created_raw)
        if created is None:
            errors.append(f"created_at '{created_raw}' is not valid ISO-8601")
        elif resolved_raw:
            resolved = _parse_iso(resolved_raw)
            if resolved is None:
                errors.append(f"resolved_at '{resolved_raw}' is not valid ISO-8601")
            elif resolved < created:
                errors.append("resolved_at must not be before created_at")

    if status in ("RESOLVED", "CLOSED") and not resolved_raw:
        errors.append("resolved_at is required when status is RESOLVED or CLOSED")

    notes = record.get("notes")
    if notes is not None and not isinstance(notes, list):
        errors.append("notes must be a list")

    history = record.get("history")
    if history is not None and not isinstance(history, list):
        errors.append("history must be a list")

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Analyst validator
# ---------------------------------------------------------------------------


def validate_analyst(record: dict) -> tuple[bool, list[str]]:
    """Validate a single analyst record.  Returns (is_valid, errors)."""
    errors: list[str] = []

    if not record.get("analyst_id"):
        errors.append("analyst_id is required")

    if not record.get("name"):
        errors.append("name is required")

    email = record.get("email", "")
    if email and not _EMAIL_RE.match(email):
        errors.append(f"email '{email}' is not a valid email address")

    tier = record.get("tier", "")
    if tier and tier not in _VALID_ANALYST_TIERS:
        errors.append(f"tier '{tier}' must be one of {sorted(_VALID_ANALYST_TIERS)}")

    active = record.get("active_cases")
    if active is not None:
        try:
            n = int(active)
            if n < 0:
                errors.append("active_cases must be non-negative")
        except (TypeError, ValueError):
            errors.append(f"active_cases '{active}' must be an integer")

    exp = record.get("years_experience")
    if exp is not None:
        try:
            n = int(exp)
            if n < 0:
                errors.append("years_experience must be non-negative")
        except (TypeError, ValueError):
            errors.append(f"years_experience '{exp}' must be an integer")

    certs = record.get("certifications")
    if certs is not None and not isinstance(certs, list):
        errors.append("certifications must be a list")

    specs = record.get("specializations")
    if specs is not None and not isinstance(specs, list):
        errors.append("specializations must be a list")

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Dataset-level validation
# ---------------------------------------------------------------------------


def validate_dataset(
    records: list[dict],
    validator,
    id_field: str = "id",
) -> dict:
    """
    Validate a list of records with the given validator function.

    Returns:
        {
            "total":   int,
            "valid":   int,
            "invalid": int,
            "errors":  [{"record_id": str, "errors": [str]}],
        }
    """
    total   = len(records)
    valid   = 0
    details: list[dict] = []

    seen_ids: set[str] = set()

    for rec in records:
        ok, errs = validator(rec)
        rec_id   = str(rec.get(id_field, ""))

        if rec_id in seen_ids and rec_id:
            errs = list(errs) + [f"duplicate {id_field}: '{rec_id}'"]
            ok   = False
        if rec_id:
            seen_ids.add(rec_id)

        if ok:
            valid += 1
        else:
            details.append({"record_id": rec_id, "errors": errs})

    return {
        "total":   total,
        "valid":   valid,
        "invalid": total - valid,
        "errors":  details,
    }
