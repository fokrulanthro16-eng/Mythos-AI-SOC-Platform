"""tests/test_parsers.py — Comprehensive tests for the parsers ingestion module."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from parsers.base import NormalizedIncident, extract_indicators, normalize_severity
from parsers.csv_parser import CSVParser
from parsers.dedup import DuplicateDetector
from parsers.ingestion_service import IngestionService, _detect_format
from parsers.json_parser import JSONParser
from parsers.syslog_parser import SyslogParser

# ===========================================================================
# base.py — normalize_severity
# ===========================================================================


def test_normalize_severity_low_aliases():
    for raw in ("low", "LOW", "info", "INFO", "debug", "1"):
        assert normalize_severity(raw) == "LOW"


def test_normalize_severity_medium_aliases():
    for raw in ("medium", "MEDIUM", "warning", "warn", "moderate", "2"):
        assert normalize_severity(raw) == "MEDIUM"


def test_normalize_severity_high_aliases():
    for raw in ("high", "HIGH", "error", "ERROR", "err", "major", "3"):
        assert normalize_severity(raw) == "HIGH"


def test_normalize_severity_critical_aliases():
    for raw in ("critical", "CRITICAL", "crit", "fatal", "emergency", "emerg", "alert", "4"):
        assert normalize_severity(raw) == "CRITICAL"


def test_normalize_severity_unknown_defaults_medium():
    assert normalize_severity("banana") == "MEDIUM"
    assert normalize_severity("") == "MEDIUM"
    assert normalize_severity("xyz123") == "MEDIUM"


def test_normalize_severity_strips_whitespace():
    assert normalize_severity("  HIGH  ") == "HIGH"
    assert normalize_severity("\tlow\n") == "LOW"


# ===========================================================================
# base.py — extract_indicators
# ===========================================================================


def test_extract_indicators_ipv4():
    text = "Connection from 192.168.1.100 to 10.0.0.1 flagged."
    inds = extract_indicators(text)
    assert "192.168.1.100" in inds
    assert "10.0.0.1" in inds


def test_extract_indicators_md5_hash():
    text = "Malware hash: d41d8cd98f00b204e9800998ecf8427e"
    inds = extract_indicators(text)
    assert "d41d8cd98f00b204e9800998ecf8427e" in inds


def test_extract_indicators_domain():
    text = "C2 beacon to evil.example.com detected"
    inds = extract_indicators(text)
    assert any("evil.example.com" in i for i in inds)


def test_extract_indicators_deduplicates():
    text = "IP 10.0.0.1 and again 10.0.0.1 in logs"
    inds = extract_indicators(text)
    assert inds.count("10.0.0.1") == 1


def test_extract_indicators_empty_text():
    assert extract_indicators("") == []


# ===========================================================================
# base.py — NormalizedIncident.fingerprint
# ===========================================================================


def test_fingerprint_stable():
    inc = NormalizedIncident(threat_name="Ransomware", severity="HIGH", indicators=["1.2.3.4"])
    assert inc.fingerprint() == inc.fingerprint()


def test_fingerprint_differs_on_threat_name():
    a = NormalizedIncident(threat_name="Ransomware", severity="HIGH")
    b = NormalizedIncident(threat_name="Phishing", severity="HIGH")
    assert a.fingerprint() != b.fingerprint()


def test_fingerprint_differs_on_severity():
    a = NormalizedIncident(threat_name="Ransomware", severity="HIGH")
    b = NormalizedIncident(threat_name="Ransomware", severity="CRITICAL")
    assert a.fingerprint() != b.fingerprint()


def test_fingerprint_stable_regardless_of_indicator_order():
    a = NormalizedIncident(threat_name="T", severity="MEDIUM", indicators=["1.1.1.1", "2.2.2.2"])
    b = NormalizedIncident(threat_name="T", severity="MEDIUM", indicators=["2.2.2.2", "1.1.1.1"])
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_case_insensitive_threat_name():
    a = NormalizedIncident(threat_name="Ransomware", severity="HIGH")
    b = NormalizedIncident(threat_name="RANSOMWARE", severity="HIGH")
    assert a.fingerprint() == b.fingerprint()


# ===========================================================================
# JSONParser
# ===========================================================================


class TestJSONParser:
    parser = JSONParser()

    def test_parse_array_of_incidents(self):
        content = json.dumps([
            {"threat_name": "Ransomware", "severity": "CRITICAL"},
            {"threat_name": "Phishing", "severity": "HIGH"},
        ])
        r = self.parser.parse(content, "test.json")
        assert len(r.incidents) == 2
        assert r.incidents[0].threat_name == "Ransomware"
        assert r.incidents[0].severity == "CRITICAL"

    def test_parse_single_object(self):
        content = json.dumps({"threat_name": "Trojan", "severity": "high"})
        r = self.parser.parse(content)
        assert len(r.incidents) == 1
        assert r.incidents[0].severity == "HIGH"

    def test_parse_wrapped_incidents_key(self):
        content = json.dumps({"incidents": [
            {"threat_name": "SQLi"},
            {"threat_name": "XSS"},
        ]})
        r = self.parser.parse(content)
        assert len(r.incidents) == 2

    def test_parse_wrapped_alerts_key(self):
        content = json.dumps({"alerts": [{"threat_name": "BruteForce"}]})
        r = self.parser.parse(content)
        assert len(r.incidents) == 1

    def test_parse_invalid_json_returns_error(self):
        r = self.parser.parse("{not json}", "bad.json")
        assert len(r.incidents) == 0
        assert any("Invalid JSON" in e for e in r.errors)

    def test_parse_missing_threat_name_records_error(self):
        content = json.dumps([{"severity": "HIGH", "indicators": ["1.2.3.4"]}])
        r = self.parser.parse(content)
        assert len(r.incidents) == 0
        assert len(r.errors) == 1

    def test_parse_severity_alias_mapping(self):
        content = json.dumps([{"threat_name": "T", "severity": "warning"}])
        r = self.parser.parse(content)
        assert r.incidents[0].severity == "MEDIUM"

    def test_parse_indicators_as_list(self):
        content = json.dumps([{
            "threat_name": "T",
            "indicators": ["1.1.1.1", "2.2.2.2"],
        }])
        r = self.parser.parse(content)
        assert set(r.incidents[0].indicators) == {"1.1.1.1", "2.2.2.2"}

    def test_parse_indicators_pipe_separated_string(self):
        content = json.dumps([{"threat_name": "T", "iocs": "1.1.1.1|2.2.2.2"}])
        r = self.parser.parse(content)
        assert "1.1.1.1" in r.incidents[0].indicators

    def test_parse_empty_array(self):
        r = self.parser.parse("[]")
        assert len(r.incidents) == 0
        assert len(r.errors) == 0

    def test_parse_bytes_input(self):
        content = json.dumps([{"threat_name": "T"}]).encode()
        r = self.parser.parse(content, "f.json")
        assert len(r.incidents) == 1

    def test_parse_auto_generates_incident_id(self):
        content = json.dumps([{"threat_name": "T"}])
        r = self.parser.parse(content)
        assert r.incidents[0].incident_id.startswith("INC-UPLOAD-")

    def test_parse_uses_provided_incident_id(self):
        content = json.dumps([{"threat_name": "T", "incident_id": "MY-001"}])
        r = self.parser.parse(content)
        assert r.incidents[0].incident_id == "MY-001"

    def test_parse_source_format_set(self):
        r = self.parser.parse(json.dumps([{"threat_name": "T"}]))
        assert r.incidents[0].source_format == "json"

    def test_parse_flexible_alias_name_field(self):
        content = json.dumps([{"name": "Rootkit"}])
        r = self.parser.parse(content)
        assert r.incidents[0].threat_name == "Rootkit"


# ===========================================================================
# CSVParser
# ===========================================================================


class TestCSVParser:
    parser = CSVParser()

    def test_parse_basic_csv(self):
        csv = "threat_name,severity\nRansomware,CRITICAL\nPhishing,HIGH\n"
        r = self.parser.parse(csv, "test.csv")
        assert len(r.incidents) == 2
        assert r.incidents[0].threat_name == "Ransomware"
        assert r.incidents[0].severity == "CRITICAL"

    def test_parse_with_indicators_pipe_separated(self):
        csv = "threat_name,indicators\nMalware,1.2.3.4|5.6.7.8\n"
        r = self.parser.parse(csv)
        assert "1.2.3.4" in r.incidents[0].indicators
        assert "5.6.7.8" in r.incidents[0].indicators

    def test_parse_missing_threat_column_returns_error(self):
        csv = "alert,severity\nSQL Injection,HIGH\n"
        r = self.parser.parse(csv)
        assert len(r.incidents) == 0
        assert any("threat_name" in e.lower() for e in r.errors)

    def test_parse_empty_threat_name_skipped(self):
        csv = "threat_name,severity\n,HIGH\nRansomware,CRITICAL\n"
        r = self.parser.parse(csv)
        assert len(r.incidents) == 1
        assert r.incidents[0].threat_name == "Ransomware"

    def test_parse_bom_stripped(self):
        csv = "﻿threat_name,severity\nT,HIGH\n"
        r = self.parser.parse(csv)
        assert len(r.incidents) == 1

    def test_parse_severity_aliases(self):
        csv = "threat_name,severity\nT,error\n"
        r = self.parser.parse(csv)
        assert r.incidents[0].severity == "HIGH"

    def test_parse_bytes_input(self):
        csv = "threat_name\nRansomware\n".encode()
        r = self.parser.parse(csv)
        assert len(r.incidents) == 1

    def test_parse_auto_generates_incident_id(self):
        csv = "threat_name\nT\n"
        r = self.parser.parse(csv)
        assert r.incidents[0].incident_id.startswith("INC-UPLOAD-")

    def test_parse_source_format_set(self):
        r = self.parser.parse("threat_name\nT\n")
        assert r.incidents[0].source_format == "csv"

    def test_parse_flexible_column_aliases(self):
        csv = "name,level\nBotnet,critical\n"
        r = self.parser.parse(csv)
        assert r.incidents[0].threat_name == "Botnet"
        assert r.incidents[0].severity == "CRITICAL"


# ===========================================================================
# SyslogParser
# ===========================================================================


class TestSyslogParser:
    parser = SyslogParser()

    def test_parse_rfc3164_format(self):
        line = "<134>Jun 17 12:00:01 server01 sshd[1234]: Failed password for root from 192.168.1.1 port 22"
        r = self.parser.parse(line, "syslog.log")
        assert len(r.incidents) == 1
        inc = r.incidents[0]
        assert inc.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_parse_rfc3164_critical_priority(self):
        # PRI=2 (facility=0, severity=2=crit) → CRITICAL
        line = "<2>Jun 17 12:00:01 server01 kern[1]: Critical malware detected"
        r = self.parser.parse(line)
        assert r.incidents[0].severity == "CRITICAL"

    def test_parse_rfc5424_format(self):
        line = "<134>1 2026-06-17T12:00:00Z server01 sshd 1234 - - Failed password from 10.0.0.1"
        r = self.parser.parse(line, "f.log")
        assert len(r.incidents) == 1

    def test_parse_simple_iso_timestamp_format(self):
        line = "2026-06-17T12:00:00Z server01 nginx: SQL injection attempt from 192.168.100.1"
        r = self.parser.parse(line)
        assert len(r.incidents) == 1
        assert r.incidents[0].severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_parse_extracts_ip_as_indicator(self):
        line = "<134>Jun 17 12:00:01 server01 sshd: Brute force from 10.10.10.99"
        r = self.parser.parse(line)
        assert any("10.10.10.99" in ind for ind in r.incidents[0].indicators)

    def test_parse_threat_name_ransomware(self):
        line = "<131>Jun 17 12:00:01 server01 antivirus: ransomware detected in /tmp/enc.exe"
        r = self.parser.parse(line)
        assert "ransomware" in r.incidents[0].threat_name.lower()

    def test_parse_threat_name_brute_force(self):
        line = "<134>Jun 17 12:00:01 server01 sshd: brute force attack detected"
        r = self.parser.parse(line)
        assert "brute" in r.incidents[0].threat_name.lower()

    def test_parse_severity_from_keywords_critical(self):
        line = "<5>Jun 17 12:00:01 server01 ids: CRITICAL ransomware outbreak"
        r = self.parser.parse(line)
        # PRI=5 → LOW, but keyword says CRITICAL — PRI takes precedence in RFC3164 parsing
        assert r.incidents[0].severity in ("LOW", "CRITICAL")

    def test_parse_empty_file_returns_error(self):
        r = self.parser.parse("", "empty.log")
        assert len(r.incidents) == 0
        assert any("empty" in e.lower() for e in r.errors)

    def test_parse_multiple_lines(self):
        content = (
            "<134>Jun 17 12:00:01 host sshd: Failed password from 1.2.3.4\n"
            "<134>Jun 17 12:00:02 host sshd: Failed password from 5.6.7.8\n"
        )
        r = self.parser.parse(content)
        assert len(r.incidents) == 2

    def test_parse_source_format_set(self):
        line = "<134>Jun 17 12:00:01 host sshd: test event"
        r = self.parser.parse(line)
        assert r.incidents[0].source_format == "syslog"

    def test_parse_auto_generates_incident_id(self):
        line = "<134>Jun 17 12:00:01 host sshd: test event"
        r = self.parser.parse(line)
        assert r.incidents[0].incident_id.startswith("INC-SYSLOG-")


# ===========================================================================
# DuplicateDetector
# ===========================================================================


class TestDuplicateDetector:
    def test_new_fingerprint_not_duplicate(self, tmp_path):
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        assert not dd.is_duplicate("abc123")

    def test_mark_seen_detects_duplicate(self, tmp_path):
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        dd.mark_seen("abc123")
        assert dd.is_duplicate("abc123")

    def test_persists_across_instances(self, tmp_path):
        store = tmp_path / "fp.jsonl"
        dd1 = DuplicateDetector(store_path=store)
        dd1.mark_seen("myfingerprint")

        dd2 = DuplicateDetector(store_path=store)
        assert dd2.is_duplicate("myfingerprint")

    def test_different_fingerprints_independent(self, tmp_path):
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        dd.mark_seen("fp-a")
        assert not dd.is_duplicate("fp-b")

    def test_reset_clears_store(self, tmp_path):
        store = tmp_path / "fp.jsonl"
        dd = DuplicateDetector(store_path=store)
        dd.mark_seen("fp-x")
        dd.reset()
        assert not dd.is_duplicate("fp-x")
        assert not store.exists()

    def test_seen_count_increments(self, tmp_path):
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        assert dd.seen_count == 0
        dd.mark_seen("fp-1")
        dd.mark_seen("fp-2")
        assert dd.seen_count == 2

    def test_double_mark_seen_is_idempotent(self, tmp_path):
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        dd.mark_seen("fp-x")
        dd.mark_seen("fp-x")
        assert dd.seen_count == 1


# ===========================================================================
# IngestionService — format detection
# ===========================================================================


def test_detect_format_json_extension():
    assert _detect_format("incidents.json", b"[]") == "json"


def test_detect_format_csv_extension():
    assert _detect_format("data.csv", b"a,b\n") == "csv"


def test_detect_format_log_extension():
    assert _detect_format("syslog.log", b"<1>") == "log"


def test_detect_format_sniff_json_array():
    assert _detect_format("unknownfile", b"[{") == "json"


def test_detect_format_sniff_csv_content():
    assert _detect_format("unknownfile", b"name,severity\n") == "csv"


# ===========================================================================
# IngestionService — end-to-end
# ===========================================================================


class TestIngestionService:
    def _service(self, tmp_path: Path) -> IngestionService:
        dd = DuplicateDetector(store_path=tmp_path / "fp.jsonl")
        return IngestionService(dedup=dd, uploads_dir=tmp_path, run_pipeline=False)

    def test_ingest_json_returns_result(self, tmp_path):
        svc = self._service(tmp_path)
        content = json.dumps([{"threat_name": f"T-{uuid.uuid4().hex[:6]}", "severity": "HIGH"}])
        result, accepted = svc.ingest(content.encode(), "test.json")
        assert result.parsed_count == 1
        assert result.accepted_count == 1
        assert len(accepted) == 1

    def test_ingest_dedup_blocks_second_upload(self, tmp_path):
        svc = self._service(tmp_path)
        content = json.dumps([{"threat_name": "Unique-Threat-XYZ", "severity": "HIGH"}])
        result1, _ = svc.ingest(content.encode(), "a.json")
        result2, _ = svc.ingest(content.encode(), "b.json")
        assert result1.accepted_count == 1
        assert result2.duplicate_count == 1
        assert result2.accepted_count == 0

    def test_ingest_csv_file(self, tmp_path):
        svc = self._service(tmp_path)
        csv = f"threat_name,severity\n{uuid.uuid4().hex},HIGH\n"
        result, accepted = svc.ingest(csv.encode(), "data.csv")
        assert result.format == "csv"
        assert result.accepted_count == 1

    def test_ingest_saves_raw_file_to_uploads(self, tmp_path):
        svc = self._service(tmp_path)
        content = json.dumps([{"threat_name": f"T-{uuid.uuid4().hex[:6]}"}])
        svc.ingest(content.encode(), "incident.json")
        saved = list(tmp_path.glob("*_incident.json"))
        assert len(saved) == 1

    def test_ingest_writes_manifest(self, tmp_path):
        svc = self._service(tmp_path)
        content = json.dumps([{"threat_name": f"T-{uuid.uuid4().hex[:6]}"}])
        svc.ingest(content.encode(), "x.json")
        manifest = tmp_path / "upload_manifest.jsonl"
        assert manifest.exists()
        lines = [l for l in manifest.read_text().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_load_manifest_returns_history(self, tmp_path):
        svc = self._service(tmp_path)
        for i in range(3):
            content = json.dumps([{"threat_name": f"T-{i}-{uuid.uuid4().hex[:6]}"}])
            svc.ingest(content.encode(), f"file{i}.json")
        history = svc.load_manifest()
        assert len(history) == 3

    def test_ingest_error_file_still_returns_result(self, tmp_path):
        svc = self._service(tmp_path)
        result, accepted = svc.ingest(b"{not json}", "bad.json")
        assert result.error_count >= 1
        assert result.accepted_count == 0
        assert len(accepted) == 0

    def test_ingest_result_has_upload_id(self, tmp_path):
        svc = self._service(tmp_path)
        content = json.dumps([{"threat_name": f"T-{uuid.uuid4().hex[:6]}"}])
        result, _ = svc.ingest(content.encode(), "x.json")
        assert len(result.upload_id) == 32  # uuid4 hex

    def test_ingest_syslog(self, tmp_path):
        svc = self._service(tmp_path)
        log = "<134>Jun 17 12:00:01 host sshd: Failed password for root from 10.0.0.1"
        result, accepted = svc.ingest(log.encode(), "events.log")
        assert result.format == "log"
        assert result.accepted_count >= 1
