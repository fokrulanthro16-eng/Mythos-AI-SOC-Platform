"""parsers/syslog_parser.py — Parse syslog-format security event files."""

from __future__ import annotations

import re
import uuid

from parsers.base import BaseParser, NormalizedIncident, ParseResult, extract_indicators

# RFC 3164: <PRI>Mon DD HH:MM:SS host program[pid]: message
_RE_RFC3164 = re.compile(
    r'(?:<(?P<pri>\d+)>)?'
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[A-Za-z0-9_\-\.]+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.+)'
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED MESSAGE
_RE_RFC5424 = re.compile(
    r'<(?P<pri>\d+)>(?P<version>\d)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<procid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'\S+\s*'
    r'(?P<message>.*)'
)

# Simple: YYYY-MM-DDTHH:MM:SS host program: message
_RE_SIMPLE = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<program>[A-Za-z0-9_\-\.]+?)(?::\s*|\s+)'
    r'(?P<message>.+)'
)

# Severity keywords in syslog messages (ordered by priority: highest first)
_SEV_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(critical|crit|fatal|emergency|emerg|ransomware)\b', re.I), "CRITICAL"),
    (re.compile(r'\b(error|err|alert|high|danger|exploit|breach|intrusion)\b', re.I), "HIGH"),
    (re.compile(r'\b(warning|warn|medium|moderate|suspicious)\b', re.I), "MEDIUM"),
    (re.compile(r'\b(info|information|notice|debug|low)\b', re.I), "LOW"),
]

# RFC 3164 PRI field → severity (severity = PRI & 0x07)
def _pri_to_severity(pri: int) -> str:
    sev = pri & 0x07
    if sev <= 2:  return "CRITICAL"   # 0=emerg, 1=alert, 2=crit
    if sev == 3:  return "HIGH"       # 3=err
    if sev == 4:  return "MEDIUM"     # 4=warning
    return "LOW"                       # 5=notice, 6=info, 7=debug


# Threat-name extraction patterns (first match wins)
_THREAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\b(ransomware)\b', re.I),                      "Ransomware"),
    (re.compile(r'\b(malware|trojan|virus|worm)\b', re.I),       "Malware Detected"),
    (re.compile(r'\b(brute.?force|bruteforce)\b', re.I),         "Brute Force Attack"),
    (re.compile(r'\b(sql.?injection|sqli)\b', re.I),             "SQL Injection"),
    (re.compile(r'\b(phishing|spear.?phishing)\b', re.I),        "Phishing Attack"),
    (re.compile(r'\b(credential[s]?.?(harvest|dump|stuff))\b', re.I), "Credential Harvesting"),
    (re.compile(r'\b(port.?scan|nmap|scanner)\b', re.I),         "Port Scan"),
    (re.compile(r'\b(data.?exfil|exfiltrat)\b', re.I),          "Data Exfiltration"),
    (re.compile(r'\b(c2|c&c|command.and.control|beacon)\b', re.I), "Command and Control"),
    (re.compile(r'\b(privilege.?escal|privesc)\b', re.I),        "Privilege Escalation"),
    (re.compile(r'\b(lateral.?mov)\b', re.I),                    "Lateral Movement"),
    (re.compile(r'\b(dos|ddos|denial.of.service)\b', re.I),      "Denial of Service"),
    (re.compile(r'\b(CVE-\d{4}-\d+)\b', re.I),                  None),  # use matched text
    (re.compile(r'\b(exploit)\b', re.I),                         "Exploit Detected"),
    (re.compile(r'\b(unauthorized.?access)\b', re.I),            "Unauthorized Access"),
    (re.compile(r'\b(failed.?password|authentication.?fail)\b', re.I), "Authentication Failure"),
    (re.compile(r'\b(intrusion|breach)\b', re.I),                "Security Breach"),
]

_GENERIC_PROGRAMS = frozenset({"kernel", "systemd", "syslog", "logger", "rsyslogd", "syslogd"})


def _extract_threat_name(message: str, program: str = "") -> str:
    """Extract a meaningful threat name from a syslog message."""
    for pattern, label in _THREAT_PATTERNS:
        m = pattern.search(message)
        if m:
            return label if label else m.group(0).upper()
    prog = program.strip().lower().rstrip("d").rstrip("-")
    if prog and prog not in _GENERIC_PROGRAMS:
        return f"{program.strip()} Security Event"
    words = [w for w in message.split() if len(w) > 4 and w.isalpha()]
    if words:
        return " ".join(words[:3]).title()
    return "Unknown Security Event"


def _infer_severity(message: str, pri: int | None = None) -> str:
    if pri is not None:
        return _pri_to_severity(pri)
    for pattern, sev in _SEV_PATTERNS:
        if pattern.search(message):
            return sev
    return "MEDIUM"


class SyslogParser(BaseParser):
    format_name = "syslog"

    def parse(self, content: str | bytes, filename: str = "") -> ParseResult:
        result = ParseResult(source_file=filename, source_format="syslog")

        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        lines = [ln.rstrip() for ln in content.splitlines() if ln.strip()]
        if not lines:
            result.errors.append("Syslog file is empty")
            return result

        for lineno, line in enumerate(lines, 1):
            parsed = self._parse_line(line)
            if parsed is None:
                result.errors.append(f"Line {lineno}: could not parse: {line[:80]}")
                continue
            result.incidents.append(
                NormalizedIncident(
                    incident_id=f"INC-SYSLOG-{uuid.uuid4().hex[:8].upper()}",
                    threat_name=parsed["threat_name"],
                    severity=parsed["severity"],
                    indicators=parsed["indicators"],
                    source_format="syslog",
                    source_file=filename,
                    raw={"line": line, **{k: v for k, v in parsed.items() if k != "indicators"}},
                )
            )

        return result

    def _parse_line(self, line: str) -> dict | None:
        # Try RFC 5424
        m = _RE_RFC5424.match(line)
        if m:
            gd = m.groupdict()
            msg = gd.get("message", "")
            pri = int(gd["pri"]) if gd.get("pri") else None
            return {
                "threat_name": _extract_threat_name(msg, gd.get("app", "")),
                "severity": _infer_severity(msg, pri),
                "indicators": extract_indicators(msg),
                "host": gd.get("host", ""),
                "message": msg,
            }

        # Try RFC 3164
        m = _RE_RFC3164.match(line)
        if m:
            gd = m.groupdict()
            msg = gd.get("message", "")
            pri = int(gd["pri"]) if gd.get("pri") else None
            return {
                "threat_name": _extract_threat_name(msg, gd.get("program", "")),
                "severity": _infer_severity(msg, pri),
                "indicators": extract_indicators(msg),
                "host": gd.get("host", ""),
                "message": msg,
            }

        # Try simple ISO timestamp format
        m = _RE_SIMPLE.match(line)
        if m:
            gd = m.groupdict()
            msg = gd.get("message", "")
            return {
                "threat_name": _extract_threat_name(msg, gd.get("program", "")),
                "severity": _infer_severity(msg),
                "indicators": extract_indicators(msg),
                "host": gd.get("host", ""),
                "message": msg,
            }

        # Last resort: treat entire line as message
        if len(line) > 10:
            return {
                "threat_name": _extract_threat_name(line),
                "severity": _infer_severity(line),
                "indicators": extract_indicators(line),
                "host": "",
                "message": line,
            }

        return None
