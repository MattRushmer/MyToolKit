"""A small, curated reference of common MITRE ATT&CK (Enterprise) technique IDs.

Detection Forge (the sibling tool in Blue/) bundles the full offline ATT&CK
STIX dataset for rigorous validation - that's the right call there, because it
ships detection rules. This tool only tags incidents for an analyst's benefit,
so a full multi-megabyte dataset would be overkill; instead we ship the ~60
techniques that actually show up in day-to-day MSP/SMB incidents (initial
access, execution, credential access, ransomware precursors, C2) and flag
anything outside that list as "unrecognized - verify manually" rather than
silently trusting or silently dropping it.
"""
from __future__ import annotations

COMMON_TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1204": "User Execution",
    "T1204.002": "User Execution: Malicious File",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1110": "Brute Force",
    "T1110.003": "Brute Force: Password Spraying",
    "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1070": "Indicator Removal",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1046": "Network Service Discovery",
    "T1018": "Remote System Discovery",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1105": "Ingress Tool Transfer",
    "T1567": "Exfiltration Over Web Service",
    "T1041": "Exfiltration Over C2 Channel",
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1114": "Email Collection",
    "T1114.003": "Email Collection: Email Forwarding Rule",
    "T1195": "Supply Chain Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1486.001": "Data Encrypted for Impact: Ransomware",  # not an official sub-technique; kept as a soft alias some tools emit
    "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure",
}


def lookup(technique_id: str) -> tuple[bool, str | None]:
    """Returns (recognized, name). Unrecognized IDs still pass through - this
    is a hint for the analyst, not a hard validator like Detection Forge's."""
    key = technique_id.strip().upper()
    name = COMMON_TECHNIQUES.get(key)
    return (name is not None, name)
