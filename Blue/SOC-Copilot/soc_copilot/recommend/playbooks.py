"""Static remediation playbooks, keyed by a small internal category taxonomy.

Vendor "category"/"tactic" fields are all over the map (Defender says
"Execution", CrowdStrike says "Credential Access", Huntress says a status
string) so we don't key off them directly - classify_category() does a
keyword pass over the incident's own text into ~7 buckets an MSP generalist
actually plans around, and the CLI/webapp fall back to "generic" for anything
that doesn't match. Each playbook is deliberately written for a competent
generalist tech, not a specialist: concrete actions, no unexplained jargon.
"""
from __future__ import annotations

from soc_copilot.models import Incident, Recommendation, TriageResult

# Ordered: first matching category wins, so put more specific/severe patterns first.
_CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("ransomware", ["ransomware", "canary", "encrypt", "inhibit system recovery", "shadow copy"]),
    ("credential_access", ["lsass", "mimikatz", "procdump", "credential dump", "password spray", "brute force"]),
    ("phishing", ["phishing", "macro", "spearphish", "malicious attachment", "malicious link"]),
    ("suspicious_login", ["impossible travel", "sign-in", "signin", "mfa", "new device login", "unfamiliar location"]),
    ("persistence", ["registry run key", "scheduled task", "persistence", "autostart", "startup folder"]),
    ("discovery_recon", ["port scan", "network scan", "discovery", "enumeration"]),
    ("malware_execution", ["encoded command", "powershell", "injection", "injected", "malware", "trojan", "backdoor", "rundll32"]),
    ("data_exfiltration", ["exfil", "data transfer", "upload to", "unusual outbound"]),
]

PLAYBOOKS: dict[str, dict[str, list[str]]] = {
    "ransomware": {
        "contain": [
            "Isolate the affected host from the network immediately (disable NIC / pull network cable / isolate via EDR) - do NOT power it off, you'll lose memory forensics.",
            "Check file shares and backup targets the host has access to; disable/restrict that access if encryption may be spreading.",
            "Disable the user account's ability to log into other hosts until the source is confirmed contained.",
        ],
        "eradicate": [
            "Identify and terminate the encrypting process if it's still running (do this before any cleanup, from an out-of-band admin session, not by RDP'ing into the infected host).",
            "Do not delete or reimage yet if this is a confirmed incident - law enforcement/insurance/forensics may need the disk image first. Check the client's IR contract.",
        ],
        "recover": [
            "Verify backup integrity and recency for anything affected before restoring - do not restore over the top of the still-connected shares.",
            "Rotate credentials for every account that touched the host in the last 7 days.",
        ],
        "communicate": [
            "Escalate to a human immediately - this is a P1 regardless of what this tool suggests. Do not let an automated queue sit on a ransomware indicator.",
            "Prepare a client-facing status note once contained: what happened, what's contained, what's still being verified.",
        ],
    },
    "credential_access": {
        "contain": [
            "Disable/lock the account(s) involved and force a password reset on next login.",
            "If a service account is involved, rotate its credential and check what else uses that credential before you rotate (avoid breaking a scheduled job blind).",
            "Revoke active sessions/tokens for the account (Entra ID / Google Workspace / IdP session revocation, not just password reset).",
        ],
        "eradicate": [
            "Check for new scheduled tasks, services, or startup items created by the account around the time of the alert.",
            "Review the host for the actual dumping tool artifact (procdump output file, mimikatz binary, LSASS dump file) and remove it.",
        ],
        "recover": [
            "Re-enable the account only after credential rotation and a clean scan.",
            "If this was a domain controller or admin account, assume broader compromise until scoped - check other hosts the same credential could reach.",
        ],
        "communicate": [
            "Note in the ticket exactly which account(s) were rotated and when, for the client's audit trail.",
        ],
    },
    "phishing": {
        "contain": [
            "Quarantine/delete the email from all mailboxes it was delivered to (check for internal forwarding, not just the reported recipient).",
            "If a link was clicked or attachment opened, isolate that endpoint pending an AV/EDR scan.",
        ],
        "eradicate": [
            "Block the sender domain/IP and any URLs from the message at the email gateway and web proxy/firewall.",
            "Check the user's mailbox for newly created inbox rules (a common follow-on to a compromised mailbox) and remove anything suspicious.",
        ],
        "recover": [
            "If credentials were entered on a phishing page, treat as credential_access above - rotate and revoke sessions.",
        ],
        "communicate": [
            "Send the client a short user-awareness note referencing this specific email (subject line, sender) so staff recognize the pattern if it's reused.",
        ],
    },
    "suspicious_login": {
        "contain": [
            "Verify with the user directly (phone/Teams, not email) whether the sign-in was theirs.",
            "If not confirmed legitimate, revoke active sessions and force MFA re-registration.",
        ],
        "eradicate": [
            "Check for mailbox rules, OAuth app grants, or forwarding rules added after the suspicious sign-in.",
        ],
        "recover": [
            "Re-enable normal access only after the user confirms and MFA is re-verified.",
        ],
        "communicate": [
            "If confirmed legitimate travel/VPN behavior, document it as benign_positive with the reason - this cuts down repeat noise on the same user.",
        ],
    },
    "persistence": {
        "contain": [
            "Do not remove the persistence mechanism yet if you want to identify what it's calling out to - note the target/command first.",
        ],
        "eradicate": [
            "Remove the registry Run key / scheduled task / startup item once documented.",
            "Check for a dropped payload file referenced by the persistence entry and remove it.",
        ],
        "recover": [
            "Re-scan the host after removal to confirm nothing re-creates the entry (a live process may recreate it on a timer).",
        ],
        "communicate": [
            "Note the exact persistence mechanism and target in the ticket - useful if the same pattern shows up on another client host later.",
        ],
    },
    "discovery_recon": {
        "contain": [
            "Confirm this isn't an authorized vulnerability scan or asset inventory tool the client runs.",
        ],
        "eradicate": [
            "If unauthorized, identify the source host/account and treat it as potentially compromised - scope what else it touched.",
        ],
        "recover": [
            "No recovery action needed if this turns out to be authorized tooling; document it to suppress future false positives.",
        ],
        "communicate": [
            "Ask the client if they run any scanning tools on this network segment before escalating further.",
        ],
    },
    "malware_execution": {
        "contain": [
            "Isolate the host from the network pending a scan.",
            "Kill the suspicious process tree if still running (from an out-of-band session).",
        ],
        "eradicate": [
            "Run a full AV/EDR scan; quarantine or remove identified payloads.",
            "Check the parent process chain (what launched it - email client, browser, script) to close the actual entry point, not just the payload.",
        ],
        "recover": [
            "Return the host to service only after a clean scan and, if a user opened a malicious file, brief re-training.",
        ],
        "communicate": [
            "Note the delivery vector in the ticket (email attachment, drive-by download, USB, etc.) if determinable.",
        ],
    },
    "data_exfiltration": {
        "contain": [
            "If a destination is identified, block it at the firewall/proxy immediately.",
            "Isolate the host if the transfer may still be in progress.",
        ],
        "eradicate": [
            "Identify what data was accessible to the account/host involved and scope what may have left.",
        ],
        "recover": [
            "Rotate any credentials/API keys that were on the host or accessible to the account.",
        ],
        "communicate": [
            "This may trigger breach-notification obligations depending on the client's industry/data - flag to the account manager, don't let a tech decide this alone.",
        ],
    },
    "generic": {
        "contain": [
            "Review the correlated alerts together before acting - confirm whether this looks like one real event or several unrelated low-signal alerts.",
        ],
        "eradicate": [
            "No category-specific playbook matched; use the AI verdict/notes above as the primary guidance for this incident.",
        ],
        "recover": [
            "Document your findings either way - even a false positive worth noting reduces repeat noise on this client.",
        ],
        "communicate": [
            "Use analyst judgment on whether this needs client notification.",
        ],
    },
}


def classify_category(incident: Incident) -> str:
    text = " ".join(f"{a.title} {a.description} {a.category}" for a in incident.alerts).lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in text for kw in keywords):
            return category
    return "generic"


def build_recommendation(incident: Incident, triage: TriageResult) -> Recommendation:
    category = classify_category(incident)
    steps = PLAYBOOKS.get(category, PLAYBOOKS["generic"])
    tailored = (
        triage.generation_notes
        if triage.is_llm_generated and triage.generation_notes
        else "No LLM-tailored recommendation available (heuristic fallback mode) - follow the standard playbook and use analyst judgment for anything incident-specific."
    )
    return Recommendation(
        playbook_name=category.replace("_", " ").title(),
        matched_category=category,
        steps={phase: list(items) for phase, items in steps.items()},
        tailored_notes=tailored,
    )
