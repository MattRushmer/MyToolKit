"""Turn registry-check results into Findings."""
from __future__ import annotations

from vibecheck.dependencies.models import DeclaredDependency
from vibecheck.dependencies.registry import RegistryCheckResult
from vibecheck.models import Category, Finding, Severity
from vibecheck.rules.catalog import (
    CWE_1357_SUPPLY_CHAIN,
    OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES,
    VIBE_DEP_NOT_ON_REGISTRY,
    VIBE_DEP_REGISTRY_UNCHECKED,
)


def build_dependency_findings(deps: list[DeclaredDependency], results: dict[tuple[str, str], RegistryCheckResult]) -> list[Finding]:
    findings: list[Finding] = []
    unchecked_count = 0

    for dep in deps:
        result = results.get((dep.ecosystem, dep.name))
        if result is None:
            continue
        if result.exists is False:
            registry_name = "PyPI" if dep.ecosystem == "pypi" else "npm"
            findings.append(Finding(
                finding_id=f"{VIBE_DEP_NOT_ON_REGISTRY}:{dep.manifest_file}:{dep.line}:{dep.name}",
                rule_id=VIBE_DEP_NOT_ON_REGISTRY,
                severity=Severity.CRITICAL,
                category=Category.HALLUCINATED_DEPENDENCY,
                title=f"'{dep.name}' does not exist on {registry_name} (possible hallucinated dependency)",
                description=(
                    f"'{dep.name}' is declared in {dep.manifest_file} but {registry_name} has no package "
                    "with this exact name. This is a known LLM failure mode ('slopsquatting'): a package "
                    "name that sounds plausible but was never published. Anyone who installs from this "
                    "manifest today gets an install error - but an attacker who notices the same "
                    "hallucinated name (from this or any other project) can publish malware under it, and "
                    "every future install then pulls a live supply-chain attack."
                ),
                file=dep.manifest_file,
                line=dep.line,
                snippet=dep.name,
                evidence={"name": dep.name, "ecosystem": dep.ecosystem},
                recommendation="Confirm the intended package name (check for a typo or a similarly-named real package) before this is ever installed in an environment with network access.",
                references=(CWE_1357_SUPPLY_CHAIN, OWASP_A08_SOFTWARE_DATA_INTEGRITY_FAILURES),
            ))
        elif result.exists is None:
            unchecked_count += 1

    if unchecked_count:
        findings.append(Finding(
            finding_id=f"{VIBE_DEP_REGISTRY_UNCHECKED}:summary",
            rule_id=VIBE_DEP_REGISTRY_UNCHECKED,
            severity=Severity.INFO,
            category=Category.HALLUCINATED_DEPENDENCY,
            title=f"{unchecked_count} declared dependenc{'y' if unchecked_count == 1 else 'ies'} could not be checked against the registry",
            description="The registry lookup for these packages didn't return a definitive answer (offline, timed out, or rate-limited) - they were skipped rather than guessed at.",
            file="",
            line=0,
            recommendation="Re-run with network access to check these.",
            references=(),
        ))

    return findings
