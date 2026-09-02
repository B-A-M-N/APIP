# 08 — Energy and OT Alignment

## Purpose

APIP is not an OT endpoint product. Its energy-sector role is to improve defense at shared network boundaries while minimizing operational risk to control systems.

## Architectural placement

Preferred locations:

- utility enterprise internet edge;
- secure DNS service;
- remote-access boundary;
- OT DMZ northbound firewall/proxy where existing architecture permits;
- managed service/provider infrastructure upstream of utility customers.

Avoid placing APIP as a new inline dependency in deterministic control/protection paths.

## Why this aligns with current public guidance

CISA's Cross-Sector Cybersecurity Performance Goals emphasize high-impact baseline practices for IT and OT. DOE CESER and NARUC's cybersecurity baselines for electric distribution systems and DER focus on risk-informed cybersecurity foundations and prioritization. APIP can support network protection, visibility, and incident mitigation, but it does not replace those broader programs.

## NERC CIP considerations

As of 2026-09-01, NERC lists multiple currently enforced and future CIP standards. Relevant themes for APIP include:

- CIP-005: Electronic Security Perimeter controls and monitoring.
- CIP-007: system security management.
- CIP-008: incident reporting and response planning.
- CIP-010: configuration change management and vulnerability assessments.
- CIP-011: information protection.
- CIP-015: internal network security monitoring, listed as future enforcement.

APIP may generate configuration changes, logs, detections, and incident evidence that fall into an operator's existing CIP processes. Applicability and compliance determinations belong to the registered entity and its compliance program.

## OT-specific policy defaults

1. Automatic exact-FQDN RPZ blocking may be allowed only if critical-vendor and operational domains are explicitly protected by allowlists.
2. Automatic exact-IP blocking should be more conservative than enterprise defaults.
3. No automated prefix denies.
4. No routing actions without network/OT operations approval.
5. Remote-access control changes should preserve emergency access procedures.
6. Rule rollout should be canaried on non-critical segments where practical.
7. Telemetry retention should support incident response without capturing unnecessary control payloads.
8. All enforcement decisions must be attributable and reversible.
9. **Allow-first posture (`docs/26`) is the preferred v2 control for OT DMZ northbound boundaries, control-network boundaries, and vendor/remote-access segments** — enumerated egress with deny-by-default is the deterministic answer to novel C2 egress from fixed-function segments. OT-owner signoff is a mandatory approver for segment onboarding and every allowlist addition in OT scopes; safety-instrumented-system and protection-relay traffic paths remain entirely out of scope.
10. **Host quarantine (L6) of OT assets requires OT-operations signoff in addition to standard approvals** — containing an engineering workstation must never outrank the OT owner's judgment about process continuity.
11. **Virtual patching (`docs/27`) is well-suited to OT patch windows**: VP-3 exposure reduction first (management interfaces unreachable from populations that never legitimately use them), signature classes only with vendor/advisory-supplied logic and alert-first staging.

## Energy-sector use cases

### C2 egress suppression
A compromised enterprise/DMZ host attempts to resolve/contact a high-confidence active C2 domain. A managed resolver or edge firewall blocks the path before the connection succeeds.

### Phishing/malware delivery domain suppression
High-confidence domains are blocked at resolver/proxy level for the entire protected population.

### Campaign burst protection
A newly active campaign produces a rapidly changing set of exact domains. APIP ingests corroborated intelligence, applies short-lived DNS policies, and expires them automatically as evidence ages.

### DDoS filtering coordination
At an ISP or utility-owned routing domain, a human-approved routing adapter can distribute a narrowly scoped FlowSpec rule for traffic destined to an authorized protected prefix. This is a high-risk profile and not part of default automatic enforcement.

## What APIP does not solve

- compromised PLC logic;
- unsafe engineering workstations already inside the OT network;
- supply-chain compromise inside signed vendor software;
- physical attacks;
- identity compromise where malicious activity uses otherwise legitimate destinations;
- traffic that does not traverse an APIP-controlled enforcement point;
- lateral movement that never crosses an inter-zone boundary (partially observable at inter-zone chokepoints only).

It is one control layer, not a complete critical-infrastructure security program.
