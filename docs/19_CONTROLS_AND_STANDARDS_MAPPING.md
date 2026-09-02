# 19 — Controls and Standards Mapping

## Important qualification

This mapping is an engineering crosswalk, **not a statement of compliance, certification, regulatory applicability, or legal sufficiency**. Applicability depends on the deploying organization, assets, jurisdiction, architecture, and regulator. A qualified operator/compliance team must determine formal compliance treatment.

## NIST Cybersecurity Framework 2.0

| CSF function | APIP capability |
|---|---|
| Govern | authorization scopes, policy versioning, approval tiers, source governance, risk acceptance, audit ownership, randomization bounds register (`docs/29`) |
| Identify | asset/tenant scope, threat/evidence inventory, provider/shared-infrastructure classification, dependency/allowlist context, **asset/service/exposure inventory (`docs/27`)** |
| Protect | bounded DNS/firewall/proxy/routing controls at authorized chokepoints, least privilege, signed bundles, **allow-first segments (`docs/26`), layered rungs (`docs/25`), virtual patches (`docs/27`), DoH/DoT containment (`docs/24`)** |
| Detect | CTI correlation, local DNS/flow/IDS observations, outcome telemetry, feed/edge health monitoring, **behavioral families (`docs/23`), denial telemetry (`docs/26`), coverage ledger (`docs/24`)** |
| Respond | evidence-driven decisions, operator approvals, suppression playbooks, incident escalation, emergency revoke, **L6 host quarantine (`docs/25`)** |
| Recover | automatic expiry, rollback, last-known-good bundles, control-plane disaster recovery, post-action review, **break-glass profiles with offline-proven expiry (`docs/26`), VP retirement on patch confirmation (`docs/27`)** |

## NIST SP 800-61 Rev. 3

APIP supports incident-response integration through:

- preparation: policies, playbooks, scopes, adapter tests, recovery bundles;
- detection/analysis: normalized evidence, source provenance, local sightings;
- response: bounded action proposals, approvals, enforcement, verification;
- recovery/improvement: rollback, expiry, outcome measurement, source/policy tuning.

APIP is a response-enabling control plane, not a complete incident-response program.

## CISA Cross-Sector Cybersecurity Performance Goals

Engineering alignment themes include:

- defensible, measurable high-impact security outcomes;
- IT/OT coordination rather than isolated tooling;
- centralized logging and monitoring of relevant security events;
- network segmentation/perimeter controls where applicable;
- incident response and recovery preparedness;
- secure product configuration and strong administrative access controls.

For an energy deployment, CISA/DOE/NARUC energy-specific baselines should be reviewed by the operator in addition to cross-sector goals.

## DOE CESER / C2M2

DOE's July 2026 Cybersecurity Threat Profile Development Guide emphasizes moving from fragmented threat updates to a prioritized, documented, validated threat profile. APIP implements a technical analogue at the indicator/action level:

```text
raw threat information
      -> identify/normalize
      -> prioritize/correlate
      -> document/provenance
      -> validate/local evidence
      -> bounded defensive decision
```

C2M2 can be used by an energy operator as a broader maturity framework around APIP; APIP itself is not a maturity model.

## NERC CIP engineering considerations

Where a Bulk Electric System entity is subject to NERC CIP, an APIP deployment may intersect with areas such as:

- Electronic Security Perimeter / external routable connectivity;
- system security management;
- incident reporting and response;
- configuration change management and vulnerability assessment;
- information protection;
- supply-chain risk management;
- internal network security monitoring as CIP-015 enters applicable enforcement timelines.

Design consequences:

1. place APIP where the operator can preserve existing ESP/OT trust boundaries;
2. treat policy and rule changes as controlled configuration changes when applicable;
3. retain receipts/evidence needed by operator processes;
4. avoid making APIP a safety-critical inline dependency;
5. coordinate with change control and incident response;
6. make data retention and access controls explicit;
7. do not advertise APIP as “NERC compliant” without a formal operator-specific assessment.

## STIX/TAXII

Use STIX 2.1 at CTI interchange boundaries and TAXII 2.1 where a source exposes TAXII. Internally, APIP may use a simpler canonical schema provided provenance and semantics are preserved.

## OpenC2

Use an OpenC2-inspired or conformant command representation to decouple the policy engine from individual actuators. The core abstraction is:

```text
action + target + actuator + modifiers + authorization context
```

A conformant implementation should validate against the relevant OpenC2 language/actuator profile rather than merely naming fields similarly.

## CACAO

Represent multi-step defensive workflows, especially analyst-approved or incident-response sequences, as CACAO-compatible playbooks where interoperability is needed. Keep one-step automatic enforcement in the deterministic policy path; a playbook engine should not be able to bypass the same authorization and blast-radius controls.

## OCSF

Where operators already consume OCSF, map APIP decision/action/receipt events into an appropriate event schema or extension. Preserve native APIP IDs so audit and replay can link exported telemetry back to source decisions.

## DNS RPZ

RPZ is the preferred first enforcement integration because response policy can be represented as local resolver policy with explicit exceptions and can be staged in logging/disabled modes. APIP must still respect the resolver implementation's exact semantics and test policy in shadow before activation.

## Suricata / firewall semantics

Suricata provides useful alert/pass/drop/reject semantics for a demonstrator and some production environments. In provider deployments, APIP should prefer the operator's native firewall/IPS API for atomic desired-state updates and verification, while retaining portable rule export for testing.

## BGP FlowSpec (RFC 8955 / 8956)

FlowSpec can distribute traffic filtering actions through BGP. Because the blast radius can be materially greater than DNS or a single firewall rule, APIP classifies it as a high-risk actuator. Manual approval, lab validation, route-policy boundaries, prefix constraints, TTL/withdrawal, and propagation limits are mandatory product requirements.
