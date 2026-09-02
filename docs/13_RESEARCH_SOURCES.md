# 13 — Research Sources and Architecture Implications

Accessed/reviewed for this specification on or before **2026-09-01**.

## NIST

### NIST Cybersecurity Framework (CSF) 2.0
https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20

Implication: APIP should map governance, protection, detection, response, and recovery rather than optimize only for blocking. CSF 2.0 explicitly adds Govern to the prior Identify/Protect/Detect/Respond/Recover functions.

### NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management
https://csrc.nist.gov/pubs/sp/800/61/r3/final

Implication: APIP decisions, actions, evidence, and rollback should integrate into incident-response lifecycle and broader cybersecurity risk management.

## CISA

### Cross-Sector Cybersecurity Performance Goals
https://www.cisa.gov/cybersecurity-performance-goals

Implication: APIP should support high-impact risk-reduction practices applicable to IT and OT, while remaining one control within a broader program.

### Known Exploited Vulnerabilities Catalog
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Implication: KEV is valuable prioritization context for vulnerability management. It is not a direct network indicator feed and should not automatically create blocks.

### Automated Indicator Sharing (AIS) 2.0 STIX Profile
https://www.cisa.gov/resources-tools/resources/automated-indicator-sharing-ais-20-stix-profile

Implication: STIX/TAXII interoperability remains relevant for machine-to-machine CTI. Privacy/minimization principles should be retained even outside AIS.

## DOE / NARUC energy sector

### DOE CESER — Cybersecurity Baselines for Electric Distribution Systems and DER and Guidance
https://www.energy.gov/ceser/cybersecurity-baselines-electric-distribution-systems-and-der-and-guidance

### NARUC — Cybersecurity Baselines for Electric Distribution Systems and DER
https://www.naruc.org/core-sectors/critical-infrastructure-and-cybersecurity/cybersecurity-for-utility-regulators/cybersecurity-baselines/

Implication: energy-sector deployment must be risk-informed, scoped to critical assets, and integrated with operator processes rather than inserted casually into safety-critical paths.

### DOE CESER — Cybersecurity RD&D for Energy Systems
https://www.energy.gov/ceser/cybersecurity-research-development-and-demonstration-energy-systems

Implication: measurable mitigation, threat/vulnerability information sharing, and transition-to-practice are appropriate goals for an APIP pilot.

### DOE CESER — Cybersecurity Threat Profile Development Guide for the Energy Sector (2026-07-28)
https://www.energy.gov/ceser/articles/ceser-releases-cybersecurity-threat-profile-development-guide-energy-sector

Implication: DOE explicitly frames the operational problem as converting fragmented, changing threat updates into prioritized, documented, validated threat profiles. APIP adopts the same discipline at the evidence-to-network-control boundary: ingestion is separated from validation, prioritization, and action.

### DOE CESER — Cybersecurity Capability Maturity Model (C2M2)
https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2

Implication: APIP should be deployable as one capability inside a larger energy-sector cybersecurity maturity program rather than presented as a complete security program.

## OASIS standards

### STIX Version 2.1
https://www.oasis-open.org/standard/stix-version-2-1/

Implication: use an open structured language for cyber threat/observable information at interchange boundaries.

### TAXII Version 2.1
https://www.oasis-open.org/standard/taxii-version-2-1/

Implication: use a standardized HTTPS application-layer protocol for CTI exchange when sources support it.

### OpenC2 Language Specification 1.0
https://www.oasis-open.org/standard/oc2-ls-v1-0/

Implication: represent defensive action requests in action/target/actuator/modifier terms so the core decision plane is not coupled to a vendor API.

### CACAO Security Playbooks Version 2.0
https://www.oasis-open.org/standard/cacao-security-playbooks-v2-0/

Implication: multi-step security workflows can be represented as shareable playbooks rather than hard-coded procedural glue.

## OCSF

### Open Cybersecurity Schema Framework
https://github.com/ocsf/ocsf-schema

Implication: export APIP operational events using a vendor-neutral normalized security event model where useful.

## DNS RPZ

### ISC — Response Policy Zones
https://www.isc.org/rpz/

### NLnet Labs Unbound — Response Policy Zones
https://unbound.docs.nlnetlabs.nl/en/latest/topics/filtering/rpz.html

Implication: DNS filtering is a mature and interoperable first enforcement surface. RPZ supports explicit triggers/actions, local exceptions, logging, and disabled/shadow use.

## Network detection/enforcement

### Suricata rule actions
https://docs.suricata.io/en/latest/rules/intro.html

Implication: alert/pass/drop/reject semantics can support a clear progression from detection-only to inline enforcement.

### Zeek Intelligence Framework
https://docs.zeek.org/en/current/frameworks/intel.html

Implication: local network observations can be matched against intelligence and used as independent evidence rather than relying solely on external feeds.

## Policy engines

### Open Policy Agent — Integration
https://www.openpolicyagent.org/docs/integration

### Open Policy Agent — Decision Logs
https://www.openpolicyagent.org/docs/management-decision-logs

Implication: a distributed policy engine can provide low-latency local decisions, bundles, status, and decision telemetry. OPA is optional, not a mandatory dependency.

## Routing

### RFC 8955 — Dissemination of Flow Specification Rules
https://www.rfc-editor.org/rfc/rfc8955.html

### RFC 8956 — Dissemination of Flow Specification Rules for IPv6
https://www.rfc-editor.org/rfc/rfc8956.html

Implication: BGP FlowSpec provides a standardized mechanism to distribute traffic filtering actions, but the protocol's power demands strict authorization, route-policy constraints, and manual approval in APIP.

## NERC CIP

### NERC Critical Infrastructure Protection standards index
https://www.nerc.com/standards/reliability-standards/cip

### CIP-008-7.1
https://www.nerc.com/standards/reliability-standards/cip/cip-008-7.1

### NERC Internal Network Security Monitoring project / CIP-015
https://www.nerc.com/standards/reliability-standards-under-development/2023-03-internal-network-security-monitoring-insm

Implication: energy operators covered by NERC CIP have formal requirements and evolving standards around perimeter controls, system security, incident response, configuration management, information protection, and internal network monitoring. APIP must fit the operator's compliance boundary and evidence processes; it cannot self-declare compliance.

## MITRE ATT&CK

### Enterprise tactics
https://attack.mitre.org/tactics/enterprise/

Implication: APIP can tag evidence and decisions to ATT&CK context, particularly Command and Control and Impact, without using ATT&CK as an authorization mechanism.

## v2 additional sources (2026-09-01)

### Mozilla — Canonical DoH Exception Lists / use-application-dns.net
https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https

Implication: the standardized bootstrap mechanism by which deployments signal "DoH disabled here"; underpins the known-hosts containment strategy in `docs/24`.

### CISA — Free Tools for Industrial Control Systems (guidance on defense-in-depth/allowlist approaches for ICS)
https://www.cisa.gov/resources-tools/resources/ics-cybersecurity-tools

Implication: sector guidance supporting deny-by-default egress and application allowlisting for control environments; informs `docs/26` OT defaults.

### MITRE ATT&CK — Command and Control techniques (Application Layer Protocol, Encrypted Channel, Dynamic Resolver, Domain Generation Algorithms)
https://attack.mitre.org/tactics/ta0011/

Implication: the behavioral families BD-1..BD-7 in `docs/23` map to deterministically observable properties of these techniques (periodicity, resolution cycling, tunneling volume, fast flux).

### IETF RFC 8484 (via DNSOP work on discovering DoH) and RFC 8310 (TLS for DNS)
https://datatracker.ietf.org/doc/html/rfc8310

Implication: DoT/DoH transport identification (port 853, ALPN) is standardized, enabling deterministic egress classification in `docs/24`.

### Moving Target Defense literature (NIST SP 800-160 vol.3 adjacent practice; ACM/IEEE MTD symposium corpus)
https://csrc.nist.gov/pubs/sp/800/160/v3/final

Implication: parameter randomization as defense is established practice; `docs/29` constrains it to seeded, replay-preserving, bounds-enforced draws suitable for audited infrastructure.
