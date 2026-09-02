# 09 — Security, Privacy, and Governance

## Authorization model

Roles:

- `viewer`
- `analyst`
- `policy_editor`
- `approver`
- `adapter_operator`
- `tenant_admin`
- `platform_admin`
- `auditor`

High-risk approvals should not be satisfiable by the same identity that authored the change when two-person control is enabled.

## Credential design

- one credential set per source connector;
- one credential set per enforcement domain;
- least privilege on devices;
- no long-lived credentials in repository/config files;
- secret manager integration in production;
- rotation and revocation tested.

## Policy signing

Recommended signed object:

```text
bundle_header
canonical_policy_delta
scope
created_at
expires_at
previous_bundle_hash
signing_key_id
signature
```

Adapters validate the signature and scope locally.

## Privacy

Collect the minimum data necessary to decide and verify actions.

Prefer:
- domain/IP/flow metadata;
- aggregated match counts;
- pseudonymous tenant/client identifiers where individual identity is unnecessary;
- short retention for high-volume telemetry.

Avoid by default:
- full packet payload capture;
- application content unrelated to the threat;
- personal data copied from threat feeds when not operationally necessary.

CISA's AIS documentation specifically emphasizes minimizing and removing PII not directly related to a cyber threat; APIP should adopt the same general privacy principle even when using other sources.

## Auditability

Every enforcement action must answer:

1. What was blocked/limited?
2. At what scope?
3. Why?
4. Which evidence supported it?
5. Which policy version authorized it?
6. Who approved it, if required?
7. When did it start and expire?
8. Which device revision implemented it?
9. What traffic matched it?
10. Was it revoked, rolled back, or superseded?

## Defend-the-defender (v2)

The APIP control plane concentrates authority over every enforcement point in the deployment; it is therefore the single highest-value target in the environment and must not be the softest one:

- **The controller runs in its own allow-first segment** (`docs/26`) — management-plane egress is enumerable (database, device APIs, NTP, update servers) and deny-by-default; the defender's own medicine applies to the defender first.
- **Edge agents are pull-only.** Agents initiate all connections (bundle fetch, receipt upload) and listen for nothing inbound; a compromised agent exposes no management listener, and there is no inbound path to attack when the controller is unreachable.
- **Adapter egress is pinned.** Each adapter's segment permit-list names the specific device management APIs it may contact; a compromised adapter cannot pivot laterally to unrelated infrastructure.
- **Signing remains isolated**: HSM/KMS-held, human-controlled service identities only (`docs/21`), never resident on controller web nodes and never grantable to programmatic clients (`docs/28`).
- Baseline hardening unchanged: mTLS everywhere, least-privilege per-domain credentials, immutable logs, short-lived credentials.

## Governance artifacts (v2 additions marked)

Production deployments should maintain:

- authorization boundary document;
- approved action catalog **including interdiction rungs per tenant/segment (`docs/25`)**;
- source trust register;
- allowlist ownership register **including segment allowlist review cadence and expiry policy (`docs/26`)**;
- emergency/break-glass procedure **including segment break-glass profiles with dual control and time-boxing (`docs/26`)**;
- false-positive review procedure;
- routing-action approval procedure;
- data retention policy;
- incident escalation matrix;
- change-management integration;
- **virtual-patch remediation-linkage policy: no VP without a ticket, orphaned VPs are findings (`docs/27`)**;
- **randomization bounds register: which mechanisms are randomized, with what bounds versions (`docs/29`)**;
- **coverage-floor policy per population segment and its compensating-controls posture (`docs/24`)**;
- **AI-exclusion statement for the supply chain: dependency review rejects AI/ML/LLM SDKs in platform components (`docs/28`)**.

## Legal/contractual note

APIP's technical architecture assumes operator authorization. An ISP, resolver provider, utility, enterprise, or cloud service must separately determine what filtering is permitted by law, regulation, customer agreements, and internal policy. The product should expose configuration to implement those constraints rather than pretending one legal policy fits all operators.
