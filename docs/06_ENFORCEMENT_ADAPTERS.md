# 06 — Enforcement Adapters

## Adapter contract

An adapter is a narrowly privileged actuator client. It accepts only already-authorized Enforcement Intents and translates them into device-specific configuration.

Every adapter must support:

- capability declaration;
- scope declaration;
- prepare/dry-run;
- apply;
- verify;
- revoke;
- reconcile;
- health;
- audit receipt.

## DNS RPZ adapter

### Preferred capabilities
- exact QNAME block;
- response-IP action where operator explicitly enables it;
- PASSTHRU exceptions;
- disabled/log-only policy zone for shadow evaluation;
- atomic zone replacement or IXFR/AXFR-based distribution;
- serial/version tracking.

### Safety requirements
- canonical FQDN validation;
- block public suffix / high-level wildcard actions by default;
- local allowlist zone evaluated before global block zone;
- rule TTL/zone refresh compatible with APIP expiry;
- shadow policy zone support.

### Output
For portability, APIP can compile standard RPZ zone records. Production adapters may manage BIND, Unbound, PowerDNS, or provider APIs.

## Firewall/IPS adapter

### Preferred capabilities
- exact source/destination IP;
- 5-tuple match where context exists;
- rate-limit or deny;
- per-(client,destination) pair rate ceilings (L2 rung, `docs/25`);
- segment-scoped egress allowlist groups (L3 rung / allow-first, `docs/26`);
- virtual-patch signature groups with alert/drop staging (VP-1, `docs/27`);
- DoH/DoT known-hosts egress controls (TCP/853 and known DoH endpoints, `docs/24`);
- staged rule group;
- hit counters;
- rule expiry;
- atomic commit where vendor supports it.

### Suricata integration
Suricata rules can serve as a portable compile target for IPS deployments. APIP should distinguish `alert` from `drop` semantics and use shadow/IDS mode before inline IPS enforcement. Virtual-patch rule sets compile to the same artifact class with patch-tracking metadata.

### Safety requirements
- exact IP by default;
- no CIDR auto deny;
- shared-infrastructure classification;
- per-tenant/home-net scoping;
- max rule count and apply delta;
- L2 ceilings are per-pair, never destination-global;
- L3 groups only for segments that completed onboarding (`docs/26`).

## Proxy/WAF adapter

Capabilities:
- host/domain deny;
- URL/path deny when exact context is available;
- challenge (L1 rung, interactive paths only — never non-interactive protocols);
- rate-limit;
- client IP reputation;
- rule expiration;
- match telemetry;
- virtual-patch path/method suppression (VP-2) and vulnerable-path challenge (VP-4) (`docs/27`).

Because application-layer controls have more context, they can sometimes safely act where IP-only controls cannot.

## NAC / host-containment adapter

Scopes enforcement to a single internal asset (L6, `docs/25`):

- restrict a host's egress to an allowlist or fully, at the chokepoint or via NAC APIs the operator already operates;
- no endpoint agent; acts on operator-owned assets;
- requires behavioral-cluster depth ≥ 3 or an active-compromise signal;
- approval-gated; full isolation always human-approved;
- OT hosts additionally require OT-operations signoff (`docs/08`);
- removal from a segment allowlist (within allow-first segments) is the simplest containment form (`docs/26`).

## Routing adapter

### Supported conceptual targets
- exact destination prefix owned by operator/customer;
- narrowly defined flow specification for DDoS or clearly authorized filtering.

### Mandatory constraints
- adapter compiled disabled in default builds or marked experimental;
- manual approval;
- destination-prefix allowlist;
- no arbitrary source-prefix blackholing outside contractual/operator scope;
- no inter-domain propagation unless separately engineered and authorized;
- device-side policy must independently filter acceptable FlowSpec NLRI/actions;
- max prefixes and max TTL;
- explicit rollback command;
- canary router/VRF when possible.

RFC 8955/8956 provide a standardized BGP mechanism for propagating flow specifications and traffic-filtering actions, but APIP treats the mechanism as high risk because protocol capability does not equal operational safety.

## Adapter anti-patterns

- Give one adapter credential access to all routers/firewalls.
- Permit adapters to accept raw feed indicators.
- Use permanent rules for volatile indicators.
- Treat “apply API returned 200” as verification.
- Let controller policy override device-side scope safeguards.
