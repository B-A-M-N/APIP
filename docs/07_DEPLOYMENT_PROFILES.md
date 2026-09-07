# 07 — Deployment Profiles

## Profile A — Single-node research/lab

Purpose: validate scoring, policy, replay, and rule compilation without controlling production traffic.

Components:
- APIP monolith;
- SQLite or PostgreSQL;
- local files/STIX imports;
- null adapter;
- RPZ/Suricata file exporters;
- CLI and metrics.

Default mode: OBSERVE/SHADOW.

### Transport security (beta reality — read before exposing the API)

The beta API is **bearer-token over plain HTTP** (`docs/09`'s "mTLS
everywhere" describes the target hardened profile, not what ships today):

- default bind is loopback (`127.0.0.1`); the Compose profile publishes
  loopback only (`127.0.0.1:8510`);
- **remote operator access REQUIRES a TLS-terminating reverse proxy the
  operator runs** (nginx/Caddy/traefik or an existing ingress) in front of
  the API — never publish the plain-HTTP port to a shared network;
- the operator token is a bearer credential: anyone who can reach the
  unproxied port can use it, which is exactly why the default publish is
  loopback-only;
- mTLS between APIP and actuators is NOT implemented in beta; adapter
  control is local file/reload-command based (see `docs/06`).

## Profile B — Enterprise or utility perimeter

Topology:

```text
Internet
   |
[existing edge firewall / resolver / proxy]
   ^
   | signed APIP policy
[APIP control plane in security management zone]
   ^
   | feeds + SOC intel + sensor telemetry
[SIEM / sensors / CTI]
```

Controls are applied at existing northbound boundaries, not inside safety-critical control loops.

Recommended architecture:
- two APIP controller instances;
- PostgreSQL HA appropriate to organization;
- dedicated adapter credentials;
- DNS RPZ first;
- firewall/IPS second;
- routing disabled unless separately approved.

v2 priorities for this profile:
- onboarding OT DMZ / remote-access / management segments to allow-first posture (`docs/26`) — typically the highest-value v2 action for a utility;
- DoH/DoT containment at egress (`docs/24`) so resolver policy cannot be bypassed;
- virtual patching of internet-exposed services with long patch windows (`docs/27`);
- behavioral suite on resolver + flow telemetry (`docs/23`).

## Profile C — Managed resolver / security provider

One control plane protects many customers through resolver policy.

Key additions:
- tenant policy overlays;
- customer allowlists;
- per-tenant reporting;
- signed RPZ bundles/zones;
- edge resolver groups;
- canary rollout;
- global high-confidence feed layer.

This is the cleanest expression of the “one deployment protects many” model because the customer already delegates DNS resolution to the provider.

## Profile D — ISP / carrier

Possible enforcement surfaces:
- recursive DNS;
- scrubbing/DDoS infrastructure;
- security gateway;
- managed firewall;
- BGP FlowSpec/RTBH for operator-owned traffic under strict controls.

Requirements beyond the core:
- high-volume telemetry aggregation;
- router/device change governance;
- network-engineering approval path;
- prefix/community safety filters;
- service-impact SLOs;
- customer contract/policy alignment.

## Profile E — Cloud/WAF/SASE provider

Use provider-native APIs through adapters. Prefer challenge/rate-limit controls where confidence is high but collateral risk is non-trivial. Use exact host/URL/domain context whenever possible.

## Profile selection rule

APIP should always be deployed at the **highest-leverage existing enforcement point that already has legitimate control over the traffic**, rather than attempting to create a new universal intermediary.
