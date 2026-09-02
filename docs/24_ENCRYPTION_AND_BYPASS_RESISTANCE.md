# 24 — Encryption and Bypass Resistance

## Problem

APIP's highest-leverage enforcement surface — resolver-layer RPZ — is only effective if the protected population actually uses the operator's resolver. Modern endpoints offer ubiquitous encrypted DNS (DoH/DoT/DoQ) and public resolvers that silently route around any chokepoint policy. An attacker who controls endpoint software (malware, malicious browser config) or users who self-select public resolvers bypass RPZ entirely. Every defense layered at the chokepoint is void if the attack path leaves through a side door.

Bypass resistance is therefore a **coverage property**, not a feature: the deployment must make the chokepoint the rational and practical path, detect when it is not being used, and compensate where it cannot be forced.

## Design stance

1. **Force, where authorized.** Redirect or block unauthorized encrypted-DNS egress so encrypted queries return to the managed resolver (see DoH/DoT known-hosts strategy below).
2. **Detect, where not forceable.** Where policy or law prevents forcing, measure chokepoint coverage continuously and treat uncovered populations as a first-class risk object.
3. **Compensate, where not coverable.** For traffic that will never traverse the chokepoint, deploy compensating layers (behavioral detection on observable flows, host containment, egress allowlisting) so the bypass does not equate to invisibility.

## Known-hosts DoH/DoT containment strategy

The deterministic core of bypass resistance is a two-part control, standard in enterprise DNS security practice:

### Part 1 — Redirect the encrypted path

Most endpoint DoH clients discover and use a **curated list of well-known public DoH/DoT resolvers**. At the operator's egress firewall:

- Block outbound TCP/853 (DoT) and the IP:443 endpoints of known public DoH providers, except from the managed resolver itself;
- Intercept the bootstrap lookups (`use-application-dns.net` and the well-known DoH provider hostnames) at the managed resolver and answer with an operator-defined policy response (commonly NXDOMAIN to signal "DoH disabled here," the Mozilla standard mechanism);
- Sinkhole nothing else; ordinary 443 traffic is untouched.

The result: the endpoint's encrypted-DNS fallback fails closed back to the system resolver — which is the operator's resolver, where RPZ applies.

### Part 1b — Legacy plaintext DNS closure

Encrypted bypass is only half the problem: an endpoint can equally send plaintext UDP/53 or TCP/53 to any external resolver, sidestepping RPZ with no encryption at all. The egress policy therefore also restricts the DNS transport ports:

- outbound UDP/53 and TCP/53 are permitted only to the managed resolvers and explicitly enumerated authoritative/conditional forwarders;
- the preferred form is **redirect, not reject**: DNAT stray port-53 egress to the managed resolver, preserving function (printers, appliances, and vendor devices with hardcoded public resolvers keep working) while gaining full policy and telemetry visibility;
- where redirect is impractical, block with per-device enumerated exceptions owned through the exception workflow;
- exceptions are governed allowlist entries (owner, ticket, expiry), never permanent firewall lines.

### Baseline resolver requirements

The managed resolver must not become the weak link: recursion restricted to served clients (no open resolver), DNSSEC validation enabled so answers for allowed names cannot be forged, and response-rate limiting so the resolver cannot be abused as a reflection amplifier.

### Part 2 — Detect the remainder

Not all bypass uses known lists (custom DoH URLs, malware-hardcoded resolvers, DNS-over-HTTPS to attacker infrastructure as C2 channel). Detection controls:

- **High-entropy TLS to raw IPs** (no SNI) from client subnets: BD-7 evidence.
- **Known DoH endpoint signatures** (JA4/JA3X of public resolver handshakes) on 443 where not blocked: immediate evidence + optionally block by destination:port class.
- **Volume anomaly on 443** for hosts whose DNS-visible activity does not correlate with their TLS-visible activity (a host moving lots of encrypted bytes while issuing no queries is tunneling something over a path DNS cannot see): BD-5 + BD-1 cross-check.
- **Certificate-transparency or sandbox-free alternatives are NOT required**; all detection uses metadata already at the chokepoint.

### Governance

Part 1 is an operator policy decision (some jurisdictions/tenants will disallow forcing). It is a policy flag (`bypass.enforce_encrypted_dns_redirection`) with its own shadow mode: first **log-only** (count how many flows would be redirected), then enforce. Blocking DoT/DoH endpoints is an egress-filter change and therefore goes through the same staged enforcement as any firewall action, with its own allowlist (legitimate third-party DoH use by specific hosts can be excepted).

## Coverage accounting

APIP maintains a **coverage ledger**: for each protected population segment, the fraction of DNS-bearing sessions observed at the managed resolver versus total egress sessions (from flow metadata). Segments below a coverage floor are:

- flagged on the operator dashboard;
- excluded from "protected population" claims in reporting;
- switched to compensating controls posture (below).

Coverage is a **measured number, not an assumption**. The pilot demonstration must report it.

## Compensating posture for non-coverable paths

Where a population cannot be covered by resolver policy (roaming devices, partner networks, legacy OT segments with hardcoded resolvers):

1. **Behavioral layer applies regardless** — BD-1/BD-5/BD-7 operate on flow metadata at the chokepoint, which encrypted DNS does not hide: the TLS connection to the C2 destination still traverses the firewall, even if DNS never did.
2. **Egress allowlisting (deny-by-default)** — for the most constrained OT/DMZ segments, `docs/25` Layer 3 provides deny-by-default egress where every outbound connection requires prior approval. This is the strongest control in the platform and is explicitly scoped to segments whose function is fixed (ICS historian uplink, vendor VPN termination), never general user populations.
3. **Host containment** — when behavioral evidence identifies a compromised internal host, containment acts on the host's traffic at the chokepoint (scoped quarantine of that host's egress) regardless of which resolver or protocol it uses.

## IPv6 and alternate-transport notes

- IPv6 must be treated as a first-class path: prefix accounting, rule parity, and the coverage ledger must include v6 or the attacker simply uses v6 where no rules exist.
- QUIC/HTTP3 (UDP/443) carries DoH and general C2 alike; the egress policy for constrained segments includes a UDP/443 class control with the same staged rollout and its own shadow mode (log QUIC flows to raw-IP destinations before considering constraints).
- Tor, VPNs, and cloud-flare-style proxies as C2 relays are handled as **shared-infrastructure policy** (`docs/25` §friction ladder): not blocked outright, but subject to challenge/rate-limit layers where policy directs, with the same two-score gating.

## Threat scenarios addressed

| Scenario | Control |
|---|---|
| Malware with hardcoded DoH to public resolver | Known-hosts block + redirect; residual via BD-7 |
| Malware DoH to its own infrastructure | Not a bypass (its C2 destination is indictable directly); BD-1/BD-5 detect |
| User configures browser secure-DNS to public resolver | Bootstrap interception (`use-application-dns.net`) + known-hosts egress block |
| Endpoint uses DoT to public resolver | 853 egress block from all but managed resolver |
| Endpoint/device with hardcoded public resolver (plaintext 53) | Redirect-to-managed (preferred) or block with enumerated governed exceptions |
| Roaming device off-network | Out of chokepoint scope by definition; coverage ledger marks it; host-agent posture (if any) is out of APIP scope |
| Attacker pivots to v6 where rules are sparse | v6 parity requirement + coverage ledger per address family |
| Attacker tunnels C2 over QUIC to raw IP | BD-7 no-SNI detection; constrained-segment UDP/443 class control |

## Non-goals

- No TLS-breaking, MITM interception, or certificate substitution is introduced by this document. APIP remains metadata-only at the chokepoint.
- No attempt to block "all encryption" or degrade normal encrypted traffic. The controls are narrowly scoped to DNS-transport endpoints and specific evidence-backed destinations.

## Release gates

1. DoH/DoT known-hosts list is a signed, versioned feed artifact with its own source profile (it can be poisoned like any feed; treat identically).
2. Bootstrap interception responses pass resolver conformance tests (no resolver breakage for non-DoH traffic).
3. Coverage ledger reporting works in SHADOW before any forcing policy enforces.
4. Forcing policies have tenant-level opt-out with audited reason recording.
5. v6 rule parity is a hard test in CI: every rule class generated for v4 must have a v6 equivalent path or an explicit waiver.
6. Plaintext-53 redirect exceptions are governed entries with expiry; resolver baseline (no open recursion, DNSSEC validation, response-rate limiting) verified at pilot.
