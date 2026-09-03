# APIP Reference Scaffold

This is a deliberately limited, offline demonstrator of the APIP decision boundary. **It contains no AI/ML/LLM components** (`docs/28`): every computation is deterministic and replayable.

It can:
- load synthetic JSON indicators (feed-style and behavioral evidence);
- canonicalize FQDN/IP/CIDR values;
- calculate deterministic maliciousness and two-variant action-safety scores (S_ctx for context-acting rungs, S_ip for identity-acting rungs, `docs/25`);
- apply the behavioral corroboration lattice via contribution caps (`docs/23`);
- select interdiction ladder rungs L0–L5 with shared-infrastructure demotion and reason codes (`docs/25`);
- apply seeded TTL randomization with recorded draws for exact replay (`docs/29`);
- apply a small reference policy;
- harvest requester-attribution features from an offline JSONL of observed transactions (`docs/30`: behavioral extraction, bounded correlation store, campaign-correlation report — display-only, never an enforcement input);
- emit dry-run DNS RPZ and Suricata rule files;
- create dry-run action receipts.

It cannot:
- fetch the internet;
- make any outbound network connection;
- perform actuator mutations (firewall/DNS/router changes, BGP, scanning, third-party modification);
- connect to TAXII;
- terminate production HTTP/TLS;
- invoke any model inference (none exists in the codebase).

On the loopback-only exception: `apip.cli capture serve` and the attribution lab
(`lab/`) open a **loopback-only HTTP observation socket** (`ChallengeOrigin`,
bind enforced to 127.0.0.1/::1, `docs/30`) to harvest behavioral fingerprints from
local synthetic HTTP. That is an inbound loopback test channel — not outbound
network and not an actuator. Evaluation and enforcement compilation are
**offline/dry-run**: the reference makes no outbound connections and performs no
actuator mutations. Attribution harvest otherwise works from an already-captured
JSONL of transaction logs, never live traffic.

## Run

```bash
python -m unittest discover -s tests -v
python -m apip.cli evaluate ../examples/indicators.json --policy ../examples/policy.toml --out ../examples/generated \
  --transactions ../examples/transactions.jsonl
```

If running from the source checkout without installation:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m apip.cli evaluate ../examples/indicators.json --policy ../examples/policy.toml --out ../examples/generated \
  --transactions ../examples/transactions.jsonl
```

## Test coverage map

| Test file | Covers |
|---|---|
| `test_scoring.py` | two-variant safety scoring; shared-infra penalty routing to identity safety |
| `test_policy.py` | ladder selection; shared-infra L5 demotion; behavioral corroboration caps; wildcard/prefix hard rules; AI-evidence invariance |
| `test_randomize.py` | seeded DRBG replay determinism; bounds enforcement; decision-level draw recording |
| `test_no_ai_conformance.py` | docs/28 CI gate: dependency allowlist, AI-package ban, inference-call scan, offline execution |
| `test_config_validation.py` | policy semantic validation (floor monotonicity, hard invariants) |
| `test_schema_consistency.py` | behavioral family enum parity across schemas/API/weights |
| `test_attribution.py` | docs/30: behavioral extraction, bounded correlation, byte-identity of decisions with/without attribution |

## Safety properties demonstrated

- a single behavioral family, however strong, can never reach any action rung (cap below floors);
- corroborated behavioral evidence reaches rate-limit but not deny floors without external corroboration;
- shared-infrastructure indicators lose L5 (IP deny) but retain L4 (domain block) and context rungs;
- every randomized TTL draw is within policy bounds and reproducible from its recorded seed.
