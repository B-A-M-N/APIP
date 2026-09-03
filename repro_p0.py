import json, pathlib, tomllib
from apip.io import load_indicators
from apip.config import load_policy
from apip.policy import evaluate

BASE = pathlib.Path("examples")

# ENFORCE policy (fresh eval, no replay pin), mirroring the shipped example floors.
ENFORCE_TOML = '''
policy_version = "2026-09-01.2"
mode = "ENFORCE"
scope = "example-tenant"

[thresholds]
observe_m = 40
fqdn_auto_m = 95
fqdn_auto_s = 90
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95

[thresholds.rungs.L1]
m = 85
s = 75
[thresholds.rungs.L2]
m = 90
s = 80
[thresholds.rungs.L4]
m = 95
s = 90
[thresholds.rungs.L5]
m = 98
s = 95

[limits]
max_auto_ttl_seconds = 3600
max_new_auto_actions_per_batch = 100
max_challenged_transaction_fraction_per_hour = 0.05
nominal_rate_ceiling_per_min = 240
max_evidence_per_indicator = 64

[authorization]
authorized_prefixes = ["198.51.100.0/24", "203.0.113.0/24"]

[behavioral.corroboration]
distinct_families_for_rate_limit = 2
distinct_families_for_deny = 3

[behavioral]
max_behavioral_m_contribution = 60

[freshness]
max_age_hours = 6.0

[replay]
reference_now = "2026-09-02T18:42:00Z"
'''
pathlib.Path("/tmp/enforce_policy.toml").write_text(ENFORCE_TOML)
policy = load_policy("/tmp/enforce_policy.toml")

def run(label, evid):
    payload = [{
        "id": label, "type": "ipv4", "value": "198.51.100.55",
        "sources": sorted({e["source_id"] for e in evid}),
        "evidence": evid,
    }]
    p = pathlib.Path(f"/tmp/{label}.json"); p.write_text(json.dumps(payload))
    ind = load_indicators(str(p))[0]
    d = evaluate(ind, policy, context={"client": "demo-interactive-client",
                                       "protocol_class": "interactive_http"})
    print(f"{label}: M={d.maliciousness} S_ctx={d.action_safety} "
          f"rung={d.rung} action={d.action} disposition={d.disposition} id={d.id}")
    return d

T = "2026-09-02T18:40:00Z"  # fresh relative to pinned reference_now below
from apip.policy import _decision_bearing_evidence

# P0-4: annotation/attribution/unregistered must not perturb the decision,
# even through the evidence cap. All-decision-bearing reference vs. that
# same set wrapped in arbitrary annotation noise.
import copy
base_ev = [  # decision-bearing: enough for a real rung
    {"kind": "curated_source", "source_id": "curated-a", "observed_at": T},
    {"kind": "curated_source", "source_id": "curated-b", "observed_at": T},
    {"kind": "direct_local_detection", "source_id": "local-sensor", "observed_at": T},
    {"kind": "exact_ip", "source_id": "local-sensor", "observed_at": T},
    {"kind": "dedicated_use", "source_id": "local-sensor", "observed_at": T},
    {"kind": "recent", "source_id": "local-sensor", "observed_at": T},
    {"kind": "verified_rollback", "source_id": "local-sensor", "observed_at": T},
]

def evset(label, evid):
    payload = [{"id": label.replace("+", "_").replace(" ", "_"),
                "type": "ipv4", "value": "198.51.100.60",
                "sources": sorted({e["source_id"] for e in evid}),
                "evidence": evid}]
    p = pathlib.Path(f"/tmp/{label}.json"); p.write_text(json.dumps(payload))
    return load_indicators(str(p))[0]

noise = [
    {"kind": k, "source_id": s, "observed_at": T}
    for k in ["curated_source", "recent", "exact_ip", "bounded_scope",
              "verified_rollback", "dedicated_use", "exactness"]
    for s in ["ai-note", "anon-attrib", "evil-unregistered", "weird-1"]
]
# prepend / append / interleave scenarios via different orderings
from itertools import cycle
scenarios = {
    "base": base_ev,
    "base+noise_prepend": noise + base_ev,
    "base+noise_append": base_ev + noise,
    "base+noise_interleave": [x for pair in zip(noise, base_ev) for x in pair] + noise,
}
base_d = evaluate(evset("p0-4-base", base_ev), policy, context={"client": "demo-interactive-client", "protocol_class": "interactive_http"})
for name, evid in scenarios.items():
    dd = evaluate(evset(f"p0-4-{name}", evid), policy, context={"client": "demo-interactive-client", "protocol_class": "interactive_http"})
    print(f"p0-4 {name:26s} == base? {base_d.to_dict() == dd.to_dict()} "
          f"M={dd.maliciousness} S={dd.action_safety} rung={dd.rung}")
# P0-1: all evidence from an unregistered source, exercise "any" fallback kinds
run("p0-1-unregistered", [
    {"kind": "curated_source", "source_id": "evil-unregistered", "observed_at": T},
    {"kind": "recent",         "source_id": "evil-unregistered", "observed_at": T},
    {"kind": "dedicated_use",  "source_id": "evil-unregistered", "observed_at": T},
])
# control: same evidence from a real registered curated source
run("control-curated", [
    {"kind": "curated_source", "source_id": "curated-a", "observed_at": T},
    {"kind": "recent",         "source_id": "curated-a", "observed_at": T},
    {"kind": "dedicated_use",  "source_id": "curated-a", "observed_at": T},
])
# P0-2: impersonate default sources
run("p0-2-impersonate", [
    {"kind": "curated_source", "source_id": "curated-a", "observed_at": T},
    {"kind": "recent",         "source_id": "curated-b", "observed_at": T},
    {"kind": "dedicated_use",  "source_id": "curated-a", "observed_at": T},
])
print()
print("P0-5 monotonicity check:")
from apip.config import validate_policy
# L1 strong, L2 radically-weaker S: tuple compare is lexicographic so passes
mono = {
    "policy_version": "t", "mode": "SHADOW", "scope": "x",
    "safety": {"allowlist_precedence": True},
    "thresholds": {"rungs": {"L1": {"m": 85, "s": 90}, "L2": {"m": 90, "s": 1}}},
    "limits": {"nominal_rate_ceiling_per_min": 240},
}
print("M=85/S=90 then M=90/S=1 problems:", validate_policy(mono))

print("P0-6 negative CLI measurement:")
from apip.policy import Policy, challenge_allowance
pol = Policy(version="t", mode="SHADOW", scope="x",
             observe_m=0, fqdn_auto_m=0, fqdn_auto_s=0, ip_rate_m=0, ip_rate_s=0,
             ip_deny_m=0, ip_deny_s=0, max_auto_ttl_seconds=0,
             auto_prefix_deny=False, auto_routing=False, auto_wildcard_domain=False,
             max_challenged_transaction_fraction_per_hour=0.05,
             measured_interactive_transactions_per_hour=-1)
print("allowance with measured=-1:", challenge_allowance(pol))