from __future__ import annotations
import argparse, json, hashlib
from pathlib import Path
from datetime import datetime, timezone
from .config import load_policy
from .io import load_indicators
from .policy import evaluate
from .exporters.rpz import compile_rpz
from .exporters.suricata import compile_rules
from .attribution import CorrelationStore, ATTRIBUTION_SOURCE_CLASS


def _receipt(decision_id: str, adapter: str, artifact: str) -> dict:
    h = hashlib.sha256(artifact.encode()).hexdigest()
    return {
        "id": f"receipt--{decision_id.split('--')[-1]}-{adapter}",
        "decision_id": decision_id,
        "adapter": adapter,
        "status": "dry_run",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device_revision": None,
        "artifact_hash": h,
        "message": "Dry-run artifact only; no live enforcement performed."
    }


def cmd_evaluate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    indicators = load_indicators(args.indicators)
    # docs/30 collection channel (offline form): fold any observed-transaction
    # log into the correlation store so decisions can carry display-only
    # attribution refs. Absent log -> no refs, decisions unchanged.
    store = CorrelationStore()
    if getattr(args, "transactions", None):
        with open(args.transactions, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    store.observe(json.loads(line))
    pairs = []
    for i in indicators:
        # Typed context for context-acting rungs (docs/25 v2.1). The demo
        # carries a representative interactive-HTTP client context; without
        # it, L1/L2 are unreachable by design (no destination-global forms).
        client = f"host-{i.id.split('--')[-1]}"
        context = {"client": client, "protocol_class": "interactive_http"}
        d = evaluate(i, policy, context=context)
        if d.to_dict() != evaluate(i, policy, context=context).to_dict():
            raise RuntimeError("nondeterministic decision")  # replay guard
        pairs.append((i, d, client))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "decisions.json").write_text(json.dumps([d.to_dict() for _, d, _ in pairs], indent=2) + "\n")
    rpz = compile_rpz([(i, d) for i, d, _ in pairs])
    suri = compile_rules([(i, d) for i, d, _ in pairs])
    (out / "rpz.zone").write_text(rpz)
    (out / "suricata.rules").write_text(suri)
    receipts = []
    for _, d, _ in pairs:
        if d.action == "dns_nxdomain":
            receipts.append(_receipt(d.id, "rpz-file-exporter", rpz))
        elif d.action in {"firewall_deny", "rate_limit"}:
            receipts.append(_receipt(d.id, "suricata-file-exporter", suri))
        elif d.action == "proxy_challenge":
            receipts.append(_receipt(d.id, "proxy-file-exporter", f"challenge:{d.indicator_id}"))
    (out / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
    # docs/30: campaign-correlation report (the analyst view, file form).
    # Display-only: feeding it back into anything enforcement-side is
    # prohibited and blocked by the attribution source-class gate.
    (out / "attribution_report.json").write_text(
        json.dumps(store.report(), indent=2) + "\n")
    print(f"evaluated={len(pairs)} mode={policy.mode} output={out}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="APIP dry-run reference scaffold")
    sub = p.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("evaluate", help="evaluate indicators and emit dry-run artifacts")
    ev.add_argument("indicators")
    ev.add_argument("--policy", required=True)
    ev.add_argument("--out", required=True)
    ev.add_argument("--transactions", default=None,
                    help="optional JSONL of observed transactions (docs/30 harvest)")
    ev.set_defaults(func=cmd_evaluate)
    args = p.parse_args()
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
