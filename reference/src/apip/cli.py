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
        from .attribution import TransactionRejected
        with open(args.transactions, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("rejected"):
                    continue   # live-capture rejection marker, not a record
                try:
                    store.observe(obj)
                except TransactionRejected as e:
                    raise SystemExit(
                        f"transaction record rejected at {args.transactions}:{lineno}: {e}")
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
    report = store.report()
    (out / "attribution_report.json").write_text(json.dumps(report, indent=2) + "\n")
    from .uireport import render_correlation_report
    (out / "attribution_report.html").write_text(
        render_correlation_report(report), encoding="utf-8")
    print(f"evaluated={len(pairs)} mode={policy.mode} output={out}")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Live-capture subcommand (docs/30): run the loopback challenge origin,
    or convert a terminator access log into contract records."""
    from .live.adapters import apply_stream
    from .live.server import ChallengeOrigin
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    store = CorrelationStore()

    if args.log:
        # log-conversion mode: terminator access log -> contract JSONL + report
        tx_path = out / "transactions.jsonl"
        class _W:
            def __init__(self, fh): self.fh = fh
            def write(self, rec): self.fh.write(json.dumps(rec, sort_keys=True) + "\n")
        with open(args.log, "r", encoding="utf-8", errors="replace") as f, \
                open(tx_path, "w", encoding="utf-8") as o:
            parsed, rejected, unparsed = apply_stream(f, _W(o))
        # fold the captured records into the store
        with open(tx_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    store.observe(json.loads(line))
        print(f"parsed={parsed} rejected={rejected} unparsed={unparsed} output={tx_path}")
    else:
        # serve mode: loopback challenge origin (refuses non-loopback by default)
        tx_path = out / "transactions.jsonl"
        origin = ChallengeOrigin(tx_path, epoch=args.epoch, store=store)
        print(f"challenge origin on http://{args.bind}:{args.port} "
              f"(observe-only; Ctrl+C to stop; records -> {tx_path})")
        try:
            origin.serve(args.bind, args.port)
        except KeyboardInterrupt:
            pass
        finally:
            origin.shutdown()

    report = store.report()
    (out / "attribution_report.json").write_text(json.dumps(report, indent=2) + "\n")
    from .uireport import render_correlation_report
    (out / "attribution_report.html").write_text(
        render_correlation_report(report), encoding="utf-8")
    print(f"tracked={report['tracked_requesters']} degraded={report['degraded']} "
          f"report={out / 'attribution_report.html'}")
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
    cap = sub.add_parser("capture", help="docs/30 harvest: loopback challenge origin or log conversion")
    cap.add_argument("--log", default=None,
                     help="terminator access log to convert (envoy/haproxy/nginx formats)")
    cap.add_argument("--bind", default="127.0.0.1",
                     help="bind address for serve mode (loopback enforced)")
    cap.add_argument("--port", type=int, default=8765)
    cap.add_argument("--epoch", default="0", help="probe-order epoch (docs/29)")
    cap.add_argument("--out", required=True)
    cap.set_defaults(func=cmd_capture)
    args = p.parse_args()
    if getattr(args, "func", None) is cmd_capture and not args.log:
        if not (args.bind.startswith("127.") or args.bind in ("localhost", "::1")):
            p.error("--bind must be loopback (production non-loopback deployment is an "
                    "explicit, reviewed opt-in; see docs/30)")
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
