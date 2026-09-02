from __future__ import annotations
import argparse, json, hashlib
from pathlib import Path
from datetime import datetime, timezone
from .config import load_policy
from .io import load_indicators
from .policy import (evaluate, apply_client_impact_budget, Policy)
from .exporters.rpz import compile_rpz
from .exporters.suricata import compile_rules
from .attribution import CorrelationStore
from .models import Indicator, Evidence
from .sanitize import UnsafeIdentifier, validate_client

# v2.2: the demo client selector is a fixed, validated literal — NOT derived
# from the indicator id. Deriving it (`host-{id.split('--')[-1]}`) made the
# selector a channel for whatever the indicator file contained, which the
# Suricata metadata interpolator then compiled. Client identity is context
# the OPERATOR supplies (or a production pipeline derives from telemetry);
# a batch of indicators has no meaningful per-indicator client anyway.
DEMO_CLIENT = "demo-interactive-client"


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
    # docs/25 L1 client-impact budget: CLI-supplied measurement wins over
    # the policy's [measurement] block (it is the fresher operator input).
    if getattr(args, "transactions_per_hour", None) is not None:
        policy = Policy(**{**policy.__dict__,
                           "measured_interactive_transactions_per_hour":
                               int(args.transactions_per_hour)})
    indicators = list(load_indicators(args.indicators))
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

    # v2.2: optional behavioral detector pass (docs/23 BD-1). A JSONL of
    # contact events (src, dst, ts_iso, epoch_s) feeds the bounded
    # beacon-periodicity detector; emitted detections are folded into the
    # matching indicators as local behavioral evidence BEFORE evaluation —
    # through the same weight table and caps as any other evidence.
    if getattr(args, "events", None):
        from .behavioral import BeaconDetector
        detector = BeaconDetector()
        detections = []
        with open(args.events, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                try:
                    det = detector.observe(str(obj["src"]), str(obj["dst"]),
                                           str(obj["ts_iso"]), int(obj["epoch_s"]))
                except (KeyError, TypeError, ValueError) as e:
                    raise SystemExit(f"event record malformed at {args.events}:{lineno}: {e}")
                if det is not None:
                    detections.append(det)
        folded_count = 0
        if detections:
            indicators, folded_count = _fold_detections(indicators, detections)
        print(f"behavioral pass: detections={len(detections)} "
              f"folded={folded_count} degraded={detector.degraded} "
              f"suppressed_windows={detector.suppressed_new_windows}")

    # docs/04 v2.2: blast-radius budget enforcement. The policy knob
    # (max_new_auto_actions_per_batch) caps how many actions one batch may
    # propose; overflow DEMOTES the remainder to OBSERVE with a named reason
    # rather than silently exceeding the budget (budgets exist so a poisoned
    # feed cannot mass-emit controls in one batch).
    budget = policy.max_new_auto_actions_per_batch
    proposed = 0
    budget_exceeded = False
    challenged_budget_exceeded = False

    pairs = []
    for i in indicators:
        # Typed context for context-acting rungs (docs/25 v2.1): a validated
        # demo client constant; without a client, L1/L2 are unreachable by
        # design (no destination-global forms).
        context = {"client": DEMO_CLIENT, "protocol_class": "interactive_http"}
        d = evaluate(i, policy, context=context)
        if d.to_dict() != evaluate(i, policy, context=context).to_dict():
            raise RuntimeError("nondeterministic decision")  # replay guard
        if budget is not None and d.disposition in {"AUTO_ENFORCE", "SHADOW_ACTION"}:
            if proposed >= budget:
                budget_exceeded = True
                d = d.with_budget_demotion()
            else:
                proposed += 1
        pairs.append((i, d))

    # v2.2 (docs/25 L1 client-impact budget): at most
    # `max_challenged_transaction_fraction_per_hour` of the tenant's
    # measured interactive transactions may be CHALLENGED per hour;
    # exceeding it alarms and auto-reverts the overflow to L0 — exactly the
    # spec's response. The denominator is explicit input: the
    # `--transactions-per-hour` flag (or the policy's [measurement] block —
    # flag wins when both are set). Fail closed: knob set, no measurement
    # -> allowance 0 -> every challenge reverts, and the alarm says why.
    pairs, challenged_budget_exceeded = apply_client_impact_budget(pairs, policy)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "decisions.json").write_text(json.dumps([d.to_dict() for _, d in pairs], indent=2) + "\n")
    rpz = compile_rpz(pairs)
    suri = compile_rules(pairs)
    (out / "rpz.zone").write_text(rpz)
    (out / "suricata.rules").write_text(suri)
    if budget_exceeded:
        print(f"WARNING: blast-radius budget reached ({budget} actions/batch); "
              f"overflow demoted to OBSERVE with reason blast_radius_budget_exceeded")
    if challenged_budget_exceeded:
        # docs/25: exceeding the client-impact budget ALARMS. On a live
        # platform this pages the operator; the scaffold's alarm is the
        # run's stderr-visible warning plus the per-decision reason codes.
        measured = policy.measured_interactive_transactions_per_hour
        frac = policy.max_challenged_transaction_fraction_per_hour
        denom = str(measured) if measured is not None else \
            "UNMEASURED (fail-closed, allowance 0)"
        print(f"ALARM (docs/25): L1 client-impact budget exceeded — "
              f"{frac} of {denom} interactive transactions/hour; "
              f"challenge overflow auto-reverted to L0 "
              f"(reason client_impact_budget_exceeded / challenge_auto_reverted_to_L0)")
    receipts = []
    for _, d in pairs:
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


def _fold_detections(indicators, detections):
    """Fold BD-1 detections into matching indicators as local behavioral
    evidence (docs/23: a detection is a fact, authority stays with the
    weight table). Matching is by destination value; a detection whose
    destination matches no indicator is carried in the run report only.
    Returns (new_indicators, folded_count)."""
    by_value = {}
    for pos, ind in enumerate(indicators):
        by_value.setdefault((ind.type, ind.value), []).append(pos)
    out = list(indicators)
    folded = 0
    for det in detections:
        # a beacon detection is about a (src,dst) pair; the DESTINATION is
        # the contested observable in this data model
        for itype in ("ipv4", "ipv6"):
            positions = by_value.get((itype, det.dst))
            if positions:
                fields = det.as_evidence_fields()
                target = out[positions[0]]
                if len(target.evidence) >= 1024:
                    continue   # ingest envelope: never unbounded
                out[positions[0]] = Indicator(
                    id=target.id, type=target.type, value=target.value,
                    sources=target.sources,
                    evidence=target.evidence + (
                        Evidence(kind=fields["kind"],
                                 source_id=fields["source_id"],
                                 source_class="unassigned",
                                 observed_at=fields["observed_at"],
                                 independent=False,
                                 detail=fields["detail"]),),
                    tags=target.tags)
                folded += 1
                break
    return out, folded


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
    ev.add_argument("--transactions-per-hour", type=int, default=None,
                    help="measured interactive transaction volume (trailing hour) that "
                         "backs the docs/25 L1 client-impact budget fraction; overrides "
                         "the policy [measurement] block when both are set. Required "
                         "for any challenges to survive when the fraction knob is set "
                         "(fail closed when unmeasured).")
    ev.add_argument("--events", default=None,
                    help="optional JSONL of contact events {src,dst,ts_iso,epoch_s} "
                         "for the BD-1 behavioral detector (docs/23)")
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
    try:
        return args.func(args)
    except UnsafeIdentifier as e:
        # ingest boundary: refuse the whole batch with a named reason
        print(f"ERROR: {e}", flush=True)
        return 2
    except (ValueError, OSError) as e:
        print(f"ERROR: {type(e).__name__}: {e}", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
