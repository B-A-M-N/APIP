from __future__ import annotations
import argparse, contextlib, json, os, tempfile
from pathlib import Path
from datetime import datetime, timezone
from .config import load_policy
from .io import load_indicators, _DEMO_TRUSTED_SOURCES
from .policy import (evaluate, apply_client_impact_budget, Policy)
from .exporters.rpz import compile_rpz, compile_rpz_structured
from .exporters.suricata import compile_rules, compile_rules_structured
from .attribution import CorrelationStore
from .models import Indicator, Evidence, CompiledArtifact
from .sanitize import UnsafeIdentifier, validate_client

# v2.2: the demo client selector is a fixed, validated literal — NOT derived
# from the indicator id. Deriving it (`host-{id.split('--')[-1]}`) made the
# selector a channel for whatever the indicator file contained, which the
# Suricata metadata interpolator then compiled. Client identity is context
# the OPERATOR supplies (or a production pipeline derives from telemetry);
# a batch of indicators has no meaningful per-indicator client anyway.
DEMO_CLIENT = "demo-interactive-client"


def _safe_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write an output artifact, REFUSING to write through a symlink
    (adversarial-audit fix). Path::write_text / open('w') follow symlinks, so a
    pre-placed symlink at a fixed artifact path (`decisions.json`,
    `suricata.rules`, ...) pointing anywhere on disk would let one run
    overwrite an arbitrary file the operator never meant to touch. Fail closed:
    if `path` is already a symlink we raise before any byte is written, naming
    the offender. The write itself goes to a `mkstemp` file in the same
    directory (O_EXCL — cannot follow a pre-placed symlink at a guessable name)
    then `os.replace` swaps it in, so a concurrent attacker racing the open
    with their own symlink can never redirect our bytes into a target file.
    """
    if path.is_symlink():
        raise SystemExit(f"refusing to write through symlink: {path}")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def _safe_writer(path: Path, *, encoding: str = "utf-8"):
    """Context manager handing back a text writer whose content lands in an
    exclusive `mkstemp` file (never through a symlink) and is moved into place
    only on clean exit (adversarial-audit fix, same class as `_safe_write_text`
    but for streaming/structured writes like transactions.jsonl). A pre-placed
    symlink at `path` is refused up front with a named error."""
    if path.is_symlink():
        raise SystemExit(f"refusing to write through symlink: {path}")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    commit = False
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        commit = True
    finally:
        if not commit:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def _receipt(art: CompiledArtifact) -> dict:
    """Build a receipt for ONE successfully compiled artifact (audit P1-26).

    Receipts are generated EXCLUSIVELY from structured compilation results —
    never by inspecting `Decision.action`. A decision that produced no
    CompiledArtifact gets no receipt, because there is no artifact to attest.

    audit P1-27: the receipt carries BOTH the decision-specific fragment
    identity (rule id + fragment hash) and the whole-bundle identity (bundle
    id + bundle hash), so later verify/revoke/reconcile can target exactly
    this rule without disturbing the rest of the bundle.
    """
    return {
        "id": f"receipt--{art.decision_id.split('--')[-1]}-{art.adapter}",
        "decision_id": art.decision_id,
        "adapter": art.adapter,
        "rule_id": art.rule_id,
        "status": art.status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device_revision": None,
        "bundle_id": art.bundle_id,
        "bundle_hash": art.bundle_hash,
        "fragment_hash": art.fragment_hash,
        "monitoring_only": art.monitoring_only,
        "message": "Dry-run artifact only; no live enforcement performed."
    }


def cmd_evaluate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    # docs/25 L1 client-impact budget: CLI-supplied measurement wins over
    # the policy's [measurement] block (it is the fresher operator input).
    if getattr(args, "transactions_per_hour", None) is not None:
        # v2.3 (audit P0-6): the CLI override bypasses load_policy's config
        # validation — a negative value used to overload the -1 "unconfigured"
        # sentinel and silently DISABLE the budget. Reject it here exactly as
        # the config loader does (non-negative integer measurement). Sketchy
        # values fail the batch loudly, never grant a budget bypass.
        tph = int(args.transactions_per_hour)
        if tph < 0:
            raise ValueError(
                "--transactions-per-hour must be a non-negative integer "
                "(a negative value previously disabled the L1 client-impact budget)")
        policy = Policy(**{**policy.__dict__,
                           "measured_interactive_transactions_per_hour": tph})
    # v2.3 (audit P0-2): source identity is bound to the ingest channel.
    # The normal path is FAIL-CLOSED — no payload source_id is granted
    # authority. `--demo-trust-fixture` certifies the reference scaffold's
    # synthetic feeds so the offline demo can run; `--trusted-source` lets an
    # operator certify their own channel's provenance set. Without either,
    # every evidence record resolves to unregistered (zero authority).
    trusted = None
    if getattr(args, "demo_trust_fixture", False):
        trusted = frozenset(_DEMO_TRUSTED_SOURCES)
    elif getattr(args, "trusted_source", None):
        trusted = frozenset(args.trusted_source)
    indicators = list(load_indicators(args.indicators, trusted_sources=trusted))
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
                # v2.3 (adversarial-audit fix): a `--transactions` line is
                # UNTRUSTED input. A non-object value (list, string, number,
                # null) previously crashed the whole batch with an AttributeError
                # on `.get` — reject it loudly as a malformed line instead.
                if not isinstance(obj, dict):
                    raise SystemExit(
                        f"transaction record malformed at {args.transactions}:{lineno}: "
                        f"expected a JSON object, got {json.dumps(obj)[:80]!r}")
                if obj.get("rejected"):
                    continue   # live-capture rejection marker, not a record
                try:
                    # v2.3 (adversarial-audit fix, P1-14 lineage): the records
                    # folded here are LIVE-CAPTURED observed transactions whose
                    # `client_ref` is ALREADY the pseudonymous requester handle
                    # (the live boundary HMACs once at capture). Feeding them to
                    # `observe` would HMAC the handle a SECOND time, so
                    # `attribution_refs_for(raw)` on real captures would miss —
                    # live and offline ingestion must derive ONE identity.
                    store.observe_pseudonymous_handle(obj)
                except TransactionRejected as e:
                    raise SystemExit(
                        f"transaction record rejected at {args.transactions}:{lineno}: {e}")

    # v2.2: optional behavioral detector pass (docs/23). A JSONL of contact
    # events (src, dst, ts_iso, epoch_s) feeds the bounded behavioral
    # detectors gated by the policy's [behavioral] enabled_families; emitted
    # detections are folded into the matching indicators as local behavioral
    # evidence BEFORE evaluation — through the same weight table and caps as
    # any other evidence. audit P1-20: only families actually IMPLEMENTED
    # detect; requested-but-pending families are reported honestly, never
    # implied present.
    if getattr(args, "events", None):
        from .behavioral import (BeaconDetector, FirstSeenNoveltyDetector,
                                 IMPLEMENTED_FAMILIES)
        fams = policy.enabled_behavioral_families or tuple(sorted(IMPLEMENTED_FAMILIES))
        beacons = BeaconDetector(enabled_families=fams)
        novelty = FirstSeenNoveltyDetector()
        detectors = []
        if beacons.beacon_enabled:
            detectors.append(("beacon", beacons))
        if "first_seen_novelty" in beacons.enabled_families:
            detectors.append(("novelty", novelty))
        pending = list(beacons.pending_families)
        if pending:
            print("behavioral pass: requested families NOT implemented "
                  f"(pending, no detection): {', '.join(pending)}")
        detections = []
        with open(args.events, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                try:
                    src, dst, ts_iso, epoch_s = (str(obj["src"]), str(obj["dst"]),
                                                 str(obj["ts_iso"]), int(obj["epoch_s"]))
                    for _name, detector in detectors:
                        det = detector.observe(src, dst, ts_iso, epoch_s)
                        if det is not None:
                            detections.append(det)
                except (KeyError, TypeError, ValueError) as e:
                    raise SystemExit(f"event record malformed at {args.events}:{lineno}: {e}")
        folded_count = 0
        if detections:
            indicators, folded_count = _fold_detections(indicators, detections)
        print(f"behavioral pass: detectors={[n for n, _ in detectors]} "
              f"detections={len(detections)} folded={folded_count} "
              f"beacon_degraded={beacons.degraded} "
              f"novelty_degraded={novelty.degraded} "
              f"novelty_seen={novelty.tracked_destinations}")

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
    from .sanitize import validate_client
    for i in indicators:
        # Typed context for context-acting rungs (docs/25 v2.1): without a
        # validated client selector, L1/L2 are unreachable by design (no
        # destination-global forms).
        #
        # audit P1-24: behavioral detections carry the ACTUAL subject (the
        # host that made contact) as evidence context. When an indicator is
        # firmed entirely by one client's detection(s), that real client is
        # the decision context — a "host-A -> destination-X" detection must
        # NOT be relabelled as "demo-interactive-client -> destination-X".
        # DEMO_CLIENT remains the operator-supplied context only when no
        # genuine subject exists.
        subject = _detection_subject(i)
        client_for_run = (
            validate_client(subject) if subject is not None else DEMO_CLIENT)
        context = {"client": client_for_run, "protocol_class": "interactive_http"}
        d = evaluate(i, policy, context=context)
        if d.to_dict() != evaluate(i, policy, context=context).to_dict():
            raise RuntimeError("nondeterministic decision")  # replay guard
        if budget is not None and d.disposition in {"AUTO_ENFORCE", "SHADOW_ACTION"}:
            if proposed >= budget:
                budget_exceeded = True
                # `with_budget_demotion` now produces a self-consistent OBSERVE
                # (no stale TTL draw; content_hash over the demoted fields).
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
    _safe_write_text(out / "decisions.json",
                     json.dumps([d.to_dict() for _, d in pairs], indent=2) + "\n")
    # v2.3 (audit P1-26/P1-27): compilation produces STRUCTURED artifacts —
    # one CompiledArtifact per decision that actually rendered a rule/zone
    # line. The string outputs below are thin concatenations of those
    # artifacts; receipts are generated from the SAME structured results so a
    # decision that produced no artifact also produces no receipt.
    rpz_arts = compile_rpz_structured(pairs)
    suri_arts = compile_rules_structured(pairs)
    _safe_write_text(out / "rpz.zone", compile_rpz(pairs))
    _safe_write_text(out / "suricata.rules", compile_rules(pairs))
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
    # audit P1-26: receipts exist ONLY for decisions that actually compiled an
    # artifact. Walking the structured artifacts (not Decision.action) means
    # an action with no adapter representation — e.g. proxy_challenge, which
    # no exporter implements as a dry-run artifact — yields NO receipt,
    # rather than a fabricated attestation of a nonexistent control.
    receipts = [_receipt(a) for a in (rpz_arts + suri_arts)]
    _safe_write_text(out / "receipts.json",
                     json.dumps(receipts, indent=2) + "\n")
    # docs/30: campaign-correlation report (the analyst view, file form).
    # Display-only: feeding it back into anything enforcement-side is
    # prohibited and blocked by the attribution source-class gate.
    report = store.report()
    _safe_write_text(out / "attribution_report.json",
                     json.dumps(report, indent=2) + "\n")
    from .uireport import render_correlation_report
    _safe_write_text(out / "attribution_report.html",
                     render_correlation_report(report), encoding="utf-8")
    print(f"evaluated={len(pairs)} mode={policy.mode} output={out}")
    return 0


def _detection_subject(indicator) -> str | None:
    """audit P1-24: the genuine subject behind behavioral evidence.

    Returns the distinct client/host the indicator's behavioral detections
    are actually ABOUT, when every behavioral evidence record names ONE and
    the same subject — and None otherwise (no behavioral subject, or several
    different clients whose detections would conflate). A single unambiguous
    subject is used as the decision context; mixed subjects fall back to the
    operator-supplied context because combining them would fabricate a client.
    """
    BEH = {"behavioral_beacon_periodicity", "behavioral_first_seen_novelty"}
    subjects = set()
    for ev in getattr(indicator, "evidence", ()):
        if ev.kind not in BEH:
            continue
        client = (ev.detail or {}).get("client")
        if isinstance(client, str) and client:
            subjects.add(client)
    if len(subjects) != 1:
        return None
    return next(iter(subjects))


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
                _safe_writer(tx_path) as o:
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
    _safe_write_text(out / "attribution_report.json",
                     json.dumps(report, indent=2) + "\n")
    from .uireport import render_correlation_report
    _safe_write_text(out / "attribution_report.html",
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
    ev.add_argument("--demo-trust-fixture", action="store_true",
                    help="v2.3 (P0-2): certify the reference scaffold's synthetic "
                         "feed ids (curated-a/b, local-sensor/behavioral) as the "
                         "ingest channel's trusted sources. Explicit, reviewed "
                         "opt-in for the offline demo; the normal evaluate path is "
                         "fail-closed (no payload source_id is granted authority).")
    ev.add_argument("--trusted-source", action="append", default=None,
                    help="v2.3 (P0-2): a source id this channel certifies. Repeat "
                         "to list several. Evidence naming any OTHER source_id is "
                         "demoted to unregistered (zero authority) at the boundary.")
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
