"""Live capture components (docs/30 WP-30): challenge origin + log adapters.

Safety invariants under test:
  - the challenge origin refuses non-loopback binds by default;
  - observation records carry pseudonymous handles, never raw addresses;
  - the writer is bounded with deterministic stop-and-mark degradation;
  - contract-violating observations are dropped, never coerced;
  - adapters normalize all supported terminator formats to contract-valid
    records, and garbage input is counted-and-dropped, never guessed;
  - nothing in the live package performs enforcement (structural check).
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from apip.attribution import CorrelationStore, TransactionRejected, handle_for
from apip.live.adapters import apply_stream, recognize
from apip.live.server import ChallengeOrigin, _key_order, _TxWriter


class LoopbackRefusalTests(unittest.TestCase):
    def test_non_loopback_bind_refused_by_default(self):
        o = ChallengeOrigin(Path("/tmp/tx.jsonl"))
        with self.assertRaises(ValueError):
            o.serve("0.0.0.0", 8765)
        self.assertIsNone(o._server)   # never started

    def test_serve_forever_nonloopback_requires_opt_in_flag(self):
        o = ChallengeOrigin(Path("/tmp/tx.jsonl"))
        with self.assertRaises(ValueError):
            o.serve_forever("10.0.0.5", 8765)   # no allow_nonloopback

    def test_loopback_bind_allowed(self):
        o = ChallengeOrigin(Path("/tmp/tx.jsonl"))
        o.serve("127.0.0.1", 0) is None if False else None
        # serve() would block; instead assert the guard passes by calling
        # the guard logic path only
        from apip.live.server import _is_loopback
        self.assertTrue(_is_loopback("127.0.0.1"))
        self.assertTrue(_is_loopback("localhost"))
        self.assertFalse(_is_loopback("0.0.0.0"))


class HandlerObservationTests(unittest.TestCase):
    """Drive the handler logic without sockets via the handler class."""

    @staticmethod
    def _handler_instance(path="/", headers=None, client=("203.0.113.9", 443)):
        origin = ChallengeOrigin(Path("/tmp/tx-unused.jsonl"))
        hs = origin._make_handler()
        h = hs.__new__(hs)
        h.client_address = client
        h.path = path
        import email.message
        raw = "\r\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        msg = email.message.Message()
        for k, v in (headers or {}).items():
            msg[k] = v
        h.headers = msg
        h.rfile = None
        h.wfile = type("W", (), {"write": staticmethod(lambda b: None)})()
        return origin, h

    def test_record_common_captures_header_order(self):
        origin, h = HandlerObservationTests._handler_instance(
            headers={"Host": "x", "User-Agent": "y", "Accept": "z"})
        rec = h._record_common()
        self.assertEqual(rec["header_order"], ["host", "user-agent", "accept"])
        self.assertEqual(rec["client_ref"], "203.0.113.9")   # raw pre-pseudonymization

    def test_session_pseudonymizes_before_retention(self):
        origin, h = HandlerObservationTests._handler_instance(
            client=("198.51.100.7", 8443))
        handle, n = h._session_for()
        self.assertEqual(handle, handle_for("198.51.100.7"))
        self.assertEqual(n, 0)
        # raw address never lands in the sessions map (keys are handles)
        self.assertIn(handle, origin._sessions)
        self.assertNotIn("198.51.100.7", origin._sessions)

    def test_emit_drops_contract_violations(self):
        with TemporaryDirectory() as td:
            p = Path(td) / "tx.jsonl"
            origin = ChallengeOrigin(p)
            origin.emit({"client_ref": "c", "observed_at": "not-a-date"})
            origin.emit({"client_ref": "c", "observed_at": "2026-09-01T19:00:00Z",
                         "header_order": ["host"]})
            lines = p.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)            # rejection marker + good record
            self.assertIn("rejected", json.loads(lines[0]))
            self.assertEqual(json.loads(lines[1])["header_order"], ["host"])

    def test_emit_folds_into_store(self):
        with TemporaryDirectory() as td:
            store = CorrelationStore()
            origin = ChallengeOrigin(Path(td) / "tx.jsonl", store=store)
            origin.emit({"client_ref": "c", "observed_at": "2026-09-01T19:00:00Z",
                         "header_order": ["host", "accept"],
                         "tls_ja4": "t13d1516h2_8daaf6152771_b186095e22b6"})
            self.assertEqual(store.report()["tracked_requesters"], 1)


class BoundedWriterTests(unittest.TestCase):
    def test_stop_and_mark_at_max(self):
        with TemporaryDirectory() as td:
            p = Path(td) / "tx.jsonl"
            w = _TxWriter(p, max_records=3)
            for i in range(5):
                w.write({"client_ref": f"c{i}", "observed_at": "2026-09-01T19:00:00Z"})
            w.close()
            lines = p.read_text().strip().split("\n")
            self.assertEqual(len(lines), 3)     # hard cap
            self.assertTrue(w.degraded)


class AdapterStreamTests(unittest.TestCase):
    ENVOY = ('[2026-09-01T19:00:00Z] "GET /asset HTTP/1.1" 203.0.113.9 '
             'accept-language=en-US accept-encoding=gzip ja4=t13d1516h2_abc')
    HAPROXY = ('Jan  1 19:00:00 host haproxy[123]: 198.51.100.7:4480 '
               '[03/Jan/2026:19:00:00.001] h=accept-language:en-GB h=accept-encoding:br')
    NGINX = ('{"time":"2026-09-01T19:00:00Z","remote_addr":"192.0.2.50",'
             '"http_accept_language":"*","http_accept_encoding":"identity",'
             '"header_order":"host|user-agent|accept"}')

    def test_all_formats_produce_contract_valid_records(self):
        from apip.attribution import validate_transaction
        for line in (self.ENVOY, self.HAPROXY, self.NGINX):
            rec = recognize(line)
            self.assertIsNotNone(rec, line)
            validate_transaction(rec)       # must not raise

    def test_haproxy_timestamp_normalized(self):
        rec = recognize(self.HAPROXY)
        self.assertEqual(rec["observed_at"], "2026-01-03T19:00:00Z")

    def test_nginx_header_order_maps_to_p1(self):
        rec = recognize(self.NGINX)
        self.assertEqual(rec["header_order"], ["host", "user-agent", "accept"])

    def test_garbage_counted_not_guessed(self):
        class Sink:
            rows = []
            def write(self, r): self.rows.append(r)
        sink = Sink()
        parsed, rejected, unparsed = apply_stream(
            [self.ENVOY, "garbage", "", self.NGINX], sink)
        self.assertEqual((parsed, rejected, unparsed), (2, 0, 1))
        self.assertEqual(len(sink.rows), 2)

    def test_same_behavior_across_formats_correlates(self):
        """The point of the adapters: the same client behavior logged by two
        different terminators lands in ONE fingerprint group."""
        envoy_a = ('[2026-09-01T19:00:00Z] "GET /a HTTP/1.1" 203.0.113.9 '
                   'accept-language=en-US accept-encoding=gzip,br '
                   'ja4=t13d1516h2_8daaf6152771_b186095e22b6')
        # same behaviors, different terminator: NGINX JSON with header order
        nginx_a = ('{"time":"2026-09-01T19:01:00Z","remote_addr":"198.51.100.7",'
                   '"http_accept_language":"en-US","http_accept_encoding":"gzip,br",'
                   '"ja4":"t13d1516h2_8daaf6152771_b186095e22b6",'
                   '"header_order":"host|user-agent|accept"}')
        # a third client with different behavior must NOT join the group
        envoy_b = ('[2026-09-01T19:02:00Z] "GET /a HTTP/1.1" 192.0.2.50 '
                   'accept-language=* accept-encoding=identity '
                   'ja4=t13d1513h2_5c54147bee53_e5647b281b39')
        s = CorrelationStore()
        s.observe(recognize(envoy_a))
        s.observe(recognize(nginx_a))
        s.observe(recognize(envoy_b))
        rep = s.report()
        # vectors differ (NGINX saw header order, Envoy did not), so exact
        # groups stay separate — but the containment link must connect the
        # same-behavior pair and must NOT reach the dissimilar client.
        links = rep["cross_fingerprint_links"]
        self.assertEqual(len(links), 1, rep)
        self.assertEqual(links[0]["shared_probes"], 2)
        # the dissimilar client's group participates in NO link
        fp_c = handle_group_fp = None
        fps_c = {g_["fingerprint"] for g_ in rep["fingerprint_groups"]
                 if g_["probe_count"] == 2 and g_["requester_handles"] == [__import__("apip.attribution", fromlist=["handle_for"]).handle_for("192.0.2.50")]}
        self.assertTrue(fps_c)
        self.assertNotIn(fps_c.pop(), {links[0]["a"], links[0]["b"]})


class KeyOrderTests(unittest.TestCase):
    def test_key_order_extracted_in_serialization_order(self):
        self.assertEqual(_key_order(b'{"nonce": 1, "ts": 2, "response": 3}'),
                         ["nonce", "ts", "response"])

    def test_values_ignored_and_strings_in_values_not_keys(self):
        self.assertEqual(_key_order(b'{"a": "x:y", "b": 2}'), ["a", "b"])

    def test_non_json_yields_empty(self):
        self.assertEqual(_key_order(b'not json'), [])


class NoEnforcementStructuralTest(unittest.TestCase):
    """The live package observes and logs; it must contain no enforcement
    vocabulary. (Enforcement lives solely in the offline decision core.)"""

    def test_no_enforcement_symbols_in_live_package(self):
        import ast
        live = Path(__file__).resolve().parent.parent / "src" / "apip" / "live"
        banned = {"firewall", "deny", "block", "rpz", "nxdomain",
                  "rate_limit", "challenge_fail", "quarantine"}
        for p in live.rglob("*.py"):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id.lower() in banned:
                    self.fail(f"enforcement symbol '{node.id}' in live/{p.name}:{node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr.lower() in banned:
                    self.fail(f"enforcement attribute '{node.attr}' in live/{p.name}:{node.lineno}")


if __name__ == "__main__":
    unittest.main()
