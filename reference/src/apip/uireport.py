from __future__ import annotations
import json
from .attribution import CorrelationStore

# Operator UI correlation view (docs/30, WP-30): renders the campaign-
# correlation report as a self-contained, read-only HTML page. This is a
# FILE renderer for an offline scaffold — the production UI embeds the same
# structure in docs/22-style screens. Strictly read-only by design: the page
# exposes no action affordances on attribution data, because attribution
# data can never authorize an action.


def render_correlation_report(report: dict, title: str = "Requester Attribution — Campaign Correlation") -> str:
    """Deterministic HTML rendering of a correlation report. Same report in,
    same bytes out — the view is reproducible like every other artifact."""
    groups = report.get("fingerprint_groups", [])
    links = report.get("cross_fingerprint_links", [])
    degraded = report.get("degraded", False)
    by_fp = {g["fingerprint"]: g for g in groups}

    # stable per-group index for link display
    idx = {fp: str(i + 1) for i, fp in enumerate(sorted(by_fp))}

    rows = []
    for fp in sorted(by_fp):
        g = by_fp[fp]
        handles = g["requester_handles"]
        rows.append(f"""
      <tr>
        <td class="fp"><code>{fp}</code><div class="sub">{idx[fp]}</div></td>
        <td>{g["probe_count"]}</td>
        <td>{len(handles)}</td>
        <td class="handles">{"<br/>".join(f"<code>{h}</code>" for h in handles)}</td>
      </tr>""")

    link_rows = []
    for l in sorted(links, key=lambda x: (-x["shared_probes"], x["a"], x["b"])):
        link_rows.append(f"""
      <tr>
        <td>Group {idx[l["a"]]} <code class="dim">{l["a"]}</code></td>
        <td>Group {idx[l["b"]]} <code class="dim">{l["b"]}</code></td>
        <td>{l["shared_probes"]} shared probes</td>
      </tr>""")

    banner = ('<div class="banner">DEGRADED — resource envelope reached; '
              'new requesters are not being tracked (authority unaffected: '
              'attribution has none).</div>' if degraded else "")
    keying = report.get("handle_keying", "unknown")
    if keying == "dev-fallback":
        banner += ('<div class="banner warn">UNKEYED HANDLES — no deployment '
                   'key is configured (APIP_DEPLOYMENT_KEY / '
                   'APIP_DEPLOYMENT_KEY_FILE), so requester handles use a '
                   'development fallback and are invertible by anyone who '
                   'guesses the client address space. Configure a key before '
                   'any real capture.</div>')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; padding: 2rem; font: 14px/1.5 system-ui, sans-serif;
         background: #f6f6f4; color: #1a1a1a; }}
  main {{ max-width: 62rem; margin: 0 auto; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 .25rem; }}
  .meta {{ color: #666; margin-bottom: 1.25rem; }}
  .banner {{ background: #fde8e8; color: #8a1f1f; border: 1px solid #e5b5b5;
            padding: .6rem .9rem; border-radius: 6px; margin-bottom: 1rem; }}
  .banner.warn {{ background: #fdf3e0; color: #7a5215; border-color: #e0c9a0; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem;
           background: #fff; border: 1px solid #ddd; border-radius: 6px; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eee;
            vertical-align: top; }}
  th {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em;
        color: #555; background: #fafafa; }}
  code {{ font-size: .85em; }}
  .fp code {{ font-weight: 600; }}
  .sub {{ color: #999; font-size: .75rem; }}
  .dim {{ color: #888; font-weight: 400; }}
  .handles code {{ color: #444; }}
  .readonly {{ font-size: .75rem; color: #777; border-top: 1px solid #ddd;
               padding-top: .75rem; margin-top: 2rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16181d; color: #e4e4e4; }}
    table {{ background: #1d2026; border-color: #333; }}
    th, td {{ border-color: #2a2e36; }}
    th {{ background: #22262e; color: #aaa; }}
    .banner {{ background: #3a2226; color: #f0b4b4; border-color: #6b3a3a; }}
    .banner.warn {{ background: #33291a; color: #e8c98a; border-color: #6b5a34; }}
    .dim, .sub {{ color: #777; }}
    .handles code {{ color: #bbb; }}
  }}
</style>
</head>
<body>
<main>
  <h1>{title}</h1>
  <p class="meta">{len(groups)} fingerprint group(s) · {report.get("tracked_requesters", 0)} requester(s) tracked
     · schema {report.get("schema_version", "?")} · handle keying: {keying} · display-only</p>
  {banner}
  <table>
    <thead><tr><th>Fingerprint</th><th>Probes</th><th>Requesters</th><th>Handles (pseudonymous)</th></tr></thead>
    <tbody>{"".join(rows) or '<tr><td colspan="4">No fingerprints tracked.</td></tr>'}</tbody>
  </table>
  <table>
    <thead><tr><th>Group A</th><th>Group B</th><th>Correlation</th></tr></thead>
    <tbody>{"".join(link_rows) or '<tr><td colspan="3">No cross-group links at the configured threshold.</td></tr>'}</tbody>
  </table>
  <p class="readonly">Read-only view. Attribution records are non-authoritative
  (docs/30): they contribute nothing to scores, corroboration, rung eligibility,
  or any action. Handles are pseudonymous; raw client identifiers are not shown.</p>
</main>
</body>
</html>
"""


def render_from_store(store: CorrelationStore, min_similarity: int = 3) -> str:
    return render_correlation_report(store.report(min_similarity=min_similarity))
