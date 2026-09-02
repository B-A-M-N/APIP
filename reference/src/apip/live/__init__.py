"""Live capture components (docs/30, WP-30).

Network-facing but strictly bounded: a loopback-default challenge origin
that observes requester behavior and emits observed-transaction records,
and terminator log adapters that convert production access logs into the
same records. These components observe and log ONLY — they perform no
enforcement, hold no enforcement state, and make no outbound calls. The
offline decision core (scoring/policy/compile) never imports this package.
"""
