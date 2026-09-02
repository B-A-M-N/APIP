#!/usr/bin/env bash
# APIP Attribution Lab — one-command entry point.
#
# WHAT THIS IS FOR: demonstrating the docs/30 requester attribution engine
# and its hard boundary against real (loopback-only) traffic. See README.md.
#
# Safety: loopback-only by construction; no enforcement anywhere in the lab;
# artifacts are plain files under lab/output/.
set -euo pipefail
cd "$(dirname "$0")"
echo "=========================================================="
echo " APIP ATTRIBUTION LAB — what this is"
echo "   Demonstrates docs/30 requester attribution:"
echo "   - rotating attacker infrastructure -> one fingerprint"
echo "   - distinct toolchains -> separate groups"
echo "   - same campaign across vendor log formats -> linked"
echo "   - observable behaviors harvested from real HTTP (loopback)"
echo "   - PROOF attribution can never change an enforcement decision"
echo "   No traffic leaves this machine. No enforcement occurs."
echo "=========================================================="
echo
python3 run_lab.py all
