#!/usr/bin/env bash
# Capsule end-to-end demo (target: under 5 minutes). Run via `make demo`.
set -euo pipefail
cd "$(dirname "$0")/.."

hr() { printf '\n\033[1m%s\033[0m\n' "================ $* ================"; }

hr "1. The problem: a repo README carrying a prompt injection"
sed -n '1,20p' examples/malicious-repo/README.md

hr "2. Unsafe baseline: with no gateway, the secrets are reachable"
python -m bench.runner --mode unsafe \
  --attacks read_host_ssh_key,read_aws_credentials,curl_exfiltration

hr "3-5. Same attacks through Capsule (scripted injected agent, one MCP session)"
rm -f demo/pending_approvals.jsonl
python -m demo.injection_demo

hr "6. Approval is out-of-band and can be denied"
APPR=$(capsule-approve list | head -1 | awk '{print $1}' || true)
if [ -n "${APPR:-}" ]; then
  echo "Pending approval: $APPR"
  capsule-approve deny "$APPR"
fi

hr "7. Full benchmark report (measured, apples-to-apples)"
python -m bench.runner --mode both >/dev/null
sed -n '1,60p' bench/REPORT.md

hr "8. Audit trail (structured, one event per decision)"
tail -n 8 audit.log || true

rm -f demo/pending_approvals.jsonl
printf '\n\033[1mDemo complete.\033[0m See bench/REPORT.md for the measured numbers.\n'
