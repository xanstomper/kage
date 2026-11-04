#!/usr/bin/env bash
# KAGE CI smoke — the mirror/purple loop in an isolated HOME.
set -e
export HOME="${RUNNER_TEMP:-/tmp}/kage-home"
mkdir -p "$HOME/.redteam/campaigns/ci"
S=scripts/kage.py
python3 -m py_compile $S
python3 $S --help > /dev/null
python3 $S verify | grep -q 'ALL PASS'
printf '%s' '{"target":"ci","surface":[{"endpoint":"/backup.zip","status":"CONFIRMED","proof":"200","at":"x"}],"logic":[],"code":[],"pocs":[]}' > "$HOME/.redteam/campaigns/ci/undercroft-state.json"
python3 $S mirror --target ci | grep -q 'detection rule'
python3 $S mirror --target ci | grep -q '0 detection rule'
python3 $S validate --target ci 2>/dev/null || test $? -eq 1
python3 $S telemetry --target ci --add 'web access log :: /var/log/w' > /dev/null
python3 $S validate --target ci | grep -q 'PURPLE VALIDATE'
python3 $S report --target ci --output rep.md
grep -q 'Detection rules' rep.md
grep -q 'sigma' rep.md
echo "KAGE CI SUITE: PASS"
