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
python3 $S export --target ci --dir "$HOME/sigma" | grep -q 'Sigma rule file'
grep -q 'logsource:' "$HOME"/sigma/*.yml
grep -q 'falsepositives:' "$HOME"/sigma/*.yml
grep -q 'attack.t1552' "$HOME"/sigma/*.yml
python3 $S refire --target ci --rule KAGE-001 2>/dev/null || test $? -eq 2   # no re-fireable URL → refusal
python3 $S refire --target ci --rule KAGE-999 2>/dev/null || test $? -eq 2   # no such rule → refusal
python3 $S report --target ci --output rep.md
grep -q 'Detection rules' rep.md
grep -q 'logsource' rep.md
rm -rf "$HOME/sigma" rep.md
echo "KAGE CI SUITE: PASS"
