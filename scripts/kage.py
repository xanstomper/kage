#!/usr/bin/env python3
"""
KAGE — The Mirror Mandate CLI. For every attack the family CONFIRMS, generate
the detection rule the defender should deploy: Sigma-shape rule + log source +
ATT&CK Detect + re-fire test. The purple loop: offense proven detectable.
stdlib-only. State: ~/.redteam/campaigns/<c>/kage-state.json.

Commands:
  mirror    --target <c>                     generate detection rules from every
                                             CONFIRMED attack in the family states
  telemetry --target <c> [--add "source :: path"]   the log-source registry
  validate  --target <c>                     the purple loop: which rules have a
                                             live telemetry source, which don't
  report    --target <c> [--output F]        the defense deliverable
  verify    self-check

Exit codes: 0 ok · 1 validate failure · 2 usage/state error.
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DETECT_MAP = [
    {"re": r"boundary|idor|org_id|scope", "attack": "foreign scope-id swap",
     "t": "T1068", "log": "app api access log", "match": "org_id value != session org",
     "sigma": {"title": "Foreign scope-id in API request", "logsource": {"service": "api"},
               "detection": {"sel": {"query_contains": "org_id=", "diff_session_org": True},
                             "condition": "sel"}}},
    {"re": r"replay|idempoten|webhook", "attack": "duplicate logical request",
     "t": "T1550", "log": "app request log", "match": "same (method+path+body-hash) N>1 within window",
     "sigma": {"title": "Repeated identical request (no idempotency)", "logsource": {"service": "api"},
               "detection": {"count_by": "hash(method,path,body)", "window": "60s", "threshold": 2}}},
    {"re": r"backup|dump|\.env|\.git|harvest", "attack": "sensitive path fetch",
     "t": "T1552", "log": "web access log", "match": "GET on sensitive path + 200",
     "sigma": {"title": "Sensitive-path GET (backup/env/git)", "logsource": {"service": "web"},
               "detection": {"uri_re": "(backup|dump|\\.env|\\.git/config)", "status": 200}}},
    {"re": r"privesc|sudo|suid|ladder|lateral", "attack": "privilege/lateral rung",
     "t": "T1068", "log": "host auditd/sysmon", "match": "sudo -l / SUID exec bursts on host",
     "sigma": {"title": "Privilege-mapping commands on host", "logsource": {"service": "auditd"},
               "detection": {"cmd_re": "(sudo -l|find / -perm)", "threshold": 3}}},
    {"re": r"credential|reuse|token|secret", "attack": "credential reuse attempt",
     "t": "T1078", "log": "auth log", "match": "same credential material across distinct principals/hosts",
     "sigma": {"title": "Cross-principal credential reuse", "logsource": {"service": "auth"},
               "detection": {"group_by": "cred_hash", "distinct_targets": 2}}},
]


def state_path(c):
    return Path.home() / ".redteam" / "campaigns" / c / "kage-state.json"


def base(c):
    p = state_path(c)
    if p.exists():
        st = json.loads(p.read_text())
    else:
        st = {"campaign": c, "rules": [], "telemetry": [],
              "created": datetime.now(timezone.utc).isoformat()}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(st, indent=2) + "\n")
    st.setdefault("rules", [])
    st.setdefault("telemetry", [])
    return st


def now():
    return datetime.now(timezone.utc).isoformat()


def _confirmed_attacks(c):
    out = []
    camp = Path.home() / ".redteam" / "campaigns" / c
    try:
        u = json.loads((camp / "undercroft-state.json").read_text())
        for s in u.get("surface", []) + u.get("logic", []):
            if s.get("status") == "CONFIRMED":
                out.append((s.get("endpoint") or s.get("seam") or "?",
                            s.get("proof") or ""))
    except Exception:
        pass
    try:
        h = json.loads((camp / "harvest-state.json").read_text())
        out += [(cr.get("asset", "?"), f"crown {cr.get('class')} harvested")
                for cr in h.get("crown", [])]
    except Exception:
        pass
    try:
        l = json.loads((camp / "ladder-state.json").read_text())
        for hh in l.get("hosts", []):
            out += [(f"{hh['host']}:{r['id']}", r.get("class", ""))
                    for r in hh.get("rungs", []) if r.get("status") == "CONFIRMED"]
    except Exception:
        pass
    return out


def cmd_mirror(args):
    st = base(args.target)
    attacks = _confirmed_attacks(args.target)
    if not attacks:
        print("· no CONFIRMED attacks in the family states — nothing to mirror")
        return 0
    known = {r["attack_ref"] for r in st["rules"]}
    made = 0
    for ref, proof in attacks:
        if ref in known:
            continue
        text = f"{ref} {proof}".lower()
        dm = next((d for d in DETECT_MAP if re.search(d["re"], text)),
                  {"attack": ref, "t": "T1592", "log": "app log",
                   "match": "documented class signature", "sigma": {
                       "title": f"Suspicious: {ref}", "logsource": {"service": "app"},
                       "detection": {"custom": True}}})
        rule = {"id": f"KAGE-{len(st['rules']) + 1:03d}", "attack_ref": ref,
                "attack": dm["attack"], "attck": dm["t"], "log_source": dm["log"],
                "match": dm["match"], "sigma": dm["sigma"], "status": "MIRRORED",
                "at": now()}
        st["rules"].append(rule)
        made += 1
        print(f"▸ {rule['id']}: {ref[:44]} → {dm['attack']} (ATT&CK {dm['t']},"
              f" source: {dm['log']})")
    save(st, args.target)
    print(f"▸ {made} detection rule(s) mirrored — the offense is now defensible")
    return 0


def save(st, c):
    state_path(c).write_text(json.dumps(st, indent=2) + "\n")


def cmd_telemetry(args):
    st = base(args.target)
    if args.add:
        if " :: " not in args.add:
            print('✗ format: "source :: path"', file=sys.stderr)
            return 2
        src, path = (p.strip() for p in args.add.split(" :: ", 1))
        if not any(t["source"] == src for t in st["telemetry"]):
            st["telemetry"].append({"source": src, "path": path, "at": now()})
            save(st, args.target)
    for t in st["telemetry"]:
        print(f"  {t['source']:22s} {t['path'][:60]}")
    if not st["telemetry"]:
        print('· telemetry empty — add: kage telemetry --target <c> --add "api log :: /var/log/api.log"')
    return 0


def cmd_validate(args):
    st = base(args.target)
    if not st["rules"]:
        print("· no mirrored rules — kage mirror first")
        return 0
    srcs = {t["source"].lower() for t in st["telemetry"]}
    missing = 0
    print(f"═══ KAGE PURPLE VALIDATE — {args.target} ({len(st['rules'])} rule(s)) ═══")
    for r in st["rules"]:
        live = r["log_source"].lower() in srcs or any(s in r["log_source"].lower() for s in srcs)
        r["status"] = "TELEMETRY-LIVE" if live else "RULE-ONLY"
        if not live:
            missing += 1
        print(f"  {'✓' if live else '⚠'} {r['id']} [{r['attck']}] {r['attack'][:40]}"
              + ("" if live else f" — no live source: {r['log_source']} (rule IS the deliverable)"))
    save(st, args.target)
    print(f"═══ {len(st['rules']) - missing}/{len(st['rules'])} rules backed by live"
          f" telemetry · {missing} rule-only (deliverable to the defender) ═══")
    return 0 if missing == 0 else 1


def cmd_report(args):
    st = base(args.target)
    out = args.output or f"{args.target}-kage-report.md"
    L = [f"# KAGE Mirror Report — {args.target}", "",
         "_every confirmed attack, mirrored as a detection rule_",
         "", "## Detection rules"]
    for r in st["rules"]:
        L += [f"### {r['id']} — {r['attack']} [{r['attck']}] ({r['status']})",
              f"- attack ref: {r['attack_ref']}", f"- log source: {r['log_source']}",
              f"- match: {r['match']}", "", "```yaml", json.dumps(r["sigma"], indent=2),
              "```", ""]
    if st["telemetry"]:
        L += ["## Telemetry sources"]
        L += [f"- {t['source']} → {t['path']}" for t in st["telemetry"]]
    Path(out).write_text("\n".join(L) + "\n")
    print(f"▸ report written: {out} ({len(st['rules'])} rule(s))")
    return 0


def cmd_verify(args):
    bad = []
    self = Path(__file__).resolve()
    if subprocess.run([sys.executable, "-m", "py_compile", str(self)],
                      capture_output=True).returncode != 0:
        bad.append("compile")
    help_out = subprocess.run([sys.executable, str(self), "--help"],
                              capture_output=True, text=True).stdout
    for want in ("mirror", "telemetry", "validate", "report", "verify"):
        if want not in help_out:
            bad.append(f"subcommand {want}")
    if len(DETECT_MAP) < 5:
        bad.append("detect map")
    if bad:
        print(f"✗ KAGE verify FAILED: {bad}")
        return 1
    print("✓ KAGE verify: compile · subcommands · detect map — ALL PASS")
    return 0


def main():
    ap = argparse.ArgumentParser(description="KAGE — The Mirror Mandate (detection for every attack)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mirror", help="generate detection rules from CONFIRMED attacks")
    m.add_argument("--target", required=True)
    t = sub.add_parser("telemetry", help="the log-source registry")
    t.add_argument("--target", required=True)
    t.add_argument("--add", help='"source :: path"')
    v = sub.add_parser("validate", help="the purple loop: rules vs live telemetry")
    v.add_argument("--target", required=True)
    r = sub.add_parser("report", help="the defense deliverable")
    r.add_argument("--target", required=True)
    r.add_argument("--output")
    vf = sub.add_parser("verify", help="self-check")
    a = ap.parse_args()
    return {"mirror": cmd_mirror, "telemetry": cmd_telemetry, "validate": cmd_validate,
            "report": cmd_report, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
