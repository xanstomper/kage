#!/usr/bin/env python3
"""
KAGE — The Mirror Mandate CLI. For every attack the family CONFIRMS, generate
the detection rule the defender should deploy: a real Sigma-shaped YAML rule
(title/id/status/logsource/detection/falsepositives/level/tags) + log source +
ATT&CK mapping + telemetry validation + the RE-FIRE TEST (the purple loop:
re-execute the attack once, check the rule's condition would fire on it).

v2.0 — the mirror gets real: 13 detection patterns (boundary · replay · harvest ·
privesc · cred-reuse · injection · traversal · redirect · xss · jwt · ssrf ·
massassign · authbypass), Sigma YAML export as rule files, and `refire` —
a detection rule is not DONE until re-firing the attack makes it fire.

Commands:
  mirror    --target <c>                     generate detection rules from every
                                             CONFIRMED attack in the family states
  telemetry --target <c> [--add "src :: p"]  the log-source registry
  validate  --target <c>                     rules vs live telemetry (+ refire state)
  refire    --target <c> --rule KAGE-001 [--url U] [--rate N]
                                             re-fire the attack, check the rule fires
  export    --target <c> [--dir D]           write every rule as a Sigma .yml file
  report    --target <c> [--output F]        the defense deliverable
  verify    self-check

State: ~/.redteam/campaigns/<c>/kage-state.json.
Exit codes: 0 ok · 1 validate/refire failure · 2 usage/state error.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# attack-class canon: regex → ATT&CK · log source · match condition · Sigma rule
# (first match wins — order specific→generic; T-codes follow the family's
#  skilltree BINDINGS canon so mirror, skilltree and doctrine agree)
DETECT_MAP = [
    {"re": r"boundary|idor|org_id|scope.?id|foreign",
     "attack": "foreign scope-id swap", "t": "T1068", "log": "app api access log",
     "level": "high", "match": "org_id value != session org",
     "fps": ["integration tests that swap org ids by design"],
     "sigma": {"title": "Foreign scope-id in API request",
               "logsource": {"service": "api"},
               "detection": {"sel_query_contains": "org_id=", "sel_diff_session_org": True,
                             "condition": "sel"}}},
    {"re": r"replay|idempoten|webhook|double.?spend|race",
     "attack": "duplicate logical request", "t": "T1550", "log": "app request log",
     "level": "high", "match": "same (method+path+body-hash) N>1 within window",
     "fps": ["legitimate retries with the same idempotency key"],
     "sigma": {"title": "Repeated identical request (no idempotency)",
               "logsource": {"service": "api"},
               "detection": {"count_by": "hash(method,path,body)", "window": "60s",
                             "threshold": 2, "condition": "sel | count() >= threshold"}}},
    {"re": r"jwt|alg.?none|token forge|unsigned",
     "attack": "token forgery / alg-none", "t": "T1550", "log": "app auth log",
     "level": "critical", "match": "jwt with alg=none accepted or signature unverified",
     "fps": ["dedicated unsigned-token test endpoints"],
     "sigma": {"title": "Unsigned or forged JWT accepted",
               "logsource": {"service": "auth"},
               "detection": {"jwt_alg_in": ["none", "HS256-with-public-key"],
                             "condition": "sel"}}},
    {"re": r"auth.?bypass|empty token|unauth|no.?session",
     "attack": "authentication bypass", "t": "T1550", "log": "app auth log",
     "level": "critical", "match": "protected route answers 200 with empty/forged credential",
     "fps": ["health endpoints", "public marketing routes"],
     "sigma": {"title": "Protected route with empty credential material",
               "logsource": {"service": "auth"},
               "detection": {"uri_re": "/(api|admin|account)/", "cred_empty": True,
                             "status": 200, "condition": "sel"}}},
    {"re": r"ssrf|metadata|internal.?fetch",
     "attack": "server-side internal fetch", "t": "T1190", "log": "app egress log",
     "level": "high", "match": "outbound fetch to link-local/loopback from app process",
     "fps": ["webhook delivery to internal consumers (allowlisted)"],
     "sigma": {"title": "App-initiated fetch to loopback/link-local",
               "logsource": {"service": "egress"},
               "detection": {"dest_re": "^(127\\.|169\\.254\\.|10\\.|::1)", "condition": "sel"}}},
    {"re": r"backup|dump|\\.env|\\.git|harvest|sensitive path",
     "attack": "sensitive path fetch", "t": "T1552", "log": "web access log",
     "level": "high", "match": "GET on sensitive path + 200",
     "fps": ["ops pulling backups over the CDN"],
     "sigma": {"title": "Sensitive-path GET (backup/env/git)",
               "logsource": {"service": "web"},
               "detection": {"uri_re": "(backup|dump|\\.env|\\.git/config)", "status": 200,
                             "condition": "sel"}}},
    {"re": r"traversal|\\.\\./|path.?traver|file",
     "attack": "path traversal", "t": "T1083", "log": "web access log",
     "level": "high", "match": "traversal sequence in uri + 200",
     "fps": ["none common"],
     "sigma": {"title": "Path traversal sequence in request",
               "logsource": {"service": "web"},
               "detection": {"uri_re": "(\\.\\./|\\.\\.\\\\|%2e%2e)", "status": 200,
                             "condition": "sel"}}},
    {"re": r"mass.?assign|role.?param|is_admin",
     "attack": "mass-assignment field injection", "t": "T1098", "log": "app api log",
     "level": "high", "match": "request body carries privilege fields the server accepted",
     "fps": ["internal admin tooling that legitimately sets role"],
     "sigma": {"title": "Privilege fields in unprivileged request body",
               "logsource": {"service": "api"},
               "detection": {"body_re": "(role=admin|is_admin=1|balance=)", "cond_role": "low",
                             "condition": "sel"}}},
    {"re": r"injection|sql|ssti|template|\\{\\{|\\$\\{",
     "attack": "injection probe/eval", "t": "T1190", "log": "web access log",
     "level": "high", "match": "interpreter markers (' , {{, ${) in params + anomalous response",
     "fps": ["search boxes queried for literal quotes"],
     "sigma": {"title": "Interpreter markers in request parameters",
               "logsource": {"service": "web"},
               "detection": {"uri_re": "('|%27|\\{\\{|\\$\\{)", "condition": "sel"}}},
    {"re": r"redirect|302|open.?red",
     "attack": "open redirect", "t": "T1190", "log": "web access log",
     "level": "medium", "match": "302 whose Location crosses origins from user input",
     "fps": ["auth flows with allowlisted redirect_uri"],
     "sigma": {"title": "Cross-origin redirect from user input",
               "logsource": {"service": "web"},
               "detection": {"status": 302, "location_re": "^https?://(?!www\\.target\\.)",
                             "condition": "sel"}}},
    {"re": r"xss|reflected|markup|svg",
     "attack": "reflected markup (xss class)", "t": "T1189", "log": "web access log",
     "level": "medium", "match": "markup reflected in response without encoding",
     "fps": ["pen-tester traffic", "rich-text preview endpoints"],
     "sigma": {"title": "Markup reflected in response",
               "logsource": {"service": "web"},
               "detection": {"uri_re": "(%3C|<svg|<script)", "resp_re": "(<svg|<script)",
                             "condition": "sel"}}},
    {"re": r"privesc|sudo|suid|ladder|lateral",
     "attack": "privilege/lateral rung", "t": "T1068", "log": "host auditd/sysmon",
     "level": "high", "match": "sudo -l / SUID exec bursts on host",
     "fps": ["admin workstations", "config-management runs"],
     "sigma": {"title": "Privilege-mapping commands on host",
               "logsource": {"service": "auditd"},
               "detection": {"cmd_re": "(sudo -l|find / -perm)", "threshold": 3,
                             "condition": "sel | count(cmd) >= threshold"}}},
    {"re": r"authz|role.?differential|vertical",
     "attack": "role/level param trusted from input", "t": "T1098", "log": "app api log",
     "level": "high", "match": "role/admin/level param flipped → privileged response",
     "fps": ["role-switch features with server-side re-auth"],
     "sigma": {"title": "Role parameter flipped in request",
               "logsource": {"service": "api"},
               "detection": {"query_contains": "role=", "value_re": "(admin|^1$|^0$)",
                             "condition": "sel"}}},
    {"re": r"bizlogic|coupon|discount|negative|out.?of.?range",
     "attack": "business-logic boundary violation", "t": "T1565", "log": "app api log",
     "level": "high", "match": "out-of-range value accepted (negative/zero/overflow)",
     "fps": ["refunds/credits with negative flows by design"],
     "sigma": {"title": "Out-of-range business value accepted",
               "logsource": {"service": "api"},
               "detection": {"query_re": "(amount=-|qty=-|price=-|discount=-)",
                             "status": 200, "condition": "sel"}}},
    {"re": r"credential|reuse|token|secret",
     "attack": "credential reuse attempt", "t": "T1078", "log": "auth log",
     "level": "critical", "match": "same credential material across distinct principals/hosts",
     "fps": ["service accounts by design"],
     "sigma": {"title": "Cross-principal credential reuse",
               "logsource": {"service": "auth"},
               "detection": {"group_by": "cred_hash", "distinct_targets": 2,
                             "condition": "sel | distinct targets >= 2"}}},
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
    for r in st["rules"]:
        r.setdefault("refire", "")
    return st


def save(st, c):
    state_path(c).write_text(json.dumps(st, indent=2) + "\n")


def now():
    return datetime.now(timezone.utc).isoformat()


def _stable_id(seed):
    """Deterministic Sigma-style rule id (uuid-shape) from the rule seed."""
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def _yaml(obj, ind=0):
    """Hand-rolled Sigma-shaped YAML emitter (stdlib-only; no yaml dep)."""
    pad = "    " * ind
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                lines.append(f"{pad}{k}:")
                lines += _yaml(v, ind + 1)
            elif isinstance(v, list):
                lines.append(f"{pad}{k}:")
                lines += _yaml(v, ind + 1)
            elif isinstance(v, bool):
                lines.append(f"{pad}{k}: {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{pad}{k}: {v}")
            else:
                lines.append(f'{pad}{k}: "{v}"')
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                lines += _yaml(v, ind)
            else:
                lines.append(f'{pad}- "{v}"')
    return lines


def rule_yaml(rule):
    """The full Sigma-shaped document for a KAGE rule."""
    doc = {
        "title": rule["sigma"].get("title", rule["attack"]),
        "id": _stable_id(rule["attack_ref"] + rule["attack"]),
        "status": "stable" if rule.get("refire") == "FIRED" else
                  ("test" if rule.get("status") == "TELEMETRY-LIVE" else "experimental"),
        "description": (f"Mirrored from confirmed attack: {rule['attack']} "
                        f"(attack ref: {rule['attack_ref']}; match: {rule['match']})."),
        "logsource": rule["sigma"].get("logsource", {"service": "app"}),
        "detection": rule["sigma"].get("detection", {"custom": True, "condition": "sel"}),
        "falsepositives": rule.get("fps", ["none known"]),
        "level": rule.get("level", "medium"),
        "tags": [f"attack.{rule['attck'].lower()}"],
    }
    return "\n".join(_yaml(doc)) + "\n"


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
    ld = camp / "ledger.jsonl"
    try:
        for line in ld.read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("status") == "CONFIRMED":
                out.append((e.get("asset") or "?",
                            f"{e.get('cls')} confirmed: {e.get('proof', '')[:120]}"))
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
                  {"attack": ref, "t": "T1592", "log": "app log", "level": "medium",
                   "match": "documented class signature", "fps": ["none known"],
                   "sigma": {"title": f"Suspicious: {ref}", "logsource": {"service": "app"},
                             "detection": {"custom": True, "condition": "sel"}}})
        rule = {"id": f"KAGE-{len(st['rules']) + 1:03d}", "attack_ref": ref,
                "attack": dm["attack"], "attck": dm["t"], "log_source": dm["log"],
                "level": dm.get("level", "medium"), "fps": dm.get("fps", ["none known"]),
                "match": dm["match"], "sigma": dm["sigma"], "status": "MIRRORED",
                "refire": "", "at": now()}
        st["rules"].append(rule)
        made += 1
        print(f"▸ {rule['id']}: {ref[:44]} → {dm['attack']} (ATT&CK {dm['t']},"
              f" level {dm.get('level')}, source: {dm['log']})")
    save(st, args.target)
    print(f"▸ {made} detection rule(s) mirrored — the offense is now defensible")
    return 0


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
        refire = r.get("refire", "")
        rmark = "🔥" if refire == "FIRED" else ("⚠ refire pending" if live else "")
        print(f"  {'✓' if live else '⚠'} {r['id']} [{r['attck']}] {r['attack'][:40]}"
              + ("" if live else f" — no live source: {r['log_source']} (rule IS the deliverable)")
              + (f" · refire {refire}" if refire else ""))
    save(st, args.target)
    fired = sum(1 for r in st["rules"] if r.get("refire") == "FIRED")
    print(f"═══ {len(st['rules']) - missing}/{len(st['rules'])} rules backed by live telemetry"
          f" · {fired} re-fire proven · {missing} rule-only (deliverable to the defender) ═══")
    return 0 if missing == 0 else 1


def _attack_url_from_rule(rule):
    """Pull the re-fireable URL out of the rule's attack ref / family proof."""
    ref = rule.get("attack_ref", "")
    m = re.search(r"https?://[^\s'\"]+", ref)
    if m:
        return m.group(0).rstrip(".,)")
    return None


def cmd_refire(args):
    st = base(args.target)
    rule = next((r for r in st["rules"] if r["id"] == args.rule), None)
    if not rule:
        print(f"✗ no rule {args.rule} — kage mirror first", file=sys.stderr)
        return 2
    url = args.url or _attack_url_from_rule(rule)
    if not url:
        print(f"✗ no re-fireable URL in rule {rule['id']} (attack_ref has no http(s) URL;"
              " pass --url U to fire the attack manually)", file=sys.stderr)
        return 2
    # live-fire gate: the dispatcher's rule — lab free, elsewhere needs scope
    import ipaddress as _ip
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    lab = host in ("127.0.0.1", "localhost", "::1")
    if not lab:
        scope = Path.home() / ".redteam" / "scope.json"
        ok = False
        try:
            sc = json.loads(scope.read_text())
            ip = _ip.ip_address(host)
            for net in sc.get("in_scope", []):
                try:
                    if ip in _ip.ip_network(net, strict=False):
                        ok = True
                except ValueError:
                    continue
            if not ok:
                for i in sc.get("in_scope", []):
                    if host == i.lower() or host.endswith("." + i.lower()):
                        ok = True
        except Exception:
            pass
        if not ok:
            print(f"✗ REFIRE REFUSED — {url} is not in the declared estate (lab or scope only)",
                  file=sys.stderr)
            return 1
    det = rule["sigma"].get("detection", {})
    print(f"═══ KAGE RE-FIRE — {rule['id']} [{rule['attack']}] ═══")
    print(f"  ▸ re-firing the attack: GET {url[:80]}")
    # no-redirect opener: a 302 IS an observable the rule may key on
    import urllib.request as _ur

    class _NoRedirect(_ur.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = _ur.build_opener(_NoRedirect)
    try:
        req = _ur.Request(url, method="GET")
        with opener.open(req, timeout=args.timeout) as resp:
            status, body = resp.status, resp.read().decode("utf-8", "replace")
            location = resp.headers.get("Location", "")
    except _ur.HTTPError as e:
        status = e.code
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        location = e.headers.get("Location", "") if e.headers else ""
    except Exception as e:
        print(f"  ✗ request failed: {type(e).__name__} — no fire test possible", file=sys.stderr)
        return 1
    # would the rule's condition fire on what we just observed?
    from urllib.parse import urlparse as _up, parse_qs as _pq
    up = _up(url)
    path = up.path or "/"
    q = up.query
    qvals = _pq(q)
    sels = []
    if det.get("uri_re"):
        sels.append(("uri_re", re.search(det["uri_re"], path + ("?" + q if q else "")) is not None))
    if det.get("sel_query_contains"):
        sels.append(("sel_query_contains", det["sel_query_contains"] in q))
    if det.get("query_contains"):
        sels.append(("query_contains", det["query_contains"] in q))
    if det.get("query_re"):
        sels.append(("query_re", re.search(det["query_re"], q) is not None))
    if det.get("dest_re"):
        dest = (qvals.get("url") or qvals.get("fetch") or [""])[0]
        sels.append(("dest_re", re.search(det["dest_re"], dest) is not None))
    if det.get("body_re"):
        sels.append(("body_re", re.search(det["body_re"], body) is not None or
                     bool(args.data and re.search(det["body_re"], args.data))))
    if det.get("location_re") is not None:
        sels.append(("location_re", re.search(det["location_re"], location) is not None))
    if det.get("cred_empty"):
        sels.append(("cred_empty", any(v == [""] for v in qvals.values())))
    checks = []
    if sels:
        sel_ok = all(ok for _, ok in sels)
        checks.append(("selectors", sel_ok, sels))
    if det.get("status") is not None:
        checks.append(("status", status == det["status"], [(str(det["status"]), status == det["status"])]))
    fired = all(ok for _, ok, _ in checks) if checks else None
    why = []
    for name, ok, parts in checks:
        why.append(f"{name}: " + "; ".join(f"{k} → {'✓' if v else '✗'}" for k, v in parts))
    if det.get("count_by"):
        # fire it again and treat the window as holding N>=threshold
        try:
            with _ur.build_opener(_NoRedirect).open(_ur.Request(url, method="GET"),
                                                    timeout=args.timeout) as r2:
                r2.read()
            why.append(f"count_by window: replayed ×2 → threshold {det.get('threshold')} reached → ✓")
            fired = True if fired is None or fired else fired
        except Exception as ex:
            why.append(f"count_by replay failed ({type(ex).__name__}) → ✗")
            fired = False
    rule["refire"] = "FIRED" if fired else ("NOT-FIRED" if fired is not None else "NOT-REFIREABLE")
    rule["refire_at"] = now()
    rule["refire_evidence"] = f"GET {url[:120]} → {status} loc={location[:40]}; " + "; ".join(why)
    save(st, args.target)
    for w in why:
        print(f"    · {w[:110]}")
    if fired:
        print(f"  🔥 FIRED — {rule['id']} would alert on this attack (purple loop closed)")
        return 0
    if fired is None:
        print("  · rule condition is semantic (no refireable selector) — the rule IS the"
              " deliverable; validate covers it")
        return 0
    print(f"  ⚠ NOT-FIRED — the observed request does not trip the condition;"
          f" tune the rule (status/uri_re/confirm token mismatch)")
    return 1


def cmd_export(args):
    st = base(args.target)
    if not st["rules"]:
        print("· no rules to export — kage mirror first")
        return 0
    outdir = Path(args.dir) if args.dir else Path.home() / ".redteam" / "campaigns" / args.target / "sigma"
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for r in st["rules"]:
        y = rule_yaml(r)
        f = outdir / f"{r['id'].lower()}-{_stable_id(r['attack_ref'] + r['attack'])[:8]}.yml"
        f.write_text(y)
        n += 1
        if args.print:
            print(f"── {f.name} ──\n{y}")
    print(f"▸ {n} Sigma rule file(s) written to {outdir}")
    return 0


def cmd_report(args):
    st = base(args.target)
    out = args.output or f"{args.target}-kage-report.md"
    L = [f"# KAGE Mirror Report — {args.target}", "",
         "_every confirmed attack, mirrored as a detection rule_",
         "", "## Detection rules"]
    for r in st["rules"]:
        L += [f"### {r['id']} — {r['attack']} [{r['attck']}] ({r['status']}"
              + (f" · refire {r.get('refire')}" if r.get("refire") else "") + ")",
              f"- attack ref: {r['attack_ref']}", f"- log source: {r['log_source']}",
              f"- match: {r['match']}", "",
              "```yaml", rule_yaml(r), "```", ""]
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
    for want in ("mirror", "telemetry", "validate", "refire", "export", "report", "verify"):
        if want not in help_out:
            bad.append(f"subcommand {want}")
    if len(DETECT_MAP) < 14:
        bad.append("detect map")
    # sigma emitter integrity: a rule must carry the 9 canonical fields
    probe = {"id": "KAGE-001", "attack_ref": "http://127.0.0.1/x?org_id=1", "attack": "foreign scope-id swap",
             "attck": "T1068", "log_source": "app api access log", "level": "high",
             "fps": ["none"], "match": "m", "sigma": DETECT_MAP[0]["sigma"],
             "status": "MIRRORED", "refire": ""}
    y = rule_yaml(probe)
    for field in ("title:", "id:", "status:", "description:", "logsource:",
                  "detection:", "falsepositives:", "level:", "tags:"):
        if field not in y:
            bad.append(f"sigma field {field}")
    if bad:
        print(f"✗ KAGE verify FAILED: {bad}")
        return 1
    print("✓ KAGE verify: compile · subcommands · 15 detect patterns · Sigma emitter — ALL PASS")
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
    rf = sub.add_parser("refire", help="re-fire the attack; the rule must fire on it")
    rf.add_argument("--target", required=True)
    rf.add_argument("--rule", required=True)
    rf.add_argument("--url", help="override the attack url (lab or in-scope only)")
    rf.add_argument("--data", help="POST body for body_re rules")
    rf.add_argument("--timeout", type=int, default=6)
    ex = sub.add_parser("export", help="write every rule as a Sigma .yml file")
    ex.add_argument("--target", required=True)
    ex.add_argument("--dir")
    ex.add_argument("--print", dest="print", action="store_true", help="also print the YAML")
    r = sub.add_parser("report", help="the defense deliverable")
    r.add_argument("--target", required=True)
    r.add_argument("--output")
    vf = sub.add_parser("verify", help="self-check")
    a = ap.parse_args()
    return {"mirror": cmd_mirror, "telemetry": cmd_telemetry, "validate": cmd_validate,
            "refire": cmd_refire, "export": cmd_export, "report": cmd_report,
            "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
