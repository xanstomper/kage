<div align="center">

# 🪞 KAGE

### *for every attack the family confirms, the detection rule the defender should deploy*

**The purple layer of the HolyShit offensive-security family — every confirmed
attack mirrored as a real Sigma-shaped rule, exported as `.yml`, and not done
until RE-FIRING the attack makes it fire.** The offense is proven detectable.

[![Version](https://img.shields.io/badge/version-2.0.0-blueviolet?style=for-the-badge)](#the-cli)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#quickstart)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](#quickstart)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#why-its-powerful)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/xanstomper/kage/actions/workflows/verify.yml/badge.svg)](https://github.com/xanstomper/kage/actions/workflows/verify.yml)
[![Use](https://img.shields.io/badge/use-AUTHORIZED%20TARGETS%20ONLY-crimson)](#the-walls)

**THE FAMILY** — ten mandates, one axis each:

[![00 BARBICAN · the shield](https://img.shields.io/badge/00-BARBICAN%20·%20the%20shield-2E4057?style=for-the-badge)](https://github.com/xanstomper/barbican)
[![01 3AM · the performer](https://img.shields.io/badge/01-3AM%20·%20the%20performer-8B0000?style=for-the-badge)](https://github.com/xanstomper/3am-shinjitsu)
[![02 KAIRO · the synthesizer](https://img.shields.io/badge/02-KAIRO%20·%20the%20synthesizer-6B8E23?style=for-the-badge)](https://github.com/xanstomper/kairo)
[![03 UNDERCROFT · the descent](https://img.shields.io/badge/03-UNDERCROFT%20·%20the%20descent-4B0082?style=for-the-badge)](https://github.com/xanstomper/undercroft)
[![04 HOLYSHIT · the finder](https://img.shields.io/badge/04-HOLYSHIT%20·%20the%20finder-B8860B?style=for-the-badge)](https://github.com/xanstomper/HolyShit)
[![05 SHIKI · the command](https://img.shields.io/badge/05-SHIKI%20·%20the%20command-111111?style=for-the-badge)](https://github.com/xanstomper/shiki)
[![06 KAISHA · the ladder](https://img.shields.io/badge/06-KAISHA%20·%20the%20ladder-704214?style=for-the-badge)](https://github.com/xanstomper/kaisha)
[![07 SHUKAKU · the harvester](https://img.shields.io/badge/07-SHUKAKU%20·%20the%20harvester-8B4513?style=for-the-badge)](https://github.com/xanstomper/shukaku)
[![09 DOJO · the range](https://img.shields.io/badge/09-DOJO%20·%20the%20range-4a5d23?style=for-the-badge)](https://github.com/xanstomper/dojo)
[![SPYDERMONKEY · dispatcher](https://img.shields.io/badge/SPYDERMONKEY-·%20the%20dispatcher-blueviolet?style=for-the-badge)](https://github.com/xanstomper/spydermonkey)

[How it works](#how-it-works) · [Why it's powerful](#why-its-powerful) ·
[Quickstart](#quickstart) · [The CLI](#the-cli) · [The Walls](#the-walls)

</div>

---

## What is this?

KAGE is the mirror. When any family mandate CONFIRMS an attack, KAGE answers the
question the engagement is really for: **would the defender have seen this?** It
generates the detection rule — Sigma-shaped, ATT&CK-mapped, log-sourced — from the
family's real state files, exports it as a deployable `.yml`, and closes the
purple loop by re-firing the attack and requiring the rule to fire on it.

## How it works

```
family states (ledger · undercroft · harvest · ladder)
    ↓  kage mirror — 15 detection patterns, first-match canon
Sigma-shaped rules (title · id · status · logsource · detection ·
                    falsepositives · level · tags — stable sha ids)
    ↓  kage export — real .yml files, ready for the defender's pipeline
    ↓  kage validate — which rules have live telemetry, which are rule-only
    ↓  kage refire — RE-FIRE the attack; the rule must fire on it
🔥 FIRED = the purple loop is closed
```

Real captured run (a lab-bound dojo replica serving, the family ledger holding a
CONFIRMED boundary finding):

```
▸ KAGE-001: http://127.0.0.1:8801/api/orders?org_id=acme → foreign scope-id swap (ATT&CK T1068, level high, source: app api access log)
▸ 1 detection rule(s) mirrored — the offense is now defensible

═══ KAGE RE-FIRE — KAGE-001 [foreign scope-id swap] ═══
  ▸ re-firing the attack: GET http://127.0.0.1:8801/api/orders?org_id=acme
    · selectors: sel_query_contains → ✓
  🔥 FIRED — KAGE-001 would alert on this attack (purple loop closed)
```

## Why it's powerful

- **Real Sigma, not JSON in a yaml fence.** v2.0 emits proper Sigma-shaped YAML
  (title/id/status/description/logsource/detection/falsepositives/level/tags)
  with deterministic sha-derived rule ids — drop the export dir into any Sigma
  pipeline.
- **15 detection patterns**, canon-aligned with the family's skilltree bindings
  (boundary · replay · jwt-forgery · auth-bypass · ssrf · harvest · traversal ·
  mass-assignment · injection · redirect · xss · authz · bizlogic · privesc ·
  cred-reuse).
- **NOT-FIRED is a finding.** A rule that doesn't fire on a re-fired attack is
  tuned or marked — a detection rule is not DONE until re-firing the attack
  makes it fire.
- **The purple mirror of the whole family.** Every mandate's confirmed rows
  (3AM chains, undercroft seams, kaisha rungs, shukaku crowns, the dispatcher's
  ledger) feed one mirror — the defender gets the eyes for everything proven.
- **Zero dependencies.** Pure Python stdlib; state in
  `~/.redteam/campaigns/<c>/kage-state.json`.

## Quickstart

```
git clone https://github.com/xanstomper/kage && cd kage
python3 scripts/kage.py verify
python3 scripts/kage.py mirror --target <campaign>
python3 scripts/kage.py export --target <campaign> --dir sigma/
python3 scripts/kage.py refire  --target <campaign> --rule KAGE-001
```

As a Hermes skill: the installed copy lives at
`~/.hermes/skills/security/kage/` (the repo is the source of truth).

## The CLI

| Command | What it does |
|---|---|
| `mirror --target C` | generate detection rules from every CONFIRMED attack in the family states (15 patterns) |
| `telemetry --target C [--add "src :: path"]` | the log-source registry |
| `validate --target C` | rules vs live telemetry — rc=1 while any rule lacks a source |
| `refire --target C --rule KAGE-NNN [--url U] [--data BODY]` | re-fire the attack; the rule must fire on it (lab-bound or in-scope only) |
| `export --target C [--dir D] [--print]` | write every rule as a Sigma `.yml` file |
| `report --target C [--output F]` | the defense deliverable (Sigma YAML per rule) |
| `verify` | self-check: compile · subcommands · 15 patterns · Sigma emitter |

Exit codes: `0` ok · `1` validate/refire failure · `2` usage/state error.

## The Walls

- **Detection-only.** KAGE never attacks — it reads family states and writes rules.
- **Live-fire rule.** `refire` fires at 127.0.0.1/localhost freely (the lab);
  anything else must be inside the declared scope authority — out-of-estate → rc=1.
- **Zero documents.** Everything under the barbican compartment.

## Files

```
kage/
├── SKILL.md            the doctrine (detect map · purple loop · walls)
├── scripts/kage.py     the mirror CLI (15 patterns · Sigma emitter · refire)
├── references/         detection-engineering playbook
├── templates/          state template
├── LICENSE             MIT
└── README.md           this page
```

## Relations

Dispatcher: [`spydermonkey`](https://github.com/xanstomper/spydermonkey) routes
every goal; [`shiki`](https://github.com/xanstomper/shiki) conducts the assault
KAGE mirrors; every confirmed row in
[`3am-shinjitsu`](https://github.com/xanstomper/3am-shinjitsu) ·
[`undercroft`](https://github.com/xanstomper/undercroft) ·
[`kaisha`](https://github.com/xanstomper/kaisha) ·
[`shukaku`](https://github.com/xanstomper/shukaku) becomes a rule here.

---

<div align="center"><em>the offense is proven · the defense gets the eyes</em></div>
