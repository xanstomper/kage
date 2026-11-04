---
name: kage
description: "Trigger `kage`. THE MIRROR — for every attack the family confirms, generate the detection rule the defender should deploy: Sigma-shape rules, ATT&CK Detect mapping, telemetry registry, purple validation. The offense is proven detectable."
version: 2.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [redteam, detection-engineering, purple-team, detection-rules, sigma, authorized-testing]
    related_skills: [shiki, 3am-shinjitsu, shukaku, kaisha, undercroft, barbican]
---

# KAGE (影) — The Mirror Mandate

The family's defense axis — the shadow that mirrors every strike. Every CONFIRMED
attack in the family states becomes a **detection rule**: Sigma-shape YAML, the
log source that should catch it, the ATT&CK Detect technique, and the purple
validation (does the telemetry exist, or is the rule the deliverable?).

> **The strongest offense is one the defender can now SEE — and we hand them the eyes.**

No offensive framework in the field ships this: the family's own findings become
the defender's ruleset, family-wide, automatically.

## Family role (mandate #8 — nine mandates, one gate)

```
BARBICAN · HOLYSHIT · UNDERCROFT · KAIRO · 3AM · KAISHA · SHUKAKU · SHIKI
   → every CONFIRMED attack → KAGE mirrors it → the defender gets the rule
```

- `spydermonkey` — the dispatcher: `route --goal "detect / mirror / detection / purple"` lands here.
- Every offensive mandate feeds it (undercroft surfaces · shukaku crowns · kaisha rungs · 3AM chains).

## The Detect Map (attack class → rule)

| Confirmed attack | Rule match | ATT&CK | Log source |
|---|---|---|---|
| foreign scope-id swap | org_id ≠ session org | T1068 | api access log |
| duplicate logical request | same hash ×N in window | T1550 | app request log |
| token forgery / alg-none | unsigned JWT accepted | T1550 | app auth log |
| authentication bypass | empty cred + 200 on protected route | T1550 | app auth log |
| server-side internal fetch | app egress to loopback/link-local | T1190 | app egress log |
| sensitive-path fetch | (backup/dump/.env/.git) + 200 | T1552 | web access log |
| path traversal | traversal sequence + 200 | T1083 | web access log |
| mass-assignment fields | privilege fields in body | T1098 | app api log |
| injection probes | interpreter markers in params | T1190 | web access log |
| open redirect | 302 cross-origin Location | T1190 | web access log |
| reflected markup | markup reflected unencoded | T1189 | web access log |
| role/level param flip | role param trusted from input | T1098 | app api log |
| business-logic boundary | negative/overflow amounts accepted | T1565 | app api log |
| privilege/lateral rung | sudo -l / SUID bursts | T1068 | auditd/sysmon |
| credential reuse | same cred across principals | T1078 | auth log |

## The purple loop

```
family CONFIRMS attack → kage mirror (Sigma-shaped rule generated)
→ kage export (real .yml rule files) → kage validate (telemetry live?)
→ kage refire (RE-FIRE the attack; the rule must fire on it) → FIRED = loop closed
   · telemetry live? ✓ rule tested in-place · ⚠ rule-only → THE DELIVERABLE
```

v2.0: rules are real Sigma-shaped YAML (title/id/status/description/logsource/
detection/falsepositives/level/tags — stable sha-derived ids), exported as .yml
files, and NOT-FIRED is a finding: `refire` re-executes the attack (lab-bound or
in-scope only — the dispatcher's live-fire rule) and checks the rule's condition
against what it observed. A detection rule is not DONE until re-firing the attack
makes it fire.

`validate` exits 1 while any rule lacks live telemetry — the operator knows
exactly which eyes the defender still needs.

## Walls

Detection-only: KAGE never attacks — it reads family states and writes rules.
Zero documents. Everything under the barbican compartment.

## Tooling

`scripts/kage.py` — stdlib CLI:
- `mirror --target <c>` — generate detection rules from every CONFIRMED attack (15 patterns)
- `telemetry --target <c> [--add "source :: path"]` — the log-source registry
- `validate --target <c>` — the purple loop (rc=1 while rules lack telemetry)
- `refire --target <c> --rule KAGE-NNN [--url U] [--data BODY]` — re-fire the attack; the rule must fire on it (lab-bound or in-scope only)
- `export --target <c> [--dir D] [--print]` — write every rule as a Sigma .yml file
- `report --target <c> [--output F]` — the defense deliverable (Sigma YAML per rule)
- `verify` — self-check (compile · subcommands · 15 patterns · Sigma emitter integrity)

State: `~/.redteam/campaigns/<c>/kage-state.json`.
