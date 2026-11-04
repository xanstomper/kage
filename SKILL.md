---
name: kage
description: "Trigger `kage`. THE MIRROR — for every attack the family confirms, generate the detection rule the defender should deploy: Sigma-shape rules, ATT&CK Detect mapping, telemetry registry, purple validation. The offense is proven detectable."
version: 1.0.0
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
| sensitive-path fetch | (backup/dump/.env/.git) + 200 | T1552 | web access log |
| privilege/lateral rung | sudo -l / SUID bursts | T1068 | auditd/sysmon |
| credential reuse | same cred across principals | T1078 | auth log |

## The purple loop

```
family CONFIRMS attack → kage mirror (rule generated) → kage validate
→ telemetry live? ✓ rule tested in-place · ⚠ rule-only → THE DELIVERABLE
```

`validate` exits 1 while any rule lacks live telemetry — the operator knows
exactly which eyes the defender still needs.

## Walls

Detection-only: KAGE never attacks — it reads family states and writes rules.
Zero documents. Everything under the barbican compartment.

## Tooling

`scripts/kage.py` — stdlib CLI:
- `mirror --target <c>` — generate detection rules from every CONFIRMED attack
- `telemetry --target <c> [--add "source :: path"]` — the log-source registry
- `validate --target <c>` — the purple loop (rc=1 while rules lack telemetry)
- `report --target <c> [--output F]` — the defense deliverable (Sigma YAML per rule)
- `verify` — self-check

State: `~/.redteam/campaigns/<c>/kage-state.json`.
