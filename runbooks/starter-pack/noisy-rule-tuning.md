---
title: Noisy rule tuning methodology
tags: [tuning, detection-engineering, false-positive, alert-fatigue]
rules: []
---

# Noisy rule tuning methodology

Not a triage runbook — a procedure for deciding what to do about a rule
that keeps firing on benign activity. Alert fatigue is a security risk in
itself: analysts who dismiss a rule 200 times stop reading it, and the
201st might be real. Tune deliberately, with data, and leave a trail.

## Qualify the noise first

Before touching the rule, characterize the last 30 days of its alerts:

- **Volume and trend**: total fires, fires/day, growing or steady?
- **Concentration**: what fraction comes from the top 3 source hosts, top 3
  destinations, or one subnet? Noise is usually concentrated; real threat
  activity is distributed. A rule that's 95% one appliance is a *scoping*
  problem, not a bad rule.
- **Verdict history**: how many were investigated and what fraction ended
  false positive? If any recent fire was a true positive, the rule stays —
  scope around the noise instead of suppressing broadly.

## Choose the narrowest effective action

In order of preference:

1. **Fix the source**: when the noise is a misconfiguration (a service with
   stale credentials, a broken health check), fixing the system beats every
   suppression option — the alert was doing its job.
2. **Scoped suppression**: suppress the rule for the *specific* source/
   destination pairs that account for the noise (e.g. the vulnerability
   scanner's IP, the backup server's nightly job). Keep the rule live for
   everything else.
3. **Threshold/rate adjustment**: for burst-prone rules, alert on N fires
   in M minutes rather than every packet.
4. **Severity demotion**: keep the record for hunting/correlation but drop
   it out of the triage queue.
5. **Full disable** — last resort, only for rules that are wrong by design
   for your environment (a protocol you don't run, a geography that doesn't
   apply), and only with an expiry/review date.

## Guardrails

- Every tuning action needs: the evidence summary that justified it, the
  scope (why this narrow), an owner, and a **review date**. Untracked
  suppressions become permanent blind spots.
- Never tune away a rule family that maps to a technique you have no other
  coverage for — check what else would catch the behavior (MITRE ATT&CK
  mapping helps here) before removing the only tripwire.
- Prefer tuning in your detection layer over deleting upstream rules, so
  vendor updates don't silently resurrect or orphan your changes.
- Re-run the 30-day analysis after tuning: if the rule still tops the noise
  chart, the scoping was wrong; if it went silent entirely, verify the rule
  still fires on a known-good test (a suppression wider than intended looks
  identical to success).

## When triaging an alert from a known-noisy rule

Don't auto-dismiss on the rule's reputation. Check whether *this* fire
matches the documented benign pattern (same source, same schedule, same
shape). A noisy rule firing *off-pattern* — new source, odd hour, different
target — deserves a full look precisely because everyone else has stopped
looking.
