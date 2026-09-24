---
title: Noisy rule tuning methodology
tags: [tuning, detection-engineering, false-positive, alert-fatigue]
rules: []
---

# Noisy rule tuning methodology

This document is a procedure for a rule that fires repeatedly on benign activity. It is
not a triage runbook. Alert fatigue is itself a security risk. An analyst who dismisses a
rule 200 times stops reading it. The 201st alert can be real. Tune the rule deliberately, use
data, and leave a record.

## Qualify the noise first

Characterize the alerts of the last 30 days before you change the rule:

- **Volume and trend**. Count the total fires and the fires per day. Record whether the
  count grows or stays steady.
- **Concentration**. Measure the fraction that comes from the top 3 source hosts, the top
  3 destinations or one subnet. Noise is usually concentrated. Real threat activity is
  distributed. A rule with 95 % of its fires from one appliance has a *scoping* problem.
- **Verdict history**. Count the alerts that reached an investigation. Measure the
  fraction that ended as a false positive. Keep the rule if any recent fire was a true
  positive. Scope the rule around the noise. Do not suppress the rule broadly.

## Choose the narrowest effective action

Use this order of preference:

1. **Fix the source.** Repair the system if a misconfiguration causes the noise. A service
   with stale credentials or a broken health check is a misconfiguration. A repair beats
   every suppression option. The alert did its job.
2. **Apply a scoped suppression.** Suppress the rule for the *specific* source and
   destination pairs that produce the noise. Two examples are the IP of the vulnerability
   scanner and the nightly job of the backup server. Keep the rule live for everything
   else.
3. **Adjust the threshold or the rate.** For a burst-prone rule, alert on N fires in M
   minutes. Do not alert on every packet.
4. **Demote the severity.** Keep the record for hunts and correlation. Remove the alert
   from the triage queue.
5. **Disable the rule in full.** Use this action last. Use it only for a rule that is
   wrong by design for your environment. A protocol that you do not run or a geography
   that does not apply makes a rule wrong by design. Set an expiry date or a review date
   for the disable.

## Guardrails

- Record 4 items for every tuning action: the evidence summary that justified it, the
  scope, an owner and a **review date**. Record why the scope is narrow. An untracked
  suppression becomes a permanent gap in coverage.
- Never tune away a rule family that maps to a technique with no other coverage. Check
  what else catches the behavior before you remove the only detection. A MITRE ATT&CK
  mapping helps here.
- Tune in your detection layer. Do not delete the upstream rules. A vendor update then
  cannot resurrect or orphan your changes silently.
- Re-run the 30-day analysis after the tuning. The scoping was wrong if the rule is still
  the top source of noise. Verify that the rule still fires on a known-good test if the
  rule went silent. A suppression wider than intended looks the same as success.

## When you triage an alert from a known-noisy rule

Do not dismiss the alert because of the reputation of the rule. Check whether *this* fire
matches the documented benign pattern. That pattern has the same source, the same
schedule and the same shape. Give a full look to a noisy rule that fires off its pattern.
A new source, an odd hour or a different target is off-pattern. Everyone else has stopped
looking at this rule.
