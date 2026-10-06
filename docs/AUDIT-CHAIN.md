# Audit chain breaks

Every audit record carries a `seq`, the `hash` of the previous record, and its own `hash`
over its content. That is the tamper evidence. An edit to the record of a decision makes
the recomputation fail. Verify the chain by hand at any time:

```bash
soc-ai audit verify              # the whole index
soc-ai audit verify --days 7     # a window
```

Exit code 0 means the chain is intact. Exit code 1 means a break. Exit code 2 means the
check could not run, because the index was unreachable or half-read. Never read exit
code 2 as either verdict.

The same check also runs on a schedule. It runs daily over the last 7 days by default.
`AUDIT_VERIFY_SCHEDULE_ENABLED`, `AUDIT_VERIFY_SCHEDULE_INTERVAL_HOURS` and
`AUDIT_VERIFY_DAYS` control it. A break reaches you in 3 ways: an audit record, the
notification webhook and a standing entry on the bell in the console. The webhook fires
only if you configured one.

## Types of break

"The chain is broken" covers several different facts. Each fact calls for a different
response. The verdict names which one:

| Type | What it means |
| --- | --- |
| `duplicate_seq` | Two or more records claim the same position. |
| `missing_seq` | A position in the run is absent. Someone deleted a record, or the record never landed. |
| `orphan_head` | The oldest record found does not start a chain. Everything before it is gone. |
| `relinked` | A record points at a predecessor that is not the one before it. |
| `content_altered` | A record no longer matches its own hash. Someone changed its content. |

`content_altered` means that someone edited a decision record. Each of the other types
can have an innocent cause. `duplicate_seq` usually does.

## Scale of a break

Every channel reports the first position that failed and the scale of the break. The
scale has these parts:

- the count of sequence numbers that more than one record claims
- the count of extra records at each of those positions
- the largest count of writers at one position
- the count of records that no longer match their own hash
- the timestamps of the oldest and the newest records involved

One collision and an afternoon of forks are different situations. The newest affected
timestamp tells you whether the damage is historical. If that timestamp
predates the fix, nothing has forked since.

## Concurrency fork or alteration

Two writers that append at the same moment leave two records at one position. Each record
is internally sound, because every field still hashes to the hash stored on it. An edit
does not survive that test. The verdict reports the difference:

- *"N records claim sequence S. Each record still matches its own hash, so the records were
  not altered. The cause is two writers that continued the chain from the same point"*. This
  verdict reports concurrency.
- *"N records claim sequence S. M of them no longer match their own hash, so the content was
  altered after it was written"*. This verdict reports that something rewrote a record.

To see the records yourself, list the duplicated positions in the index:

```
POST /soc-ai-audit-*/_search
{"size": 0,
 "query": {"bool": {"filter": [{"exists": {"field": "seq"}},
                               {"range": {"timestamp": {"gte": "now-7d"}}}]}},
 "aggs": {"dups": {"terms": {"field": "seq", "size": 200, "min_doc_count": 2}}}}
```

Then fetch the records at one of those positions. Compare their `timestamp`, `session_id`
and `prev_hash`. A shared `prev_hash` and two different sessions seconds apart is the
fork. One record rewritten in place is an alteration.

## The 2026-09 fork

A deployment that runs soc-ai from before the fix can carry duplicated positions. The
cause is a defect in the allocation of the chain head. The head lived in memory behind a
per-process lock, so a second writer could continue the chain from the same point. The
second writer was one of these:

- the logger of the nightly quality alarm
- a `soc-ai` command that cron ran beside the server
- a write whose acknowledgement never arrived

Each record involved is sound, and the position is claimed twice. soc-ai now claims the
sequence from Elasticsearch itself, so this cannot happen again. The records already
written stay as they are.

One check confirms this break. Every copy of every duplicated position still matches its
own hash. On the first deployment with this break, the check held for all 41 duplicated
positions. Some positions carried 3 or 4 records. No record showed an alteration.

### Response to a past fork

**Recommended: change nothing in the index. Let the damage age out of the daily check.**

The scheduled verification reads a window. The window is 7 days by default. After you
deploy the fix, no new duplicate can be created. The damaged stretch then ages out of the
window, and the daily check goes green on its own. soc-ai edits nothing and suppresses
nothing. Until the stretch ages out, every run reports the break.

That report is the true state, and soc-ai does not suppress it. A standing break is a
standing claim that the record cannot be trusted. A suppressed check would read as a
resolved break.

The full-index scan reports the historical break forever. That is correct, because the
trail does carry real damage. The verdict names the type of damage and the epoch that
holds it. The verdict also reports whether anything *after* the damage verified.
"Historical damage, current epoch sound" and "the current epoch is broken" then read
differently.

Before the damage ages out of the window, record a fingerprint of it. Keep the
fingerprint outside the audit index. The fingerprint holds the duplicated positions. For
each position it holds the `timestamp`, the `session_id` and the `hash` of every copy.
That written baseline lets you show later that a new duplicate is new.

**Rejected: an acknowledgement that stops the verification from reporting the break.** An
acknowledgement store is a switch that turns a tamper alarm off. The audit subsystem is
the one subsystem that must not have such a switch. A loosely keyed acknowledgement would
also cover damage that has not happened yet. The windowed schedule reaches the same
practical outcome, and it needs no switch.

### Dismissal of the bell entry

The bell entry is separate from the reporting, and you can dismiss it. The old entry used
the moment of detection as its key. Every run created a new entry, so nobody could clear
it. The result was a danger notification every morning until the damage aged out.

A dismissal covers one finding. The identity of a finding has three parts:

- the types of break present
- the timestamp of the newest record involved in any of them
- the count of records that no longer match their own hash

Dismiss a historical fork and it stays dismissed
while it is the same fork. Anything that breaks afterwards moves the newest timestamp. An
edited record adds a type that was not there. A second edited record moves the count.

Each of those changes is a different identity, and it arrives undismissed. The duplicate
counts are not part of the identity. A rolling window sheds old records daily, so an
identity that held the counts would re-raise the entry every morning.

A finding that includes an altered record offers no dismiss control at all, and "Clear
all" skips it. The reporting does not change in either case. The audit record and the
webhook fire on every run while the chain does not verify.

**Rejected: a fresh epoch that closes the damage behind a boundary.** The method works. A
new genesis record ends the damaged epoch, and everything after it verifies. The method
needs a command whose effect is "make the verification stop complaining". That command is
the same switch with a different name. A restart already starts an epoch if the head cannot
be recovered. Nothing else may ask for one.

**Never: delete or edit the duplicate records.** If you remove one copy, the
recomputation still fails at that position. The removal also destroys the evidence of
what happened. The audit index is append-only by intent. Treat it that way even if its
contents are inconvenient.
