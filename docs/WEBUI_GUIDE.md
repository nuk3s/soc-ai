# The soc-ai web console: operator guide

The soc-ai web console is a self-hosted triage console for Security Onion
alerts. It runs on the soc-ai host at `https://<host>:8443/app` behind
session authentication. This guide is a reference for the analyst screens and
the operator screens.

![An investigation in the console](img/screenshot-investigation.png)

> The front door is `/app`, the React console. It is the only web surface.
> Bare `/` redirects to it, and a sign-in lands you on the Dashboard. The old
> server-rendered `/ui` console is gone.

> **First run with a self-signed certificate:** the console serves HTTPS with a
> self-signed certificate. Visit the base URL once and accept the certificate
> warning before you sign in. If you do not, the browser refuses the connection
> with an opaque `TypeError: Failed to fetch`.

## Sign in

`/app/login` takes a username and a password. There are two roles:

- **analyst**: the full triage console, with alerts, hunts and investigations.
- **admin**: everything an analyst can do, and the config console at `/app/config`.

soc-ai creates the first admin, `admin`, at the first start. It writes the
generated password once to a locked-down sidecar file,
`<soc_ai_data_dir>/bootstrap-admin-password.txt`, with mode `0600`. It does not
write the password to the service log, because the service log is often readable
by the same people the credential must stay secret from. Read the file for your
deploy path:

```bash
# Docker deploy (default data dir /var/lib/soc-ai/data)
docker exec soc-ai cat /var/lib/soc-ai/data/bootstrap-admin-password.txt
# systemd / host-venv deploy
cat "$SOC_AI_DATA_DIR/bootstrap-admin-password.txt"
```

soc-ai logs the plaintext password only if the data directory was not writable
at startup. Read it then with `journalctl -u soc-ai | grep -i password` or with
`docker compose logs soc-ai | grep -i password`. On the normal path the log holds
a pointer line and no password.

Change the password after the first login. Use Config → Users → reset password.
Then delete the sidecar file, because nothing needs it and the volume must not
keep it.

## Navigation

The sidebar has two groups. Investigate holds Dashboard, Alerts,
Investigations, Hosts, Notifications and Hunts. It stays open, because most of a
shift runs in that loop. Operate holds the Operate hub, Runbooks, Backtest and
Config. It starts collapsed, because you reach those screens once a shift or
once a week.

Click the Operate heading to expand the group, or go straight to one of its
screens. Operate expands itself if the current page lives inside it, so no closed
group hides your screen.

## Dashboard (`/app/dashboard`)

A sign-in lands you here. The Dashboard shows what the grid does now and what
soc-ai made of it. A box on the screen answers questions about either one.

### Setup health

A persistent card sits at the top of the side column on the Dashboard.
Persistent means the card never hides itself. The panels below it do hide if
they have nothing to review.

A clean card is one compact line, "All checks passing," with the time since that
check. On a degraded card an admin sees each failing or warned check by name,
with its detail and a hint if one exists. The card also carries a Re-check
button. Re-check forces a fresh check past the 10 minute cache, for the case
where the problem is already fixed. A re-check that itself fails says so
("The re-check failed. Try again.") and leaves the last known-good rows on screen. An
analyst sees a count and a pointer to Config → Diagnostics, and never the row
names.

The card reads the same doctor checks that Wave 1 added, without the model
fitness probe. That probe can take a few minutes and is too slow for a dashboard
poll. Fitness stays on the model battery in Config.

### Ask soc-ai

A chat answers on the spot. It uses the same read tools as the investigation chat
and takes about as long. Ask it which datasets you have, which rule was noisiest
overnight, or what a host did.

- **One rolling thread per analyst:** the thread survives navigation and
  restarts. Two analysts do not see each other's questions. Clear discards
  your thread.
- **It proposes a hunt and never starts one.** If an answer needs a sweep across
  many hosts or a long window, the turn returns a Start hunt card. The card
  holds an objective that the agent wrote from what it read, and a line on what
  the sweep would settle. You see both before you decide. Press Start hunt to
  run that objective and to open the running hunt.
- **What it cannot do:** it runs no write action, it changes no verdict, and it
  never acknowledges or escalates an alert. It has read tools only.
- **How to turn it off:** open Config → Models & Reasoning → Agent →
  *Dashboard chat*. The setting is hot, so it takes effect with no restart. The
  box then disappears from the Dashboard instead of failing under a question.

    Turn it off if the triage backlog already saturates a shared analyst model.
    The assistant sits on the screen that everyone lands on, so it is the easiest
    place in the product to spend inference capacity by accident. Nothing runs
    while nobody types, and the stored threads survive the change.

### Outcome and severity tiles

The verdict tiles count alert groups over the range that you picked. The four
settled verdicts open the Investigations list filtered to that verdict.
Untriaged opens `/app/alerts` instead, because a group that nobody
investigated has no investigation row to show. That link carries your range and
un-hides acknowledged groups, so the destination holds what the tile counted.

The severity bars open the same list, filtered to that severity.

### Verdict quality

This card holds the trend from the nightly micro-eval. See
[DOCKER.md](DOCKER.md#the-nightly-quality-micro-eval-schedule-it-in-app-or-from-host-cron)
for how to schedule it. The badge names the instrument that measured each point.
An oracle-graded point carries an agreement rate. A locally measured point
carries fallback and error rates. soc-ai never blends the two on one line.

Under the run count, one line dates the newest point and the last attempt. If a
run wrote nothing, the line carries the reason from that run. The usual reason is
a grid with no eligible alerts. With the in-app nightly on, a point older than 2
scheduled runs gets an amber "no point in Nd" marker, so last month's point
cannot pass as last night's. The attempt half lives in the memory of the server
process and clears on a restart.

Under the headline rate sits the grade composition, "3 agree · 2 partial". A
partial critique reads "right verdict, thin reasoning". It costs the rate as much
as a flat disagreement. A bare 60% cannot tell you which one you got. A partial
critique asks you to tighten a prompt. A disagreement asks you to chase a
regression.

If a point alarms, the card prints the path to the eval bundle of that run. That
directory holds the oracle critiques. The critiques are the only evidence for or
against the alarm. The card prints a path on the soc-ai host and not a link. Read
it with `docker exec soc-ai cat <path>/report.md`.

## Triage console (`/app/alerts`)

![The alert queue with AI verdicts inline](img/screenshot-alerts.png)

The main pane holds alert groups in the Security Onion style. soc-ai groups them
by rule and shows the newest first.

- **Filter and sort:** the controls are the time range, the severity, the sort
  order, and a free-text OQL box.
- **Expand a group:** click a group row to load its recent events.
- **Hunt:** start an AI investigation for an alert or a group. A hunt runs as a
  background task. It survives a closed drawer, it runs beside other hunts, and
  soc-ai records every run. Live progress streams into the drawer: the phase, the
  elapsed time, the tools called and the enrichments.
- **Verdict badges:** each group and each alert shows its latest investigation
  verdict: true_positive, false_positive, needs_more_info, running or error. A
  dashed badge with an "inherited" tooltip means the verdict came from a similar
  alert. A similar alert has the same rule and the same src/dst pair, inside the
  inherit window. The badge appears at the individual level and at the group
  level.
- **Permalinks:** every investigation has a URL that you can share,
  `/app/investigation/{id}`. soc-ai creates the URL while the hunt still runs.
- **⚡ Auto-triage:** sweep the current view and hunt every alert that nothing
  covers yet. Use the severity checkboxes to choose the severities it acts on.
  The default is critical and high. `auto_triage_max_targets` caps a single
  run at 25 targets, so one click cannot start dozens of hunts. The next run
  picks up the uncovered overflow. The status chip shows the hunted, total and
  skipped counts with the chosen severities.

## Investigations (`/app/investigations`)

![The investigations list with verdicts and confidence](img/screenshot-investigations.png)

The screen lists every past investigation and every in-flight one, with a
permalink on each. A row carries the verdict, the rule, the time and the person
who started it. Use the list to review history and to find an earlier verdict.

**Stale-run reaping:** soc-ai cleans up an investigation that a crash, a restart
or a network drop left in `running`. At startup it marks every orphaned `running`
row as `error`, because the worker for that row died with the previous process. A
periodic sweep then marks any run that stays `running` past
`investigation_reaper_minutes`. That setting defaults to 30. You never have to
clear an orphan by hand.

## Hunts (`/app/hunts`)

This screen holds the hunting pipeline in order, top to bottom: the Needs you
strip, Analytic hits, Leads, Hunts and the New hunt drawer. A second tab,
Analytics, holds the analytic catalog and the Lead quality block.

The Needs-you strip counts the two things that wait on you: the unread shadow
hits, and the leads that need a decision. Each link jumps to the block that holds
them, with the filter set. The sidebar badge on the Hunts item shows the same
count.

[docs/HUNTING.md](HUNTING.md) is the full guide. It covers the five nouns, how a
hit becomes a lead and a lead becomes a hunt, the shadow week, the settings, the
command line and the API routes.

## Hosts (`/app/hosts`)

This screen holds what soc-ai concluded about each machine on your network, and
what you declared instead. It has two screens.

**The list** at `/app/hosts` gives one row per host. A row holds the address, the
role, the hostname, the criticality, the number of fields in each lane, the event
count and the last-seen time.

Search matches an address or a hostname. The Role select narrows to one role. The
Lane select narrows to the hosts a human has touched, "declared", or to the hosts
nobody has touched, "inferred only". Sort by last seen, first seen, stalest,
busiest or address. Click a row to open the host.

Four counts of the whole network sit above the table. The panel header below them
counts what your filters match. The four counts never follow the filters.

- **All hosts** carries how many hosts have no clean build. A host has no clean
  build if no sweep reached it, or if the last attempt errored.
- **Named** counts the hosts whose name the resolver asserts, so it agrees with
  the Hostname column and not with the stored value.
- **Reporting** counts the hosts where an agent on the machine reports about
  itself. It is the only place the console shows the progress of host-log
  shipping.
- **Needs review** counts the open disagreements. It is the same number the queue
  carries.

Under the four counts sits the age of the numbers, for example "Last swept 4h
ago". A note appears while automatic sweeps are off, because nothing else
refreshes the numbers. A count that soc-ai could not read shows a dash and never
a zero.

**The host page** at `/app/hosts/<ip>` holds these parts, top to bottom:

- **The banner** names the machine. It uses the hostname if any source knows one,
  and the address if none does. It also carries the role, the source of that
  role, the OS, the criticality, and whether the machine reports on itself. "no
  agent data" means the network supplied every field below, and the host told
  soc-ai nothing.
- **Four counters** cover the services the host answers on, the accounts that
  authenticated, the connection volume, and the alerts over 7 days. An
  `all alerts · 7d` link sits under the alert count. The alerts console filters
  by time, severity and verdict, and never by host. The link therefore opens on
  the detections of the whole network over those days, with this host's
  detections among them.
- **Peers, volume and users** over the window that you pick, 24h or 7d.
- **12 field cards**, one for each dossier field.

An internal address opens here from anywhere in the console. Alert rows, the peer
graph and old `/entity/<ip>` links all redirect to it. An external address still
opens the Entity screen, because the sweep builds hosts inside your
`internal_cidrs` only.

### The two lanes

Every field holds up to 2 answers, and one answer never overwrites the other:

- **inferred** is what the sweep concluded. It carries a provenance rung that
  names the type of signal, a confidence, and the evidence under **Why?**.
- **operator** is what you declared. soc-ai stores it in its own columns, so no
  rebuild can overwrite it.

soc-ai stores no "current value". The page resolves each field as it reads it. It
takes the operator lane first. It then takes the inferred value if that value
clears the confidence floor `dossier_min_confidence` and a re-confirmation falls
inside the freshness window `dossier_staleness_hours`. A field that resolves to
nothing names the test it failed, because "no signal yet" and "observed but too
weak to assert" are different answers.

### Declare a value, accept one, or keep yours

On any field card:

- **Declare a value** writes your value and an optional note. The card records
  your name and shows the value back. The button reads Edit declaration once a
  declaration exists. Three fields hold structured values and take JSON:
  services offered, activity profile and management plane.
- **Hand back to the builder** deletes your override, so the answer from the
  sweep stands again.
- If the sweep disagrees with a value that you declared, the card says so and
  names the type of disagreement. The evidence points elsewhere. The evidence it
  rested on is gone. The address appears to have rebound to a different machine.
  Then you have two choices:
  - **Accept inference** drops your override and takes the answer from the sweep.
    Confirm it with Discard my value.
  - **Keep mine** keeps your value and stops the question for a period. The
    period doubles each time you press it, up to 90 days.

An analyst sees all of this as read-only. Only an admin can declare a value,
accept one, keep one, or run a sweep.

A disagreement must earn its place on the screen. soc-ai prompts you after 3
consecutive builds disagree. `dossier_conflict_min_observations` sets that count.
It prompts at most once per field per 14 days.
`dossier_conflict_prompt_interval_hours` sets that interval. One build that
agrees resets the count.

### Running the sweep

The scheduled sweep is off by default. `dossier_schedule_enabled` controls it. A
sweep covers hundreds of hosts and runs several Elasticsearch queries for
each one, so you decide when it runs. The Hosts screen stays empty until the
sweep runs once. An empty screen means the sweep has not run. It does not mean
the network has no hosts on it.

- **Rebuild now** on the Hosts screen runs a sweep in the background and reports
  what it built. Only an admin sees the button.
- Config → Host dossier turns on the schedule and sets its interval. Every
  setting there is hot, so it needs no restart and the next sweep reads it.

## Operate hub (`/app/operate`)

![The Operate hub: the Analytics panel, with its sweep status line and one row per analytic, above the trust-instrument cards](img/screenshot-operate.png)

The hub maps the trust instruments of the console. It holds 6 cards. Each card
names one thing that soc-ai can prove and links to the screen where you prove it.
The cards carry no live status of their own. The setup-health card on the
Dashboard carries that status.

The one live panel on the page sits above the cards. It is the Hunt catalog.
The declarative hunt catalog runs unattended, as a scheduler sweep with no model
call. If nothing fires, it leaves no trace anywhere else in the console. Check
here that it runs.

The status line says whether the sweeps are on, how often they run, how far back
they look, and when the last one ran. With the sweeps off the line still shows
the other three, because a `soc-ai spec-sweep` run by hand leaves the same trail with
the same look-back. The interval then reads "once enabled", because that is the
schedule the flag would start. The line also says how to turn the sweeps on.

A legend above the rows says that the counts cover the last 24 hours. Each spec
then gets a row. The row holds the level of the spec, the number of times it
fired in that window, and how many of those hits were fresh or already handled.
It also holds the last sweep time, the last firing time, and 3 markers.

**shadow** is amber and carries a count. It means some sweeps in the window were
`spec-sweep --shadow` runs. A shadow sweep counts what it would have reported as
fresh, and never as fired. On a marked row, "fired 0, fresh 2" is the shadow
reporting. The spec is not withholding a hit. A condition that a shadow sweep saw
is fresh again to the live sweep that follows, so the fresh count is per sweep and
not per condition.

**blind** is amber. It means the precondition of the spec matched nothing on the
last sweep. The telemetry that the spec reads is absent. An absent telemetry
plane is not a clean grid.

**error** is red. It means the sweep itself broke on that spec. Hover over the
marker for the reason.

A spec that the loop never reached reads "not yet swept" and not a row of zeros.
A row of zeros would say "swept, saw nothing". The panel refreshes itself every 5
minutes.

- **Model fitness** proves the analyst model is fit before triage depends on it.
  It links to Config → Agent.
- **Verdict quality** proves the verdicts held up. It carries the nightly
  micro-eval trend and links to Config → Quality.
- **Audit chain** proves the tamper-evident record is intact. It links to
  Config → Diagnostics, and that screen carries a Verify audit chain button.
  Press it and it reports one of 5 outcomes:
  - intact. A green check. soc-ai verified the records.
  - partial verification. Amber. The scan stopped at the start of the chain and
    did not cover the whole chain.
  - intact within N epochs. Amber. Every restart has its own verified trail, but
    soc-ai cannot link one restart boundary to another. This outcome stops short
    of "one unbroken chain". Read the paragraph below.
  - tampered. Red. The message names the sequence number and the restart it broke
    in.
  - couldn't verify. Amber. The console could not read the chain at all.

  Only a full, single-epoch, uncapped scan gets the green check.

  A chain that spans more than one epoch is not proof of a problem. A process
  restart legitimately cannot link back to what came before it. A fixed bug once
  turned restarts into 134 epochs, and the Diagnostics panel holds the specifics.
  The console names that state plainly. It reports no tamper at a boundary.
- **Backtest** replays history against the current pipeline. It links to
  Backtest.
- **Diagnostics** is the doctor's view from inside the app. It links to
  Config → Diagnostics.
- **Runbooks** holds the procedures that ground every verdict. It links to
  Runbooks.

## Runbooks (`/app/runbooks`)

This screen is the authoring space for your team's own triage guidance. The
investigation agent searches this corpus with its `lookup_runbook` tool and cites
it in a verdict. An analyst can read a runbook. Only an admin can create, edit or
delete one.

- **Editor**: the title, the markdown content, the tags, and the linked rules. A
  write and preview toggle sits on the content field. A linked rule is a
  detection rule name or UUID that this runbook applies to. A rule link is the
  strongest retrieval signal, so this runbook wins if that rule fires.
- **Import files…**: import your existing `.md` procedures from your wiki or repo
  in bulk. The optional YAML front-matter fields are `title:`, `tags:` and
  `rules:`. The parser is lenient. It ignores malformed metadata and still
  imports the body. A missing title falls back to the first `#` heading, then to
  the filename.
- **Load starter pack**: seed 10 generic, vendor-neutral SOC runbooks from
  `runbooks/starter-pack/` in the repo. The action is idempotent by title, so it
  never duplicates or overwrites a runbook that you already have. Run it again
  after an upgrade. Edit the seeded copies as you want, because your edits stay.
- If you configure the optional Retrieval (RAG) embeddings tier, each row shows
  its embed status: `embedded`, `not embedded` or `stale embedding`. The
  catch-up pass lives at Config → Retrieval → "Re-embed runbooks".

The Config page keeps a compact summary next to the Retrieval settings. The
summary holds a count and a manage link.

## Config console (`/app/config`, admin only)

This screen configures soc-ai from the console. A non-admin who reaches it gets a
clean 403 and no login loop.

### The day-1 view

![The Config day-1 view: a section's day-1 settings up front, the rest collapsed behind an Advanced fold](img/screenshot-config-day1.png)

Config opens on 8 decisions and not on the full list. The decisions are the
analyst model, the events index pattern, the alerts query, the 4 auto-triage
settings, and the notifications master toggle. The 4 auto-triage settings are the
schedule switch, the interval, the per-run target cap and the minimum severity.
setup.sh already asks about most of them at install time, or they decide whether
the console shows anything at all. The notifications toggle is the one opt-in
outbound-egress decision that deserves a day-one look.

Everything else in a section folds behind an Advanced (N) reveal, collapsed by
default. A section with no day-1 setting in it starts with its Advanced fold
open, so it does not read as empty.

Settings search still finds every setting, day-1 or behind Advanced. A click on a
result opens the section of the setting. It also opens the Advanced fold if the
setting lives there.

### Settings sections: Oracle, Agent and PCAP

These sections hold editable, non-secret runtime settings. Each row shows a source
badge:

- `env` means the value comes from `.env`. This is the default.
- `db` means an admin override is set. soc-ai stores it in the `config_overrides`
  table.

soc-ai hot-applies a change. A save writes the override and changes the live
settings, so the change takes effect on the next investigation with no restart.
soc-ai re-applies the overrides at startup, so they survive a restart.
These keys are editable:

- **Oracle**: `oracle_enabled`, `oracle_model`, and the escalation thresholds
  `oracle_escalate_*`. `oracle_enabled` turns on the cloud frontier-model second
  opinion, and soc-ai sanitizes everything that it sends there. This section is
  the home of the Oracle toggle.
- **Agent**: `investigate_when_unsure` and `general_chat_enabled`.
  `investigate_when_unsure` runs the bounded investigation loop if evidence does
  not back the fast round-1 verdict. `general_chat_enabled` controls the Ask
  soc-ai box on the Dashboard, and it is on by default.
- **PCAP**: `pcap_enabled` fetches and decodes raw packets on demand from the
  Suricata pcap ring on the Security Onion sensor.

### Connection (Danger Zone)

The connection details for the LLM gateway, Security Onion and Elasticsearch
default to the values in `.env` on the host. soc-ai masks a secret as `••••••`
and never echoes it back. These fields are not read-only. The Danger Zone panel
lets an admin override the connection identity and the credentials: `so_host`,
`so_username`, `so_password`, `so_verify_ssl`, the SSH-pivot fields
`so_ssh_host`, `so_ssh_user` and `so_ssh_key`, `es_hosts`, `es_username`,
`es_password`, `es_verify_ssl`, `litellm_base_url`, `litellm_api_key`, and
`internal_cidrs`.

Each write needs a typed confirmation. Retype the key name to confirm it. soc-ai
encrypts the value at rest with Fernet, so this panel needs `CONFIG_SECRET_KEY`.
These settings repoint clients that soc-ai builds at startup, so they are not
hot. An override takes effect at the next restart.

An admin session can repoint the gateway or the grid from here. That sends the
enriched context of every alert to a different endpoint. Treat the admin role and
`/app/config` as trust-sensitive.

- **Test connection** buttons probe the LiteLLM gateway with `GET /v1/models` and
  report the model count. A second button probes Elasticsearch with `ping` and
  reports the cluster and the version. Each result is an inline ✓ or ✗ and holds
  no secret.

### API keys

A separate API keys panel holds the enrichment-provider secrets:
`shodan_api_key`, `greynoise_api_key`, `misp_api_key`, `maxmind_license_key`,
`abuse_ch_auth_key`, and `crawl4ai_token`. The panel renders next to Data sources
and not in the normal settings groups. These keys are write-only. soc-ai
encrypts each one at rest with Fernet and never renders it back. soc-ai
hot-applies them and reads each one fresh on every enrichment call, so they need
no restart and no typed confirmation. They also need `CONFIG_SECRET_KEY` to
persist.

### Users

Add a user with a username, a password of 8 characters or more, and a role. You
can enable a user, disable one, reset a password, and change a role. soc-ai shows
a reset password once. Two guards apply. You cannot disable your own account. You
cannot disable or demote the last enabled admin.

### API tokens

Mint an API token here, and revoke one here. soc-ai shows the `scai_…` value once
at creation, so copy it then. soc-ai stores only the hash of the token. A token
gives programmatic API access for automation and integrations after you
enable `API_AUTH_REQUIRED`.

## Safety model (recap)

Every read tool that the agent uses is read-only. A write tool changes Security
Onion state. The write tools acknowledge an alert, escalate it to a
case, and add a comment. The agent can only *recommend* a write tool. You execute
it with a click from the report, and soc-ai audits every execution.

The one bounded exception is the confidence-gated auto-acknowledge for a
low-stakes false positive. `auto_ack_fp_enabled` controls it. It never touches a
critical alert or a malware-class alert. It never fires on a verdict that the run
retrieved nothing for. See [SAFETY_MODEL.md](SAFETY_MODEL.md) and the agent
capability surface in [AGENT_TOOLS.md](AGENT_TOOLS.md).
