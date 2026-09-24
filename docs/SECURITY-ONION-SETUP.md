# Security Onion account requirements

soc-ai connects to a Security Onion 3.0 grid in 3 distinct ways, and each way needs a
*different* privilege. SO means Security Onion in this document. A wrong privilege is the
largest single source of install-time troubleshooting. This document states what the
account behind each path needs.

| Path | What it does | How it authenticates | Privilege needed |
|------|--------------|----------------------|------------------|
| **Read / triage** | Pulls alerts, events, cases, detections and playbooks | Elasticsearch basic auth with `ES_USERNAME` and `ES_PASSWORD` | `read` and `view_index_metadata` on the events indices and the SO indices. The stock `analyst` role covers this. |
| **Write-back** | ack / escalate-to-case / add-comment | SO web API with the SO login. The login uses a Kratos session cookie. | A real SO analyst login. It needs no ES write privilege. |
| **Audit log** | Tamper-evident forensic record of every action | Elasticsearch basic auth. This is the same identity as Read. | `write` and index-create on `soc-ai-audit-*`. This is NOT in the stock `analyst` role. |
| **PCAP (optional)** | Pulls full packet captures from a sensor | SSH to the sensor with a de-privileged key | A sensor SSH key. It is not an SO role and not an ES role. |

The rest of this document explains each row. The network comes first.

---

## 0. Pinhole soc-ai's IP in Security Onion's firewall

soc-ai's host must *reach* the grid before any credential matters. Security Onion
firewalls all of its services by default. A host outside the allow-list cannot open a
socket to Elasticsearch or to the web API. A blocked connection looks like a wrong
password or an unreliable network. Most operators meet this problem first.

Add soc-ai's source IP to SO's firewall so it can reach:

- **Elasticsearch REST, TCP 9200.** This port carries the read and triage path and the
  audit write. It is the important one, because ES 9200 is not open to analyst
  workstations by default.
- **The web API, TCP 443.** This port carries ack, escalate-to-case and comment.
- **A sensor over SSH, TCP 22**, only if you enable PCAP fetch.

**Allow-list the host IP under Docker.** The default Docker bridge network NATs the
container's traffic out of the Docker host's address, so SO sees the Docker host's IP.
Pinhole that address. An internal `172.x` container address does not work. A
host-networked deployment uses the host IP anyway. This rule holds for both methods
below.

**Recommended: use the SOC web UI.** On the SO manager, open Administration →
Configuration → Firewall. Pick a host group that may reach Elasticsearch REST and the
analyst and web ports, or add one. On a stock SO 3.0 grid the `analyst` host group
covers the web UI. A normal analyst workstation lacks access to
Elasticsearch on `:9200`, and soc-ai needs that access, so confirm that your group opens
`9200`. Add soc-ai's source IP to that group and apply the change. This path is
supported, and it survives an upgrade.

An equivalent CLI exists. The host-group semantics changed across SO versions, so the
exact group name is grid-specific. Prefer the UI above unless you already know the host
groups of your grid.

```bash
# <hostgroup> is grid-specific — list yours first, then add the IP to one that
# opens Elasticsearch REST (9200) and the analyst/web ports:
sudo so-firewall list-hostgroups       # inspect the available groups (newer SO builds)
sudo so-firewall includehost <hostgroup> <soc-ai-host-ip>
sudo so-firewall apply
```

`list-hostgroups` is missing on SO 3.0.x. `so-firewall help` there lists only
`help|apply|includehost|removehost|addhostgroup`. Use the web UI above, or read the group
names from `/opt/so/saltstack/local/pillar/firewall/soc_firewall.sls` and
`minions/*.sls`.

**Symptom if you skip this step:** the first hunt stops and then fails with a connection
*timeout* or "connection refused" against `…:9200`. The startup ES health check fails the
same way. The credentials are correct in this case. Wrong credentials give a fast 401.
A *timeout* points at the firewall.

---

## 1. Reads go through Elasticsearch basic auth

soc-ai reads alerts and enrichment context from Elasticsearch with the `ES_USERNAME` and
`ES_PASSWORD` basic-auth credentials in `.env`. These credentials are normally your SO
analyst login. The account needs:

- `read` + `view_index_metadata` on the events pattern. SO 3.x stores the Suricata and
  Zeek events and alerts in `logs-*` data streams. The pattern is
  `EVENTS_INDEX_PATTERN=logs-*` on a single-node grid. On a multi-node or distributed
  deployment the pattern is `*:logs-*` for cross-cluster search. Set the pattern in
  `.env`. `setup.sh` detects the cluster prefix and writes the concrete value. The old
  `*:so-*` form is wrong, because it matches the old-style `so-*` admin indices and not
  the `logs-*` data streams, so the alerts console comes up empty.

  **Leave it as `logs-*`.** The grant must cover every data stream that soc-ai reads, and
  the pattern must cover them too. Some of those data streams do not belong to Security
  Onion. Read the namespace note under Troubleshooting before you narrow the pattern.
- `read` + `view_index_metadata` on the cases, detections and playbooks patterns. On a
  single-node grid these are `so-case*`, `so-detection*` and `so-playbook*`. On a
  multi-node grid, prefix each one with `*:`, for example `*:so-case*`.

The stock SO `analyst` role already grants all of these reads. A normal analyst account
triages with no extra grant.

---

## 2. Write-back goes through the SO *web API*

Acknowledging an alert, escalating it to a case and adding a case comment do not write
to Elasticsearch directly. They go through Security Onion's own web API, for example
`POST /api/events/ack`. The SO web UI calls that same endpoint if you click the bell
icon. Your SO login authenticates the call through a Kratos session cookie.

Two consequences:

- You need no Elasticsearch *write* privilege for ack, escalate or comment. A
  read-capable analyst login is enough. SO enforces the write authorization on its own
  side.
- You do need a real, working SO analyst login. You also need the correct Kratos auth
  prefix. SO 3.0 mounts Kratos under `/auth/...`, so leave the default:

  ```ini
  SO_KRATOS_PATH_PREFIX=/auth
  ```

  Older SO releases used `/self-service/...`. The `/auth` default matches SO 3.0.

This path replaces the older, paywalled SO Connect API. The web path is always available
on an OSS grid.

### Security Onion 3.3 needs the browser login flow

Kratos offers two login flows. The API flow returns a session token, which the caller
sends in an `X-Session-Token` header. The browser flow returns a login page document
with a CSRF token, and it sets an `ory_kratos_session` cookie that the caller sends on
every later request.

Security Onion 3.3 stopped accepting the API-flow session token. The login itself still
succeeds, so nothing looks wrong until the first write. Then SOC refuses the session on
every call with HTTP 401 and the reason "Missing or invalid authorization header for
bearer token". Acknowledge, escalate, case creation and case comments all fail that way.
Reads keep working, because they read Elasticsearch with the `ES_USERNAME` credential.

soc-ai now logs in the way the Security Onion web interface does. It reads the login flow
document, submits the credentials with the flow's CSRF token, and lets its cookie jar
carry the session cookie. The srv-token handling and `SO_KRATOS_PATH_PREFIX` are
unchanged.

One build works on every Security Onion release. The setting Security Onion login flow
(`so_login_flow`) takes three values:

| Value | What it does |
|---|---|
| `auto` | The default. Run the browser flow. Fall back to the API flow if the browser flow cannot complete. |
| `browser` | Force the browser flow, with no fallback. SO 3.3 and later need it. |
| `api` | Force the API flow, with no fallback. SO 2.4 and SO 3.0 to 3.2 accept it. |

```ini
SO_LOGIN_FLOW=auto
```

`auto` falls back for four reasons: the browser endpoint is absent, the flow document
holds no CSRF token, the login answers a 4xx that is not a credential rejection, or SOC
refuses the cookie session on `/api/info` while it accepts the same account's API-flow
session. A wrong password never causes the fallback, because the same password fails on
both flows. soc-ai keeps the flow that worked for the life of the process, so a fallback
costs one extra login. The setting applies at the next restart, and one log line names
the flow at the first login that Security Onion accepts.

`soc-ai doctor` names the flow in use on its `security onion` PASS line. The header status
indicator in the console says the same.

---

## 3. The audit log needs an Elasticsearch write grant

This is the requirement that costs people an afternoon.

soc-ai keeps a tamper-evident audit log. The log is a hash-chained record of every
action that soc-ai takes. soc-ai writes it directly to Elasticsearch, into daily indices
named `soc-ai-audit-YYYY.MM.DD`. The stock SO `analyst` role does not grant create or
write on that index pattern. The first audit write then fails with a 403:

```
action [indices:admin/auto_create] is unauthorized for user [...] with roles [analyst]
on indices [soc-ai-audit-2026.06.25], this action is granted by the index privileges
[auto_configure,create_index,manage,all]
```

The audit write authenticates as the Elasticsearch basic-auth identity in `ES_USERNAME`.
It does not use the Kratos web login. Grant the `soc-ai-audit-*` privilege to that ES
account.

### Why this breaks ack and escalate

soc-ai ships with `AUDIT_FAIL_CLOSED=true`. That is the 1.x default. Under fail-closed,
soc-ai writes the audit record for a *mutating* action before the action proceeds. If the
audit write returns a 403, soc-ai aborts the mutating action. Ack, escalate-to-case and
add-comment then fail silently. You lose the action as well as its forensic record.

Read-only triage still works. soc-ai absorbs an audit failure on a read by design. An
investigation still completes, and it loses its audit entries.

### Two fixes

**Recommended: least privilege.** Run the bundled grant script on the SO manager node.
It adds the `soc-ai-audit-*` index privileges to the `analyst` role. Those
privileges are `auto_configure`, `create_index`, `index`, `read`, `view_index_metadata`
and `write`. The script also creates today's audit index.

```bash
# From the soc-ai repo root (so the relative script path resolves), piping the
# script over SSH to the SO manager:
ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh

# Or interactively on the SO box itself (copy the script over first — e.g.
# `scp scripts/setup-audit-index.sh <admin>@<so-manager>:` , or on a Docker
# deploy `docker compose cp soc-ai:/opt/soc-ai/scripts/setup-audit-index.sh .`):
sudo bash setup-audit-index.sh
```

The script uses `so-elasticsearch-query`. That command authenticates against the local ES
through the root-only `curl.config`, so the script must run on the manager as root or
under sudo. After the script runs, test an ack or an escalate again. The 403 disappears
immediately, and the action goes through.

**The trap: the Superuser toggle.** SO does not expose Elasticsearch role editing in its
web UI. People then use the only control that is exposed. They set the SO user to
Superuser in SOC → Administration → Users. This works, because superuser implies the
`all` index privilege. It is also a large over-grant on a shared cluster, because
that account can then read and write *everything* in Elasticsearch. Prefer the
least-privilege script.

If you use the toggle, allow for the ~15-minute Salt propagation lag. Salt pushes the
role change, so the change is not effective at the moment you set the switch. Set the
switch, then wait ~15 minutes before you test again. An immediate retry looks like a
toggle that did nothing. That is the most common false "it's still broken" report.

---

## 4. PCAP fetch uses SSH

PCAP fetch is optional, and it uses no ES role and no SO role. If you enable full
packet-capture retrieval with `PCAP_ENABLED=true`, soc-ai connects to a sensor over SSH
and pulls Suricata's ring-buffer PCAP. It uses a separate, de-privileged sensor SSH key in
`SO_SSH_KEY`, pointed at `SO_SSH_HOST`. That key is not an SO web login and not an
Elasticsearch role. PCAP is off by default. See [DOCKER.md](DOCKER.md) for the key
mount.

---

## Two deployment shapes

### Minimal read-only deploy

This deploy triages only. It has no ack, no escalate and no audit log. The stock
`analyst` account is enough. You need no grant script and no superuser toggle.

- `ES_USERNAME` and `ES_PASSWORD` hold your SO analyst login.
- Nothing else is required. You get full investigations and recommendations. The UI shows
  the recommended write actions, and you apply them by hand in SO.
- `AUDIT_FAIL_CLOSED=false` removes the audit 403 noise from the logs, and it grants
  nothing. Under that setting a failed audit write no longer blocks a write. Use it only
  on a read-only deploy.

### Full deploy with write-back and audit

To let soc-ai ack, escalate and comment, and to keep a forensic trail:

1. Put a real SO analyst login in `.env` under `SO_USERNAME` and `SO_PASSWORD`. Set
   `SO_KRATOS_PATH_PREFIX=/auth`.
2. Put the same account in `ES_USERNAME` and `ES_PASSWORD` for the reads and the audit
   writes.
3. Run `scripts/setup-audit-index.sh` on the SO manager to grant the
   `soc-ai-audit-*` write privilege. Run it even though `analyst` covers the reads,
   because the audit index is the one grant that `analyst` lacks.

---

## Troubleshooting

> **soc-ai cannot see logs that exist in SO.** The symptoms are an auth or syslog "not
> found", and a hunt that contradicts an investigation.
>
> Check `EVENTS_INDEX_PATTERN`. If it names `.ds-` backing indices, it is probably too
> narrow.
>
> SO 3.x keeps events in Elasticsearch data streams. The documents live in hidden backing
> indices named `.ds-<stream>-<date>-<generation>`. One example is
> `.ds-logs-system.auth-default-2026.07.17-000004`. A search pattern never has to name
> those indices. `logs-*` matches the *data-stream* name, and Elasticsearch expands it to
> every backing index under that stream.
>
> The leading dot matters. A dot-prefixed index is hidden, so a plain `logs-*` never
> matches a `.ds-…` name directly. It does not need to.
>
> If you write the pattern against the backing indices, you must name the Elastic Agent
> namespace segment yourself:
>
> | fragment | covers |
> |---|---|
> | `.ds-logs-*-so-*` | Security Onion's own integrations: suricata, zeek, soc, kratos, strelka, import |
> | `.ds-logs-*-default-*` | Elastic's stock integrations: system.auth, system.syslog, endpoint, winlog |
> | `logs-synth-*` | soc-ai's synthetic and eval data |
>
> Any fragment you leave off is invisible, and nothing tells you. On 2026-08-05 a
> production install ran `.ds-logs-*-so-*,logs-synth-*`. It had no access to ~117K
> `system.auth` records and ~48M `system.syslog` records. Every query succeeded. The
> pattern still matched 139M documents, so `soc-ai doctor` stayed green at the time. An
> investigation reached the wrong conclusion, because the login evidence was absent.
>
> The doctor's index pattern coverage check now catches this exact shape by name. It
> reports alerts present and zero auth or syslog records under the same pattern. The count
> below is still the fastest hand check.
>
> If you are upgrading and you narrowed this value before, widen it now. Set
> `EVENTS_INDEX_PATTERN=logs-*` in `.env` and restart. You can also set it live in
> Config → Queries → Events index pattern. The live change applies to the next query.
> Confirm the result with a count that includes the `default` namespace:
>
> ```bash
> curl -sk -u "$ES_USERNAME:$ES_PASSWORD" -XPOST \
>   "$ES_HOSTS/logs-*/_search?ignore_unavailable=true" \
>   -H 'Content-Type: application/json' \
>   -d '{"size":0,"track_total_hits":true,"query":{"term":{"event.dataset":"system.auth"}}}'
> ```
>
> A non-zero `hits.total.value` means that the auth stream is in scope. A zero on a grid
> that ships auth logs means that the stream is out of scope.
>
> Pin the namespaces only if you have a reason to exclude data. If you pin them, keep
> `.ds-logs-*-default-*` in the list.

> **`action [indices:admin/auto_create] is unauthorized for user [...] with roles [analyst] on indices [soc-ai-audit-…]`**
>
> Elasticsearch rejects the audit-log write. `AUDIT_FAIL_CLOSED=true`, so this also aborts
> ack, escalate and comment. Those actions appear to do nothing.
>
> **Fix A, recommended:** run `scripts/setup-audit-index.sh` on the SO manager. It grants
> the `soc-ai-audit-*` privileges to the `analyst` role. The grant is effective
> immediately.
>
> **Fix B, an over-grant:** set the SO user to Superuser in SOC → Administration → Users.
> This works, and it grants far more than soc-ai needs. It also has a ~15-minute Salt
> propagation lag. Wait ~15 min before you test again, or the change looks ineffective.
>
> In both fixes the privilege must land on the `ES_USERNAME` account. The audit write
> uses the Elasticsearch basic-auth identity. It does not use the Kratos web login.

> **Every write fails after an SO upgrade, and the doctor says `GET /api/info` answered
> HTTP 401.** Reads still work.
>
> Security Onion 3.3 stopped accepting the Kratos API-flow session token. The login
> succeeds and SOC then refuses the session it issued, so acknowledge, escalate, case
> creation and case comments all fail. The role grants are not the cause.
>
> soc-ai 1.5.0 and later log in with the Kratos browser flow and send the session cookie.
> On `SO_LOGIN_FLOW=auto`, the default, soc-ai runs the browser flow first and needs no
> change. Set `SO_LOGIN_FLOW=browser` to force it, and restart. Section 2 covers the three
> values.
>
> Confirm the fix with `soc-ai doctor`. Its `security onion` PASS line names the flow in
> use, for example "Kratos session (browser flow)".

> **The log fills with `Kratos login flow init failed: Expecting value: line 1 column 1`.**
>
> Security Onion sheds repeated logins by redirecting them to its own login page. Older
> soc-ai builds read that page as JSON and reported a login that never started. That
> report hid the real cause. The message now says that SO throttled the login and gives
> the status code.
>
> A refused session now backs off. The hold starts at 30 seconds and doubles to a ceiling
> of ten minutes, and the next accepted call clears it. Fix the login flow above, then
> wait one hold period for the log to go quiet.

> **ack/escalate "succeeds" in the UI but the alert is unchanged in SO**
>
> If the audit write fails under `AUDIT_FAIL_CLOSED=true`, soc-ai aborts the action
> before it reaches SO. See the entry above. Fix the audit grant first.

> **The first hunt times out against `…:9200` with correct credentials.** The startup
> health check times out the same way.
>
> Security Onion's firewall does not allow soc-ai's host through. A *timeout* or a
> "connection refused" means that the socket never opened. A fast 401 means something
> else. Pinhole soc-ai's IP in SO's firewall. Section 0 covers this step. Under Docker
> bridge networking, allow-list the Docker host's IP. The container's `172.x` address
> does not work.
