# Security Onion account requirements

soc-ai connects to a Security Onion (SO) 3.0 grid in three distinct ways, and each
needs a *different* privilege. Getting these wrong is the single biggest source of
install-time troubleshooting, so this doc spells out exactly what the account behind
each path needs.

| Path | What it does | How it authenticates | Privilege needed |
|------|--------------|----------------------|------------------|
| **Read / triage** | Pulls alerts, events, cases, detections, playbooks | Elasticsearch **basic auth** (`ES_USERNAME` / `ES_PASSWORD`) | `read` + `view_index_metadata` on the events + SO indices (the stock `analyst` role covers this) |
| **Write-back** | ack / escalate-to-case / add-comment | SO **web API** with the SO login (Kratos session cookie) | A real SO analyst login — **no ES write privilege** |
| **Audit log** | Tamper-evident forensic record of every action | Elasticsearch **basic auth** (same identity as Read) | `write` + index-create on `soc-ai-audit-*` — **NOT in the stock `analyst` role** |
| **PCAP (optional)** | Pulls full packet captures from a sensor | **SSH** to the sensor with a de-privileged key | A sensor SSH key — not an SO/ES role |

The rest of this doc explains each row — but first, the network.

---

## 0. Pinhole soc-ai's IP in Security Onion's firewall

Before any credential matters, soc-ai's host has to be able to *reach* the grid.
Security Onion firewalls all of its services by default, so a host that isn't on the
allow-list can't even open a socket to Elasticsearch or the web API — and a blocked
connection looks exactly like a wrong password or a flaky network. This is usually the
first wall people hit.

Add soc-ai's source IP to SO's firewall so it can reach:

- **Elasticsearch REST — TCP 9200** (the read/triage path *and* the audit write). This is
  the important one: ES 9200 is **not** open to analyst workstations by default.
- **The web API — TCP 443** (ack / escalate-to-case / comment).
- **A sensor over SSH — TCP 22**, only if you enable PCAP fetch.

Do it from the SO manager — either in the SOC web UI (**Administration → Configuration →
Firewall**, add the IP to a host group permitted to reach Elasticsearch + the web
interface) or on the CLI:

```bash
sudo so-firewall includehost <hostgroup> <soc-ai-host-ip>
sudo so-firewall apply
```

(The exact host group is SO-version-specific — pick or create one that opens
Elasticsearch REST and the analyst/web ports; see Security Onion's firewall docs.)

**Docker nuance — pinhole the *host* IP, not the container's.** With the default Docker
bridge network the container's traffic is NAT'd out the Docker host's address, so SO sees
the **Docker host's IP** — allow-list *that*, not an internal `172.x` container address.
(Host-networked deployments use the host IP anyway.)

**Symptom if you skip it:** the first hunt — or the startup ES health check — hangs and
then fails with a connection *timeout* / "connection refused" to `…:9200`, even though the
credentials are correct. Wrong creds give a fast **401**; a *timeout* points at the
firewall, not the password.

---

## 1. Reads go through Elasticsearch basic auth

soc-ai reads alerts and enrichment context straight from Elasticsearch using the
`ES_USERNAME` / `ES_PASSWORD` basic-auth credentials in `.env` (these are normally the
same as your SO analyst login). The account needs:

- `read` + `view_index_metadata` on the **events pattern** — `logs-*` on a single-node
  SO 3.0 grid, or `*:so-*` for a cross-cluster (distributed) deployment. Set this with
  `EVENTS_INDEX_PATTERN` in `.env`.
- `read` + `view_index_metadata` on `so-case*`, `so-detection*`, and `so-playbook*`
  (cases, detections, and playbooks).

**The stock SO `analyst` role already grants all of these reads.** A normal analyst
account works out of the box for triage with no extra grants.

---

## 2. Write-back goes through the SO *web API*, not Elasticsearch

Acknowledging an alert, escalating it to a case, and adding a case comment do **not**
write to Elasticsearch directly. They go through Security Onion's own web API (e.g.
`POST /api/events/ack` — the same endpoint the SO web UI hits when you click the bell
icon), authenticated with your SO login via a **Kratos session cookie**.

Two consequences:

- You do **not** need any Elasticsearch *write* privilege for ack / escalate / comment.
  A read-capable analyst login is sufficient — SO enforces write authorization on its
  own side.
- You **do** need a real, working SO analyst login, and you need the Kratos auth prefix
  set correctly. SO 3.0 mounts Kratos under `/auth/...`, so leave the default:

  ```ini
  SO_KRATOS_PATH_PREFIX=/auth
  ```

  (Older SO releases used `/self-service/...`; the `/auth` default matches SO 3.0.)

This path replaces the older, paywalled SO Connect API approach — the web path is always
available on an OSS grid.

---

## 3. The gotcha that bites: the audit log needs an Elasticsearch write grant

This is the one that costs people an afternoon.

soc-ai keeps a **tamper-evident audit log** (a hash-chained record of every action it
takes) and writes it **directly to Elasticsearch**, into daily indices named
`soc-ai-audit-YYYY.MM.DD`. The stock SO `analyst` role does **not** grant create/write on
that index pattern, so the first audit write fails with a 403:

```
action [indices:admin/auto_create] is unauthorized for user [...] with roles [analyst]
on indices [soc-ai-audit-2026.06.25], this action is granted by the index privileges
[auto_configure,create_index,manage,all]
```

Critically, the audit write authenticates as the **Elasticsearch basic-auth identity**
(`ES_USERNAME`) — *not* the Kratos web login. So the `soc-ai-audit-*` privilege must be
granted to **that** ES account.

### Why this breaks ack/escalate, not just forensics

soc-ai ships with `AUDIT_FAIL_CLOSED=true` (the 1.x default). Under fail-closed, the
audit record for a *mutating* action is written **before** the action is allowed to
proceed — so if the audit write 403s, soc-ai **aborts the mutating action**. The result:
ack / escalate-to-case / add-comment **silently fail**, not just the audit trail. You
lose the action, not only its forensic record.

(Read-only triage is unaffected — audit failures on reads are swallowed by design, so
investigations still complete; you just lose their audit entries.)

### Two fixes

**RECOMMENDED — least privilege.** Run the bundled grant script on the SO **manager**
node. It adds the `soc-ai-audit-*` index privileges (`auto_configure`, `create_index`,
`index`, `read`, `view_index_metadata`, `write`) to the `analyst` role and bootstraps
today's audit index:

```bash
# From your dev box, piping the script over SSH to the SO manager:
ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh

# Or interactively on the SO box itself:
sudo bash scripts/setup-audit-index.sh
```

It uses `so-elasticsearch-query` (which authenticates against the local ES via the
root-only `curl.config`), so it must run on the manager as root/sudo. After it runs,
re-test an ack/escalate — the 403 disappears immediately and the action goes through.

**THE TRAP — the Superuser toggle.** SO does **not** expose Elasticsearch role editing
in its web UI, so people reach for the only knob that *is* exposed: flipping the SO user
to **Superuser** in **SOC → Administration → Users**. This works (superuser implies the
`all` index privilege), but it's a large over-grant on a shared cluster — that account
can now read and write *everything* in Elasticsearch. Prefer the least-privilege script.

If you do use the toggle, mind the **~15-minute Salt propagation lag**: the role change
is pushed by Salt and is **not** effective the instant you flip the switch. Flip it,
then **wait ~15 minutes** before re-testing. Retrying immediately makes it look like the
toggle did nothing — the most common false "it's still broken" report.

---

## 4. PCAP fetch (optional) uses SSH, not an ES/SO role

If you enable full packet-capture retrieval (`PCAP_ENABLED=true`), soc-ai SSHes to a
sensor to pull Suricata's ring-buffer PCAP. This uses a **separate, de-privileged sensor
SSH key** (`SO_SSH_KEY`) pointed at `SO_SSH_HOST` — it is *not* an SO web login or an
Elasticsearch role. PCAP is off by default; see [DOCKER.md](DOCKER.md) for the key mount.

---

## Two deployment shapes

### Minimal read-only deploy

Triage only — no ack/escalate, no audit log. The stock `analyst` account is enough; no
grant script, no superuser toggle.

- `ES_USERNAME` / `ES_PASSWORD` = your SO analyst login.
- Nothing else required. You get full investigations and recommendations; the recommended
  write actions surface in the UI but you apply them by hand in SO.
- (If you want to suppress the audit 403 noise in the logs without granting anything, set
  `AUDIT_FAIL_CLOSED=false` — but then a failed audit write no longer blocks a write, so
  only do this on a read-only deploy.)

### With write-back + audit (full deploy)

To let soc-ai ack/escalate/comment *and* keep a forensic trail:

1. A real SO analyst login in `.env` (`SO_USERNAME` / `SO_PASSWORD`) and
   `SO_KRATOS_PATH_PREFIX=/auth`.
2. The same account as `ES_USERNAME` / `ES_PASSWORD` for reads + audit writes.
3. **Run `scripts/setup-audit-index.sh` on the SO manager** to grant the
   `soc-ai-audit-*` write privilege. (Do this even though `analyst` covers reads — the
   audit index is the one thing it lacks.)

---

## Troubleshooting

> **`action [indices:admin/auto_create] is unauthorized for user [...] with roles [analyst] on indices [soc-ai-audit-…]`**
>
> The audit-log Elasticsearch write is being rejected. Because `AUDIT_FAIL_CLOSED=true`,
> this **also aborts ack/escalate/comment** — they appear to do nothing.
>
> **Fix A (recommended):** run `scripts/setup-audit-index.sh` on the SO manager to grant
> the `analyst` role the `soc-ai-audit-*` privileges. Effective immediately.
>
> **Fix B (over-grant):** toggle the SO user to **Superuser** in
> **SOC → Administration → Users**. Works, but grants far more than needed — and it has a
> **~15-minute Salt propagation lag**, so wait ~15 min before re-testing or it'll look
> like it didn't take.
>
> Either way, the privilege must land on the **`ES_USERNAME`** account — the audit write
> uses the Elasticsearch basic-auth identity, not the Kratos web login.

> **ack/escalate "succeeds" in the approval flow but the alert is unchanged in SO**
>
> If the audit write is failing (see above) under `AUDIT_FAIL_CLOSED=true`, the action is
> aborted before it reaches SO. Fix the audit grant first.

> **The first hunt (or startup health check) times out against `…:9200` with correct creds**
>
> soc-ai's host isn't allowed through Security Onion's firewall. A *timeout* / "connection
> refused" (as opposed to a fast 401) means the socket never opened — pinhole soc-ai's IP
> in SO's firewall (§0). With Docker bridge networking, allow-list the **Docker host's IP**,
> not the container's `172.x` address.
