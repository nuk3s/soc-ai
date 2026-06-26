# Blocklist refresh

soc-ai enriches alerts against locally-vendored public IOC blocklists
(abuse.ch URLhaus / ThreatFox / Feodo Tracker, the Tor exit list, and an
operator-curated seed list). **There is no runtime egress to these feeds** —
lookups are pure in-memory probes against files on disk. The files are kept
fresh out-of-band by the `soc-ai blocklists refresh` job.

This document covers the refresh job, the abuse.ch Auth-Key requirement, the
systemd timer (and a cron alternative), and the synth-eval snapshot pinning.

## Feeds

| Source      | Upstream URL                                                   | On-disk filename   | Loader            | Auth-Key |
|-------------|----------------------------------------------------------------|--------------------|-------------------|----------|
| `urlhaus`   | https://urlhaus.abuse.ch/downloads/csv_recent/                 | `urlhaus.csv`      | `_load_urlhaus`   | required |
| `threatfox` | https://threatfox.abuse.ch/export/json/recent/                 | `threatfox.json`   | `_load_threatfox` | required |
| `feodo`     | https://feodotracker.abuse.ch/downloads/ipblocklist.csv        | `feodo.csv`        | `_load_feodo`     | required |
| `tor`       | https://check.torproject.org/torbulkexitlist                   | `tor_exits.txt`    | `_load_tor`       | none     |

Each feed is written under the **exact filename** the matching loader in
`soc_ai/enrichment/blocklists.py` reads from `blocklist_data_dir`, in the format
that loader already parses. The download is written **atomically** (temp file in
the same directory, then `os.replace`), so a partial or failed download can
never corrupt a live feed file that triage is reading.

Two configured sources are intentionally **not** network-fetched by this job:

- `internal_seed` (`internal_seed.yaml`) — operator-curated; you maintain it
  by hand in the deployment repo.
- `spamhaus_drop` (`spamhaus_drop.txt`) — license-gated and OFF by default;
  fetch it out-of-band only after acknowledging the Spamhaus terms.

## abuse.ch Auth-Key (required for URLhaus / ThreatFox / Feodo)

Since 2024, abuse.ch gates its CSV/JSON data exports behind a free **Auth-Key**
sent as the `Auth-Key` HTTP header. To get one:

1. Sign in at <https://auth.abuse.ch/> (X / LinkedIn / Google / GitHub login).
2. Connect at least one **additional** auth provider and **Save profile**
   (abuse.ch recommends this so you don't lose access if one provider dies).
3. Generate your personal **Auth-Key** in the Optional section.

Put it in `.env`:

```ini
ABUSE_CH_AUTH_KEY=your-personal-auth-key
```

Behaviour:

- The key is sent **only** to the abuse.ch feeds, **only** by the refresh job
  (never during triage), and is **never logged**.
- If `ABUSE_CH_AUTH_KEY` is **unset**, the abuse.ch feeds are **skipped** with a
  clear message and the job does **not** fail hard — the Tor exit list (which
  needs no key) still refreshes, and the job still exits 0.

The free community API is fair-use; commercial/for-profit use may require a paid
abuse.ch subscription.

## Running it

Refresh all enabled feeds (plus the cloud-provider prefix lists):

```bash
soc-ai blocklists refresh
```

Refresh a single feed (cloud-prefix refresh is skipped in this mode):

```bash
soc-ai blocklists refresh --source tor
soc-ai blocklists refresh --source urlhaus
```

Output reports `ok` / `FAIL` / `skip` per feed. Exit code is non-zero only if a
feed genuinely **failed** (HTTP error, write error); a **skipped** abuse.ch feed
(no Auth-Key) is an expected operator-driven state and keeps the exit code 0.

The job writes only to the configured `blocklist_data_dir`
(`BLOCKLIST_DATA_DIR`, default `/var/lib/soc-ai/blocklists`) and
`cloud_prefix_data_dir`.

## Cadence — systemd timer

Two units live under `scripts/systemd/`:

- `soc-ai-blocklists.service` — `oneshot` unit running `soc-ai blocklists refresh`.
- `soc-ai-blocklists.timer` — fires daily at 03:30 local (with up to 15 min
  jitter), `Persistent=true` so a powered-down host catches up on next boot.

Install:

```bash
sudo cp scripts/systemd/soc-ai-blocklists.service /etc/systemd/system/
sudo cp scripts/systemd/soc-ai-blocklists.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-ai-blocklists.timer

# Verify + trigger an immediate run:
systemctl list-timers soc-ai-blocklists.timer
sudo systemctl start soc-ai-blocklists.service
journalctl -u soc-ai-blocklists.service -n 50
```

The service runs as `User=soc-ai` from `/opt/soc-ai` with `EnvironmentFile=
/opt/soc-ai/.env` (so it picks up `ABUSE_CH_AUTH_KEY` and the data-dir paths),
and is hardened to match `soc-ai.service`. `ReadWritePaths=/var/lib/soc-ai`
grants write access to the data dirs under the `ProtectSystem=full` sandbox —
adjust it if you point the data dirs elsewhere.

`blocklist_stale_threshold_days` (default 7) controls when a stale feed file
produces a warning; the daily timer keeps you well inside that window.

### Cron alternative

If you don't run systemd, a daily cron entry works just as well:

```cron
# /etc/cron.d/soc-ai-blocklists — runs daily at 03:30 as the soc-ai user.
30 3 * * * soc-ai cd /opt/soc-ai && set -a && . ./.env && set +a && \
    /opt/soc-ai/.venv/bin/soc-ai blocklists refresh >> /var/log/soc-ai-blocklists.log 2>&1
```

Sourcing `.env` first makes `ABUSE_CH_AUTH_KEY` and the data-dir paths available
to the process (cron does not read `.env` on its own).

## Synth-eval reproducibility (snapshot pinning)

The synthetic-eval catalogue was built against a **pinned blocklist snapshot**.
Refreshing the live `blocklist_data_dir` must NOT silently change synth-eval
results from run to run.

The refresh job **only ever writes to the configured live `blocklist_data_dir`**.
So the rule is simply: **point the eval harness at its own frozen snapshot dir,
separate from the live dir.** For an eval run, override the data dir to a
pinned copy:

```bash
BLOCKLIST_DATA_DIR=/var/lib/soc-ai/blocklists-synth-snapshot \
    soc-ai validate-batch --synth-set all ...
```

That snapshot dir is never touched by `soc-ai blocklists refresh` (which reads
`BLOCKLIST_DATA_DIR` from the production `.env`, i.e. the live dir), so the synth
catalogue stays reproducible while the live dir refreshes daily for real triage.

> Do **not** run `soc-ai blocklists refresh` against the synth snapshot dir — if
> you ever need to re-pin it, snapshot the live dir explicitly
> (`cp -a /var/lib/soc-ai/blocklists /var/lib/soc-ai/blocklists-synth-snapshot`)
> and record the date.

## MaxMind GeoIP

MaxMind GeoLite2 `.mmdb` files are downloaded separately (license key + ZIP — a
different shape) and are covered in `docs/DEPLOYMENT.md`, not by this CLI.
