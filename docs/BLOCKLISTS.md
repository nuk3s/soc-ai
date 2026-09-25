# Blocklist refresh

soc-ai enriches alerts against public IOC blocklists that it vendors locally. The feeds
are the abuse.ch URLhaus, ThreatFox and Feodo Tracker lists, the Tor exit list, and a
seed list that the operator curates. **There is no runtime egress to these feeds.** A
lookup is an in-memory probe against a file on disk. The `soc-ai blocklists refresh` job
keeps the files fresh out of band.

This document covers the refresh job, the abuse.ch Auth-Key requirement, the systemd
timer, the cron alternative and the synth-eval snapshot pinning.

## Feeds

| Source      | Upstream URL                                                   | On-disk filename   | Loader            | Auth-Key |
|-------------|----------------------------------------------------------------|--------------------|-------------------|----------|
| `urlhaus`   | https://urlhaus.abuse.ch/downloads/csv_recent/                 | `urlhaus.csv`      | `_load_urlhaus`   | required |
| `threatfox` | https://threatfox.abuse.ch/export/json/recent/                 | `threatfox.json`   | `_load_threatfox` | required |
| `feodo`     | https://feodotracker.abuse.ch/downloads/ipblocklist.csv        | `feodo.csv`        | `_load_feodo`     | required |
| `tor`       | https://check.torproject.org/torbulkexitlist                   | `tor_exits.txt`    | `_load_tor`       | none     |

The job writes each feed under the exact filename that the matching loader in
`soc_ai/enrichment/blocklists.py` reads from `blocklist_data_dir`. It writes the format
that the loader parses. The job writes the download atomically. It writes a temporary
file in the same directory and then calls `os.replace`, so an interrupted write can
never leave a half-written live feed file that triage reads.

An HTTP 200 alone does not replace a feed. Before the swap, the job runs the download
through the same loader that triage uses. A body that parses to no indicator at all is
discarded: an empty body, a sign-in or WAF challenge page served as HTML, a JSON error
document, or a download that ended early. The previous file stays in place, the feed is
reported as `FAIL`, and the job exits non-zero so the timer log shows it. The
cloud-prefix half applies the same rule: the Cloudflare list must contain at least one
CIDR line, and the AWS, GCP and Azure documents must carry their top-level prefix list.

This job never fetches 2 configured sources over the network:

- `internal_seed` in `internal_seed.yaml`. The operator curates it by hand in the
  deployment repo.
- `spamhaus_drop` in `spamhaus_drop.txt`. It is license-gated and OFF by default.
  Acknowledge the Spamhaus terms first, then fetch it out of band.

## abuse.ch Auth-Key

URLhaus, ThreatFox and Feodo need this key.

Since 2024, abuse.ch gates its CSV and JSON data exports behind a free Auth-Key. The
client sends the key in the `Auth-Key` HTTP header. To get a key:

1. Sign in at <https://auth.abuse.ch/> with an X, LinkedIn, Google or GitHub login.
2. Connect at least one additional auth provider and select Save profile.
   abuse.ch recommends this, because you keep access if one provider fails.
3. Generate your personal Auth-Key in the Optional section.

Put the key in `.env`:

```ini
ABUSE_CH_AUTH_KEY=your-personal-auth-key
```

Behaviour:

- The refresh job sends the key only to the abuse.ch feeds. No other job sends it, and
  triage never sends it. soc-ai never logs the key.
- If `ABUSE_CH_AUTH_KEY` is unset, the job skips the abuse.ch feeds and prints a clear
  message. The job does not fail. The Tor exit list needs no key, so it still refreshes,
  and the job still exits 0.

The free community API is fair-use. Commercial use can need a paid abuse.ch subscription.

## Running the job

Refresh every enabled feed and the cloud-provider prefix lists:

```bash
soc-ai blocklists refresh
```

Refresh a single feed. This mode skips the cloud-prefix refresh:

```bash
soc-ai blocklists refresh --source tor
soc-ai blocklists refresh --source urlhaus
```

The output reports `ok`, `FAIL` or `skip` for each feed. The exit code is non-zero only
if a feed failed with an HTTP error, a write error, or a body that the loader cannot
turn into at least one indicator (see above). A skipped abuse.ch feed means
that you set no Auth-Key. That state is expected, and it keeps the exit code 0.

The job writes only to the configured `blocklist_data_dir` and `cloud_prefix_data_dir`.
`BLOCKLIST_DATA_DIR` sets the first one, and its default is `/var/lib/soc-ai/blocklists`.

## Systemd timer cadence

Two units live under `scripts/systemd/`:

- `soc-ai-blocklists.service` is a `oneshot` unit. It runs `soc-ai blocklists refresh`.
- `soc-ai-blocklists.timer` fires daily at 03:30 local time, with up to 15 min of jitter.
  It sets `Persistent=true`, so a host that was powered down runs the job at the next
  boot.

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

The service runs as `User=soc-ai` from `/opt/soc-ai`. It reads
`EnvironmentFile=/opt/soc-ai/.env`, so it picks up `ABUSE_CH_AUTH_KEY` and the data-dir
paths. Its hardening matches `soc-ai.service`. `ReadWritePaths=/var/lib/soc-ai` grants
write access to the data dirs inside the `ProtectSystem=full` sandbox. Change that
setting if you point the data dirs elsewhere.

`blocklist_stale_threshold_days` sets the age at which a stale feed file produces a
warning. Its default is 7. The daily timer keeps every file inside that window.

### Cron alternative for the host-venv deploy

The host-venv deploy uses rsync and systemd. If you run it without the timer, a daily
cron entry works as well. The block below sources the host venv at `/opt/soc-ai/.venv`.
It is not valid on the Docker deploy.

```cron
# /etc/cron.d/soc-ai-blocklists — runs daily at 03:30 as the soc-ai user.
30 3 * * * soc-ai cd /opt/soc-ai && set -a && . ./.env && set +a && \
    /opt/soc-ai/.venv/bin/soc-ai blocklists refresh >> /var/log/soc-ai-blocklists.log 2>&1
```

The entry sources `.env` first, so `ABUSE_CH_AUTH_KEY` and the data-dir paths reach the
process. cron does not read `.env` on its own.

**Docker deploy:** this deploy has no host venv to source. Run the refresh inside the
container with `python -m soc_ai blocklists refresh`. See the
[`docker compose exec` cron example in DOCKER.md](DOCKER.md#blocklist-refresh-has-no-scheduler-in-the-docker-path).

## Synth-eval reproducibility

The synthetic-eval catalogue was built against a pinned blocklist snapshot. A refresh of
the live `blocklist_data_dir` must NOT change synth-eval results from run to run.

The refresh job writes only to the configured live `blocklist_data_dir`. The rule
follows from that. **Point the eval harness at its own frozen snapshot dir.** Keep that
dir separate from the live dir. For an eval run, override the data dir to a pinned copy:

```bash
BLOCKLIST_DATA_DIR=/var/lib/soc-ai/blocklists-synth-snapshot \
    soc-ai validate-batch --synth-set all ...
```

`soc-ai blocklists refresh` never touches that snapshot dir. The command reads
`BLOCKLIST_DATA_DIR` from the production `.env`. That value names the live dir. The synth
catalogue stays reproducible, and the live dir refreshes daily for real triage.

> Do not run `soc-ai blocklists refresh` against the synth snapshot dir. To re-pin the
> snapshot, copy the live dir explicitly with
> `cp -a /var/lib/soc-ai/blocklists /var/lib/soc-ai/blocklists-synth-snapshot`. Record
> the date.

## MaxMind GeoIP

You download the MaxMind GeoLite2 `.mmdb` files separately. They need a license key and
arrive as a ZIP file, so they have a different shape. `docs/DEPLOYMENT.md` covers them.
This CLI does not.
