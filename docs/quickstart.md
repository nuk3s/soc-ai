# Quickstart

From `git clone` to an AI verdict on one of **your** alerts in about 30
minutes — most of it the one-time Security Onion prerequisites. Try the
demo first; it costs five.

## 0. See it working first (5 minutes, no SO, no LLM)

```bash
git clone https://github.com/nuk3s/soc-ai.git && cd soc-ai
docker compose -f docker-compose.demo.yml up --build
# → http://127.0.0.1:8080/ui/alerts
```

A full local replay of recorded investigations, hunts, and a backtest — the
same console you're about to connect for real, on canned data. Nothing
leaves the box. (The hosted twin: [the live demo](https://soc-ai-demo.onrender.com/).)

## 1. What you need for the real thing

- A **Linux host** with `git` and `curl` (`setup.sh` installs Docker itself if
  needed, including on RHEL / Rocky / Alma 10).
- **Network reach** to your Security Onion grid — the SO web UI and
  Elasticsearch on TCP 9200. Pinhole this host's IP through SO's firewall:
  [SO prerequisites](SECURITY-ONION-SETUP.md).
- **An AI model, one of two routes** (the installer asks which):

| Route | What it is | Day-1 cost |
| --- | --- | --- |
| **Local / self-hosted** (primary) | Any OpenAI-compatible endpoint you run — a LiteLLM gateway, vLLM, Ollama. No backend yet? The bundled profile stands one up: [Standing one up](LESSER_MODELS.md#standing-one-up). | Model download + hardware |
| **Cloud API key** | OpenRouter or another OpenAI-compatible provider. The installer turns on **redacted egress** (internal IPs, hostnames, usernames, MACs, and internal-domain emails tokenized before anything leaves; the reversal map stays local) and prints exactly what the provider sees. | An API key; alert data (redacted) leaves your network |

```bash
# minimal images lack git/curl:
sudo dnf install -y git curl    # RHEL / Rocky / Alma / Fedora
sudo apt install -y git curl    # Debian / Ubuntu
```

## 2. The one Security Onion step people skip (don't)

soc-ai's tamper-evident audit log needs an Elasticsearch write grant the stock
`analyst` role doesn't have — and it **fails closed**: without the grant,
every ack / escalate / comment aborts, silently. One command against your SO
manager:

```bash
ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh
```

You can run it before or after the installer; the doctor (below) tells you if
it's missing. Details: [SO prerequisites](SECURITY-ONION-SETUP.md).

## 3. Install

```bash
./setup.sh
```

The installer validates the SO/ES credentials **before** the ~3-minute build,
asks the local-vs-cloud model question, lets you pick the model — a curated
shortlist on the cloud route, your endpoint's live list on the local one —
offers day-1 auto-triage (every 5 min, capped at 25
targets a sweep, high-severity and up) and the 10-runbook starter pack,
generates secrets and a TLS cert, starts the stack, and finishes with the
**doctor**: a pass/fail table over every dependency — connectivity by layer
(DNS / TCP / TLS), ES privileges *including the audit grant*, index-pattern
coverage, and the model's measured fitness on the real triage contract. Every
failing line names its fix.

Re-run it any time: `docker exec soc-ai python -m soc_ai doctor`.

!!! tip "Unattended installs"
    Fill in `setup.conf` once and run `./setup.sh --auto` on the next host.

## 4. Work an alert

Open `https://<host>:8443/app`, accept the self-signed cert, sign in as
`admin` with the printed password. Pick a detection, hit **Investigate**, and
watch the agent pull the alert's context, enrich the indicators, and land an
evidence-cited verdict. Write-backs wait for your click. If you enabled
auto-triage, the backlog starts draining on its own — check back in five
minutes.

![soc-ai web UI: an investigation showing the verdict, confidence, reasoning, recommended actions, and the agent's evidence timeline](img/screenshot-investigation.png)

Next steps:

- [Web console guide](WEBUI_GUIDE.md) — triage, auto-triage, investigations, config
- [Running on a lesser model](LESSER_MODELS.md) — standing up a backend, qualifying small/slow models
- [Agent tools](AGENT_TOOLS.md) · [Safety model](SAFETY_MODEL.md)
- Full Docker detail (mounts, SELinux, TLS trust, port conflicts): [Docker deployment](DOCKER.md)
