# Quickstart

This page goes from `git clone` to a verdict on one of your own alerts in about
30 minutes. The one-time Security Onion prerequisites take most of that time.
Try the demo first, because it takes 5 minutes.

## 0. See it working first

The demo takes 5 minutes. It needs no Security Onion grid and no model.

```bash
git clone https://github.com/nuk3s/soc-ai.git && cd soc-ai
docker compose -f docker-compose.demo.yml up --build
# → http://127.0.0.1:8080/ui/alerts
```

The demo replays recorded investigations, hunts and a backtest on canned data.
It runs the same console that you connect to your grid later. The demo also
carries a week of hunt catalog sweeps. The catalog panel on the Operate hub and
the Catalog preset on the Hunts screen show the declarative catalog at work.
No data leaves the box. The hosted copy is
[the live demo](https://soc-ai-demo.onrender.com/).

## 1. What you need

- A **Linux host** with `git` and `curl`. `setup.sh` installs Docker itself if
  the host needs it, and it does so on RHEL, Rocky and Alma 10 as well.
- **Network reach** to your Security Onion grid. The host needs the Security
  Onion web UI and Elasticsearch on TCP 9200. Open a pinhole for the IP address
  of this host through the Security Onion firewall. See
  [SO prerequisites](SECURITY-ONION-SETUP.md).
- **An AI model on one of two routes.** The installer asks which route you use.

| Route | What it is | Day-1 cost |
| --- | --- | --- |
| **Local or self-hosted**, the primary route | Any OpenAI-compatible endpoint that you run: a LiteLLM gateway, vLLM or Ollama. If you have no backend, the bundled profile starts one. See [Standing one up](LESSER_MODELS.md#standing-one-up). | Model download + hardware |
| **Cloud API key** | OpenRouter or another OpenAI-compatible provider. The installer turns on redacted egress and prints what the provider sees. Redacted egress tokenizes internal IP addresses, hostnames, usernames, MAC addresses and internal-domain emails before anything leaves. The reversal map stays on your host. | An API key. Redacted alert data leaves your network |

```bash
# minimal images lack git/curl:
sudo dnf install -y git curl    # RHEL / Rocky / Alma / Fedora
sudo apt install -y git curl    # Debian / Ubuntu
```

## 2. The Security Onion step that people skip

The tamper-evident audit log needs an Elasticsearch write grant that the stock
`analyst` role does not have. The audit log **fails closed**. Without the grant
every acknowledge, escalate and comment aborts, and it aborts silently. Run one
command against your Security Onion manager:

```bash
ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh
```

You can run it before the installer or after it. The doctor below reports a
missing grant. For the detail, see [SO prerequisites](SECURITY-ONION-SETUP.md).

## 3. Install

```bash
./setup.sh
```

The installer does the following:

1. It validates the Security Onion and Elasticsearch credentials before the
   build. The build takes about 3 minutes.
2. It asks whether you run a local model or a cloud model.
3. It lets you pick the model. The cloud route offers a curated shortlist. The
   local route offers the live list from your endpoint.
4. It offers day-1 auto-triage. Auto-triage runs every 5 min, it is capped at 25
   targets a sweep, and it acts on high-severity alerts and above.
5. It offers the 10-runbook starter pack.
6. It generates the secrets and a TLS certificate.
7. It starts the stack.
8. It runs the **doctor**.

The doctor prints a pass and fail table over every dependency. It covers
connectivity at the DNS, TCP and TLS layers, the Elasticsearch privileges
*including the audit grant*, the index-pattern coverage, and the measured
fitness of the model against the triage contract. Every failing line names its
fix.

Run the doctor again at any time with
`docker exec soc-ai python -m soc_ai doctor`.

!!! tip "Unattended installs"
    Fill in `setup.conf` once. Then run `./setup.sh --auto` on the next host.

## 4. Work an alert

1. Open `https://<host>:8443/app`.
2. Accept the self-signed certificate.
3. Sign in as `admin` with the printed password.
4. Pick a detection and press **Investigate**.

The agent pulls the context of the alert, enriches the indicators, and lands a
verdict that cites its evidence. Each write-back waits for your click. If you
turned on auto-triage, the backlog drains on its own. Look again after 5
minutes.

![soc-ai web UI: an investigation showing the verdict, confidence, reasoning, recommended actions, and the agent's evidence timeline](img/screenshot-investigation.png)

Next steps:

- [Web console guide](WEBUI_GUIDE.md): triage, auto-triage, investigations and config
- [Running on a lesser model](LESSER_MODELS.md): how to start a backend, and how to qualify a small or slow model
- [Agent tools](AGENT_TOOLS.md) · [Safety model](SAFETY_MODEL.md)
- [Docker deployment](DOCKER.md): mounts, SELinux, TLS trust and port conflicts
