# Quickstart

Get soc-ai triaging alerts on your grid in a few minutes.

## Prerequisites

You'll need:

- a **Linux host** with `git` and `curl`,
- **network reach** to your Security Onion grid, and
- a **LiteLLM gateway** serving at least one model.

`setup.sh` handles Docker for you, including the automatic install on RHEL / Rocky /
Alma 10.

!!! warning "Read the SO prerequisites first"
    First-time installers should skim the
    [Security Onion account + firewall prerequisites](SECURITY-ONION-SETUP.md) before
    running the installer. Pinholing soc-ai's IP through SO's firewall and the audit-log
    role grant are the two things that reliably bite.

`git` and `curl` aren't preinstalled on minimal images, so add them first:

=== "RHEL / Rocky / Alma / Fedora"

    ```bash
    sudo dnf install -y git curl
    ```

=== "Debian / Ubuntu"

    ```bash
    sudo apt install -y git curl
    ```

## Install

```bash
git clone https://github.com/nuk3s/soc-ai.git && cd soc-ai
./setup.sh
```

`setup.sh` walks you through the connection settings and checks them *before* it builds
anything (a wrong password or an unreachable gateway fails in seconds, not after a
three-minute build), lets you pick your model from the gateway's live list (it
authenticates to fetch it), generates the secrets and a TLS cert, brings the stack up, and
prints the URL and admin password.

!!! tip "Unattended installs"
    To stand up more hosts without the prompts, fill in `setup.conf` once and run
    `./setup.sh --auto`.

!!! tip "Something not working?"
    Run the doctor: `docker exec soc-ai python -m soc_ai doctor` (or `uv run soc-ai doctor`
    from a source checkout). It checks config, the local store + migrations, Security Onion,
    Elasticsearch, the gateway, and the analyst model's fitness — a pass/fail table with a
    fix hint on every failing line.

Full Docker detail — required mounts, SELinux relabeling, upstream TLS trust
(`*_VERIFY_SSL`), the port-8443-vs-SO-nginx conflict, and the manual + rsync/systemd
paths — is in [Docker deployment](DOCKER.md).

## Work an alert in the browser

Open `https://<host>:8443/app`, accept the self-signed cert, and sign in as `admin`. Pick
a detection, hit **Investigate**, and watch the agent work live: it pulls the
alert and its Zeek/PCAP context, enriches the indicators, and lands an evidence-cited
verdict. Anything it recommends writing back to Security Onion waits in the report as a
recommended action until you execute it with one click.

![soc-ai web UI: an investigation showing the verdict, confidence, reasoning, recommended actions, and the agent's evidence timeline](img/screenshot-investigation.png)

Next steps:

- [Web console guide](WEBUI_GUIDE.md): triage, auto-triage, investigations, the admin config page
- [Agent tools](AGENT_TOOLS.md): every tool the agent can call, and the guardrails on them
- [Safety model](SAFETY_MODEL.md): the analyst write path, audit schema, and Oracle redaction
