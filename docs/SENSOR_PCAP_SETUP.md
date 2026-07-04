# Sensor PCAP user (`socpcap`) — setup & recovery runbook

`t_get_pcap` fetches packets by SSHing to the Security Onion **sensor** and
running `sudo tcpdump -r <suripcap file>`. soc-ai connects as `socpcap`, a
dedicated **low-privilege** user, instead of a root-capable account, so a
leaked PCAP key can only run `tcpdump`, never arbitrary commands.

> **⚠ The grid can nuke this user.** `socpcap` is a manually-created system user
> on the sensor. A Salt highstate / SO upgrade / re-image can remove it (or its
> sudoers/`authorized_keys`), which silently breaks PCAP fetch. There is a
> backlog item to *detect* this and prompt re-creation; until then, if PCAP stops
> working, re-run the setup below.
>
> **Recreate via a SENSOR ADMIN path** (the SO console, or your own admin SSH
> account), **not** via the soc-ai `so_pcap` key. That key is now `socpcap`
> (tcpdump-only) and *cannot* recreate itself.

## What the setup establishes

| Piece | Value |
|-------|-------|
| User | `socpcap` (a normal system user; needs a shell + home for SSH) |
| Group | `socore` — grants read/traverse on `so_suripcap_dir` (`/nsm/suripcap`, mode 775 `suricata:socore`) so the `find` step can list pcap files |
| Sudo | `/etc/sudoers.d/socpcap` → `socpcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump` **only** (arbitrary sudo blocked) |
| Key | the soc-ai `so_pcap` **public** key in `~socpcap/.ssh/authorized_keys`, `from="<soc-ai host IP>"`-restricted |

soc-ai side (`.env` on the soc-ai host): `SO_SSH_USER=socpcap`,
`SO_SSH_KEY=/opt/soc-ai/.ssh/so_pcap`, `SO_SSH_SUDO=sudo`, `PCAP_ENABLED=true`.

## Setup / recovery (run on the SENSOR as an admin with sudo)

1. Get the soc-ai PCAP **public** key (from the soc-ai host):

   ```bash
   # on the soc-ai host:
   cat /opt/soc-ai/.ssh/so_pcap.pub
   ```

2. On the sensor, create the user + group + key + sudoers (idempotent). Replace
   `PUBKEY` with the line from step 1 and `SOC_AI_IP` with the soc-ai host IP:

   ```bash
   sudo useradd -m -s /bin/bash socpcap 2>/dev/null || true
   sudo usermod -aG socore socpcap

   sudo mkdir -p /home/socpcap/.ssh
   printf 'from="SOC_AI_IP" %s\n' 'PUBKEY' | sudo tee /home/socpcap/.ssh/authorized_keys >/dev/null
   sudo chmod 700 /home/socpcap/.ssh
   sudo chmod 600 /home/socpcap/.ssh/authorized_keys
   sudo chown -R socpcap:socpcap /home/socpcap/.ssh
   sudo restorecon -R /home/socpcap/.ssh 2>/dev/null || true   # SELinux

   printf 'socpcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump\n' | sudo tee /etc/sudoers.d/socpcap >/dev/null
   sudo chmod 440 /etc/sudoers.d/socpcap
   sudo visudo -cf /etc/sudoers.d/socpcap     # must print "parsed OK"
   ```

   > `tcpdump` path: confirm with `command -v tcpdump` (this grid: `/usr/sbin/tcpdump`).
   > `so_suripcap_dir`: confirm `SO_SURIPCAP_DIR` in soc-ai's `.env` (default `/nsm/suripcap`).

## Verify (from the soc-ai host)

```bash
ssh -i /opt/soc-ai/.ssh/so_pcap socpcap@<SENSOR_IP> '
  id -Gn | grep -q socore && echo socore-OK
  find /nsm/suripcap -name "so-pcap.*" | head -1
  sudo -n /usr/sbin/tcpdump --version | head -1   # works
  sudo -n id                                       # MUST fail: "a password is required"
'
```

Then end-to-end through soc-ai: run a hunt that calls `t_get_pcap`, or
`get_pcap_facts(settings, src_ip=..., dst_ip=...)`.

## History

- An earlier setup authorized PCAP access via a key on a root-capable account
  (`NOPASSWD:ALL`). Prefer the dedicated, de-privileged `socpcap` account:
  scope sudo to `tcpdump` only, so a compromised PCAP key cannot escalate. If you migrate from a root-capable key, back up the existing
  account's `authorized_keys` before removing the old entry, and confirm a
  separate admin path still works first.
