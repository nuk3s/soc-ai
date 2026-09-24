# Sensor PCAP user `socpcap`: setup and recovery runbook

`t_get_pcap` fetches packets over SSH from the Security Onion sensor. It runs
`sudo tcpdump -r <suripcap file>` there. soc-ai connects as `socpcap`, a dedicated
low-privilege user. A leaked PCAP key can then run `tcpdump` only. It can never run
an arbitrary command.

> **⚠ The grid can delete this user.** An operator creates `socpcap` by hand on the
> sensor. A Salt highstate, an SO upgrade or a re-image can remove the user, its sudoers
> file or its `authorized_keys` file. PCAP fetch then breaks silently. A backlog item
> covers the *detection* of this state and a prompt to create the user again. Until that
> item lands, run the setup below again if PCAP stops working.
>
> **Create the user again through a SENSOR ADMIN path.** Use the SO console or your own
> admin SSH account. Do not use the soc-ai `so_pcap` key. That key now belongs to
> `socpcap`, it runs tcpdump only, and it *cannot* create itself.

## What the setup establishes

| Piece | Value |
|-------|-------|
| User | `socpcap`. It is a normal system user. SSH needs a shell and a home directory for it. |
| Group | `socore`. It grants read and traverse on `so_suripcap_dir`. That directory is `/nsm/suripcap`, mode 775, owner `suricata:socore`. The `find` step can then list the pcap files. |
| Sudo | `/etc/sudoers.d/socpcap` holds `socpcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump` only. Arbitrary sudo is blocked. |
| Key | The soc-ai `so_pcap` public key sits in `~socpcap/.ssh/authorized_keys`. A `from="<soc-ai host IP>"` restriction limits it. |

On the soc-ai side, set these values in `.env` on the soc-ai host: `SO_SSH_USER=socpcap`,
`SO_SSH_KEY=/opt/soc-ai/.ssh/so_pcap`, `SO_SSH_SUDO=sudo` and `PCAP_ENABLED=true`.

## Setup and recovery

Run these steps on the SENSOR as an admin with sudo.

1. Get the soc-ai PCAP public key from the soc-ai host:

   ```bash
   # on the soc-ai host:
   cat /opt/soc-ai/.ssh/so_pcap.pub
   ```

2. On the sensor, create the user, the group, the key and the sudoers file. The block is
   idempotent. Replace `PUBKEY` with the line from step 1. Replace `SOC_AI_IP` with the
   soc-ai host IP:

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

   > Confirm the `tcpdump` path with `command -v tcpdump`. On this grid the path is
   > `/usr/sbin/tcpdump`.
   > Confirm `so_suripcap_dir` against `SO_SURIPCAP_DIR` in soc-ai's `.env`. The default
   > is `/nsm/suripcap`.

## Verification

Run this command from the soc-ai host.

```bash
ssh -i /opt/soc-ai/.ssh/so_pcap socpcap@<SENSOR_IP> '
  id -Gn | grep -q socore && echo socore-OK
  find /nsm/suripcap -name "so-pcap.*" | head -1
  sudo -n /usr/sbin/tcpdump --version | head -1   # works
  sudo -n id                                       # MUST fail: "a password is required"
'
```

Then test the path end to end through soc-ai. Run a hunt that calls `t_get_pcap`, or call
`get_pcap_facts(settings, src_ip=..., dst_ip=...)`.

## History

- An earlier setup authorized PCAP access with a key on a root-capable account under
  `NOPASSWD:ALL`. Prefer the dedicated, de-privileged `socpcap` account. Scope its sudo
  to `tcpdump` only, so a compromised PCAP key cannot escalate. Confirm that a separate
  admin path still works before you migrate from a root-capable key. Back up the
  `authorized_keys` file of the existing account before you remove the old entry.
