# Test PCAPs — safe malicious captures for `so-import-pcap`

Catalog of safe, downloadable, labeled-**malicious** packet captures for validating
the Security Onion (Suricata + Zeek) detection pipeline end-to-end. These are inert
**network captures** (no live malware execution), the standard material SOC analysts
use. Import with `sudo so-import-pcap <file.pcap>` on the sensor; alerts land in the
SO 3.0 `logs-*` data streams (what soc-ai queries via `EVENTS_INDEX_PATTERN`,
e.g. the `.ds-logs-suricata.alerts-so-...` backing indices) with the PCAP's
original timestamps + an `import.id` tag.

> Compiled 2026-06-16; URLs HEAD-verified live then.

## Start here (small, verified, guaranteed to pop)

1. **SMB EICAR** — 4.4 KB, no password. Suricata's own regression fixture → file-extraction smoke test, will fire deterministically. EICAR test string, not real malware.
   ```bash
   wget -O smb-eicar.pcap "https://raw.githubusercontent.com/OISF/suricata-verify/master/tests/smb-eicar-file/input.pcap"
   sudo so-import-pcap smb-eicar.pcap
   ```
2. **CryptoWall 4 C2** — 137 KB, no password. Real ransomware HTTP C2.
   ```bash
   wget -O cryptowall4_c2.pcapng "https://raw.githubusercontent.com/chrissanders/packets/master/cryptowall4_c2.pcapng"
   sudo so-import-pcap cryptowall4_c2.pcapng
   ```
3. **NetSupport RAT** — 5.2 MB, MTA 2026-02-28. Recent, signature-rich full infection chain (fake-CAPTCHA/ClickFix → NetSupport C2).
   ```bash
   wget -O nsm-rat.pcap.zip "https://www.malware-traffic-analysis.net/2026/02/28/2026-02-28-traffic-analysis-exercise.pcap.zip"
   unzip -P 'infected_20260228' nsm-rat.pcap.zip
   sudo so-import-pcap 2026-02-28-traffic-analysis-exercise.pcap
   ```

## Broader catalog

| Family / sample | Size | Pass | Download | Expected |
|---|---|---|---|---|
| Exploit-kit → CryptoWall4 (chrissanders) | 652 KB | — | `wget "https://raw.githubusercontent.com/chrissanders/packets/master/ek_to_cryptowall4.pcapng"` | ET EXPLOIT_KIT landing/redirect, malware download; Zeek http/files chain |
| DonBot/Buzus spambot — CTU-13 #47 | 5.3 MB | — | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/botnet-capture-20110816-donbot.pcap"` | ET Donbot C2; SMTP-spam; Zeek http beacons + smtp |
| Muhstik IoT — IoT-23 #3-1 | 984 KB | — | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/test.pcap"` | ET SCAN/CINS; IRC C2; Zeek conn fan-out, irc, weird |
| Lumma Stealer — MTA 2026-01-31 | 21.7 MB | `infected_20260131` | `wget "https://www.malware-traffic-analysis.net/2026/01/31/2026-01-31-traffic-analysis-exercise.pcap.zip"` | ET Lumma Stealer fingerprinting + exfil; Zeek http/ssl |
| dnscat2 DNS tunneling (Active Countermeasures) | ~2.5 MB | — | `wget -L -O dnscat2_1hr.pcap "https://www.dropbox.com/s/j5le068uz8n69wk/dnscat2_dns_tunneling_1hr.pcap?dl=1"` | ET DNS-tunnel/TXT; Zeek dns high-entropy TXT (pairs with RITA) |
| DNS-TXT C2 cmds (PCAP-ATTACK) | 36 KB | — | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Command%20and%20Control/cmds%20over%20dns%20txt%20queries%20and%20reponses.pcap"` | DNS-tunnel sigs; Zeek dns anomalous TXT (T1071.004) |
| Zerologon CVE-2020-1472 (PCAP-ATTACK) | 811 KB | — | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Lateral%20Movement/CVE-2020-1472_Zerologon_RPC_NetLogon_NullChallenge_SecChan_6_from_nonDC_to_DC.pcapng"` | ET EXPLOIT Zerologon; Zeek dce_rpc all-zero challenge |
| RDP-tunneled Meterpreter (PCAP-ATTACK) | 5.0 MB | — | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Command%20and%20Control/rdp_tunneling_meterpreter_portfwd.pcapng"` | ET Meterpreter + RDP-tunnel; Zeek rdp + payload anomaly (T1572) |
| Hakai/Gafgyt IoT — IoT-23 #8-1 | 2.1 MB | — | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap"` | ET Gafgyt/Bashlite; Telnet scan; Zeek SYN floods/weird |
| Torii IoT (JA3/TLS) — IoT-23 #20-1 | 4.1 MB | — | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap"` | TLS/JA3 anomaly; Zeek ssl odd JA3/self-signed, periodic beacon |
| DCSync cred theft (PCAP-ATTACK) | ~11 KB | — | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng"` | Zeek dce_rpc DRSGetNCChanges (T1003.006) |
| SmartApeSG→NetSupport→StealC v2 — MTA 2025-08-20 | 63 MB | `infected_20250820` | `wget "https://www.malware-traffic-analysis.net/2025/08/20/2025-08-20-SmartAgeSG-Netsupport-RAT-with-StealCv2.pcap.zip"` | Multi-stage, many ET MALWARE hits (loud test) |

## Safety / handling notes

- **MTA password scheme changed:** no longer flat `infected`. Now `infected_<YYYYMMDD>` (the post date), e.g. 2026-02-28 → `infected_20260228`. (Password shown in `about.gif` on the MTA about page.)
- **Only download the `*.pcap.zip`** from MTA, NOT the `*-files-*.zip` / `files-from-the-infection.zip`, which contain **live malware binaries**.
- **Stratosphere/MCFP** pcaps are plain libpcap, no password, but the cert chain is old → use `curl -k`. Browsable index at `https://mcfp.felk.cvut.cz/publicDatasets/`.
- **CTU-13:** use `botnet-capture-*.pcap` (full payloads → content rules fire); avoid the `*.truncated.pcap` siblings (payloads stripped).
- **GitHub raw** (chrissanders, PCAP-ATTACK, suricata-verify): plaintext, no password; URL-encode spaces (`%20`) + quote local paths.
- Named `ET MALWARE` hits on old datasets (CTU-13 2011, IoT-23 2018) are *likely not guaranteed* against a current ruleset; the **Zeek protocol behaviours** are the durable signal there. MTA-2026 + GitHub samples are most likely to fire named ET sigs.
- Timestamps are the PCAP's original time → imported alerts land historically. Hunt by `alert_es_id` works regardless; to see them in the live alerts pane, widen the time range or `editcap -t <offset>` the PCAP to ~now before importing.
