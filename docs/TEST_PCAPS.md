# Test PCAPs: safe malicious captures for `so-import-pcap`

This page is a catalog of safe, downloadable, labeled-malicious packet captures. Use
them to validate the Security Onion detection pipeline end to end, across Suricata and
Zeek. These are inert network captures, and no live malware runs. SOC analysts use
this material as standard.

Import a capture with `sudo so-import-pcap <file.pcap>` on the sensor. The alerts land in
the SO 3.0 `logs-*` data streams, with the original timestamps of the PCAP and an
`import.id` tag. soc-ai queries those streams through `EVENTS_INDEX_PATTERN`, for example
the `.ds-logs-suricata.alerts-so-...` backing indices.

> Compiled on 2026-06-16. Every URL passed a live HEAD check on that date.

## Start here

These captures are small and verified. Each one fires.

1. **SMB EICAR:** 4.4 KB, no password. This is Suricata's own regression fixture, so it is the file-extraction smoke test. It fires deterministically. It holds the EICAR test string and no real malware.
   ```bash
   wget -O smb-eicar.pcap "https://raw.githubusercontent.com/OISF/suricata-verify/master/tests/smb-eicar-file/input.pcap"
   sudo so-import-pcap smb-eicar.pcap
   ```
2. **CryptoWall 4 C2:** 137 KB, no password. This is real ransomware HTTP C2 traffic.
   ```bash
   wget -O cryptowall4_c2.pcapng "https://raw.githubusercontent.com/chrissanders/packets/master/cryptowall4_c2.pcapng"
   sudo so-import-pcap cryptowall4_c2.pcapng
   ```
3. **NetSupport RAT:** 5.2 MB, from MTA 2026-02-28. This is a recent, signature-rich full infection chain. It runs from a fake CAPTCHA and ClickFix to NetSupport C2.
   ```bash
   wget -O nsm-rat.pcap.zip "https://www.malware-traffic-analysis.net/2026/02/28/2026-02-28-traffic-analysis-exercise.pcap.zip"
   unzip -P 'infected_20260228' nsm-rat.pcap.zip
   sudo so-import-pcap 2026-02-28-traffic-analysis-exercise.pcap
   ```

## Broader catalog

| Family / sample | Size | Pass | Download | Expected |
|---|---|---|---|---|
| Exploit-kit → CryptoWall4 (chrissanders) | 652 KB | none | `wget "https://raw.githubusercontent.com/chrissanders/packets/master/ek_to_cryptowall4.pcapng"` | ET EXPLOIT_KIT landing/redirect, malware download; Zeek http/files chain |
| DonBot/Buzus spambot (CTU-13 #47) | 5.3 MB | none | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/botnet-capture-20110816-donbot.pcap"` | ET Donbot C2; SMTP-spam; Zeek http beacons + smtp |
| Muhstik IoT (IoT-23 #3-1) | 984 KB | none | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/test.pcap"` | ET SCAN/CINS; IRC C2; Zeek conn fan-out, irc, weird |
| Lumma Stealer (MTA 2026-01-31) | 21.7 MB | `infected_20260131` | `wget "https://www.malware-traffic-analysis.net/2026/01/31/2026-01-31-traffic-analysis-exercise.pcap.zip"` | ET Lumma Stealer fingerprinting + exfil; Zeek http/ssl |
| dnscat2 DNS tunneling (Active Countermeasures) | ~2.5 MB | none | `wget -L -O dnscat2_1hr.pcap "https://www.dropbox.com/s/j5le068uz8n69wk/dnscat2_dns_tunneling_1hr.pcap?dl=1"` | ET DNS-tunnel/TXT; Zeek dns high-entropy TXT (pairs with RITA) |
| DNS-TXT C2 cmds (PCAP-ATTACK) | 36 KB | none | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Command%20and%20Control/cmds%20over%20dns%20txt%20queries%20and%20reponses.pcap"` | DNS-tunnel sigs; Zeek dns anomalous TXT (T1071.004) |
| Zerologon CVE-2020-1472 (PCAP-ATTACK) | 811 KB | none | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Lateral%20Movement/CVE-2020-1472_Zerologon_RPC_NetLogon_NullChallenge_SecChan_6_from_nonDC_to_DC.pcapng"` | ET EXPLOIT Zerologon; Zeek dce_rpc all-zero challenge |
| RDP-tunneled Meterpreter (PCAP-ATTACK) | 5.0 MB | none | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/Command%20and%20Control/rdp_tunneling_meterpreter_portfwd.pcapng"` | ET Meterpreter + RDP-tunnel; Zeek rdp + payload anomaly (T1572) |
| Hakai/Gafgyt IoT (IoT-23 #8-1) | 2.1 MB | none | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap"` | ET Gafgyt/Bashlite; Telnet scan; Zeek SYN floods/weird |
| Torii IoT JA3/TLS (IoT-23 #20-1) | 4.1 MB | none | `curl -k -O "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap"` | TLS/JA3 anomaly; Zeek ssl odd JA3/self-signed, periodic beacon |
| DCSync cred theft (PCAP-ATTACK) | ~11 KB | none | `wget "https://raw.githubusercontent.com/sbousseaden/PCAP-ATTACK/master/CredAccess/DCSync_krbtgt_dcerpc_smb.pcapng"` | Zeek dce_rpc DRSGetNCChanges (T1003.006) |
| SmartApeSG→NetSupport→StealC v2 (MTA 2025-08-20) | 63 MB | `infected_20250820` | `wget "https://www.malware-traffic-analysis.net/2025/08/20/2025-08-20-SmartAgeSG-Netsupport-RAT-with-StealCv2.pcap.zip"` | Multi-stage, many ET MALWARE hits (loud test) |

## Safety and handling notes

- **The MTA password scheme changed.** The password is no longer the flat `infected`. It is now `infected_<YYYYMMDD>`, and the date is the post date. For 2026-02-28 the password is `infected_20260228`. The MTA about page shows the password in `about.gif`.
- The `*-files-*.zip` and `files-from-the-infection.zip` archives hold live malware binaries. **Download only the `*.pcap.zip`** from MTA.
- **Stratosphere and MCFP** pcaps are plain libpcap files with no password. Their certificate chain is old, so use `curl -k`. The browsable index is at `https://mcfp.felk.cvut.cz/publicDatasets/`.
- **CTU-13:** use `botnet-capture-*.pcap`, because it carries full payloads and the content rules fire. Avoid the `*.truncated.pcap` files, because they have no payloads.
- **GitHub raw** holds the chrissanders, PCAP-ATTACK and suricata-verify samples. They are plaintext and need no password. URL-encode the spaces as `%20` and quote the local paths.
- A current ruleset *probably does not* fire the named `ET MALWARE` hits on an old dataset. CTU-13 is from 2011 and IoT-23 is from 2018. The Zeek protocol behaviours are the durable signal on those datasets. The MTA-2026 samples and the GitHub samples are the most likely to fire a named ET signature.
- The timestamps are the original time of the PCAP, so the imported alerts land in the past. A hunt by `alert_es_id` works anyway. To see the alerts in the live alerts pane, widen the time range. You can also shift the PCAP to about now with `editcap -t <offset>` before you import it.
