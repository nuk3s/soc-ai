---
title: Lateral movement triage (SMB / PsExec / RDP)
tags: [lateral-movement, smb, rdp, psexec, admin-shares]
rules:
  - "ET POLICY SMB2 NT Create AndX Request For an Executable File In A Temp Directory"
  - "ET POLICY RDP connection confirmed"
  - "ET INFO PsExec service created"
---

# Lateral movement triage (SMB / PsExec / RDP)

Lateral movement alerts are hard because administrators and attackers use the *same
tools*. The MITRE ATT&CK techniques are **T1021.001** Remote Desktop Protocol,
**T1021.002** SMB/Windows Admin Shares, **T1570** Lateral Tool Transfer and **T1569.002**
Service Execution. The mechanism almost never decides the verdict. The actor, the source,
the time and the next action decide the verdict.

## Establish the actor context

- **Account**. Identify the account that authenticated for the SMB session or the Remote
  Desktop Protocol (RDP) logon. Check whether an admin account is expected to touch this
  target. A *user* workstation account that authenticates to the admin share of another
  workstation is abnormal in almost every environment.
- **Source**. Check whether the source is a management host or a jump box. Such a source
  is expected. An ordinary workstation or server has no business that administers other
  hosts. Workstation-to-workstation admin traffic is the pattern of a worm or a
  hands-on-keyboard attacker.
- **Time**. Check whether the time falls inside the working pattern of the administrator.
  A session at 03:00 on a weekend falls outside that pattern. Correlate the session with
  the other activity of the administrator. A real administrator generates parallel
  context such as a ticket, a virtual private network session and other managed hosts. An
  attacker with stolen credentials usually generates no parallel context.

## Read the mechanism for intent

- **Service execution in the style of PsExec**. Look for a service creation on the target
  with a random or copied name. Look for an executable written to ADMIN$ immediately
  before the service creation. Legitimate software deployment creates services too.
  Deployment runs from *deployment servers*, uses *consistent* service names and hits many
  hosts at once.
  Escalate a one-off service with a random name from a workstation source.
- **SMB executable and script writes**. A .exe, .dll, .ps1 or .bat file written to an
  admin share outside a deployment window is tool transfer. The admin shares are C$ and
  ADMIN$. Record the filename and the hash. Pivot the hash across the network.
- **RDP**. A single interactive session is thin evidence alone. Chained RDP escalates the
  alert. The chain runs from A to B and then from B to C within minutes. A source and
  target pair seen for the first time escalates the alert. RDP from a host that
  recently received a suspicious file escalates the alert.

## Scope before verdict

Lateral movement covers 2 or more hosts by definition. Pivot on the source and on the
account. List everything else they touched in the 2 hours before the alert and the 2
hours after it. A source that reaches many targets performs discovery and movement.
Sequential IP order, or many failures and then one success, shows the same. Build the
host list. The investigation needs the graph of the movement.

## Verdict guidance

- **Escalate** a service creation with a random name. Escalate a tool transfer to an
  admin share. Escalate an admin session from a workstation source. Escalate any movement
  chain that follows another alert on the source, such as a phish, a beacon or credential
  access. Recommend isolation of the source. Recommend a review of the credentials of the
  account.
- **Dismiss** documented deployment or patching activity. Name the product and the
  deployment server. Dismiss a scheduled backup job or inventory job. Dismiss help-desk
  remote support that matches its normal source and hours.
- Check the next 30 min on the target if you are unsure. New outbound connections, new
  services or credential dumping artifacts settle the question.
