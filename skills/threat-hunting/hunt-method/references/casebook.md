# Casebook — behaviours observed in public DFIR case reports

Every entry below is a **paraphrase of published intrusion reports**, used to keep the hunt
hypotheses anchored in tradecraft that has actually been seen. Read the source for the full
chain, evidence and IOCs; nothing here is copied verbatim, and no case data is redistributed.

Use a case as a *shape*, never as an IOC list: the value is in the discriminator, not the hash.

## C1 — Edge appliance exploited, then hands-on-keyboard to ransomware
*Confluence template injection (CVE-2023-22527) → ELPACO.*
Source: https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/

- **Initial access:** unpatched internet-facing Java application; template injection reaching
  RCE. Two sources used the same exploit — the first ran `whoami` and left, the second stayed.
- **Execution:** a loader binary dropped into the application's install directory; it fetched
  its next stage from the same host that exploited the appliance, on an unusual high port.
- **Credential access:** ~30 seconds after the loader started, a remote thread was created in
  the credential process; memory was dumped shortly after.
- **Persistence:** new local accounts created seconds after the dump, plus a batch file written
  into the application's install path.
- **Evasion:** the loader opened handles to several unrelated processes (application server,
  console host, database, JVM, a system service) before the credential access.
- **Discovery → lateral:** commands ran as children of the application server; remote execution
  to a domain controller produced children of the WMI provider host.
- **Impact:** ransomware after hands-on-keyboard staging.

**Discriminators:** application-server parent spawning a shell; new executable *inside* the
application install path; handle-open fan-out across unrelated processes; remote execution whose
parent is the WMI provider host; new account creation within seconds of credential access.

## C2 — Message-broker RCE, evicted, re-entered, then ransomware
*Apache ActiveMQ (CVE-2023-46604) → LockBit.*
Source: https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/

- **Initial access:** exposed broker service; RCE delivered through an XML payload interpreted by
  the Java process. The actor was removed and **returned to the same unpatched server 18 days
  later** to finish the job.
- **Execution:** the Java service process is the parent of the commands in the XML — a service
  account spawning a shell is the tell, not the shell itself.
- **Persistence:** a commercial remote-access tool installed as an **autostart service**; a new
  service created to host the attacker's payload.
- **Evasion:** a batch script written by an **injected system process**, not by a user session.
- **Credential access:** process-memory dumps on multiple hosts; the call trace was unknown
  (indicative of injected code) and the granted access was read-for-dump.
- **Discovery → lateral:** no discovery immediately after the exploit; SMB traffic to remote
  hosts began about an hour later, followed by remote service execution on day 1 and day 18.
- **Impact:** ransomware deployed on the return visit.

**Discriminators:** Java/broker service as a parent of `cmd`; service creation from a path that
is not a product directory; a remote-access tool installing itself as a service; file writes
attributed to a system process; re-compromise of a host you already remediated (patch gap).

## C3 — Search-ad lure to loader to C2 framework, then hands-on-keyboard
*Bing search ads → fake installer → Bumblebee → AdaptixC2 → Akira.*
Source: https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/

- **Initial access:** malvertising in search results led to a trojanised installer; the user
  executed an MSI from their own profile directory.
- **Execution:** installer package running from Desktop/Downloads is the parent of unexpected
  children.
- **Credential access:** the administrative dump utility was invoked through a signed system
  library from a shell, after enumerating the credential process by name to get its PID.
- **Privilege escalation / persistence:** a new domain account was created with a predictable
  backup-style name and immediately added to a highly privileged group.
- **Discovery:** a rapid enumeration sequence (system info, domain and trust listing, group
  membership, privileged-group enumeration) completed in under five minutes.
- **Lateral:** remote desktop logons using the freshly created account.
- **Collection / exfiltration:** a consumer FTP client installed on servers, with data staged
  in a program-data directory before large outbound transfers.
- **Evasion:** command names invoked with mixed case.

**Discriminators:** MSI from a user profile with a suspicious child; signed-utility abuse for
memory dumping preceded by process enumeration; account creation plus privileged-group add in
one breath; enumeration burst under five minutes; FTP client on a server role; staging
directory growth before egress.

## C4 — Password spray against exposed remote desktop → RansomHub
Source: https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/

- **Initial access:** spray against an internet-facing remote-desktop service; a single account
  with a weak password yielded the foothold.
- **Shape:** many accounts, few attempts each, one source — the classic spray silhouette, and
  the logon that succeeds is usually not the account with the most failures.

**Discriminators:** success after a distributed failure pattern; the successful account's first
interactive logon from an unfamiliar network; remote-desktop logon types on a host that
normally only serves file shares.

## C5 — ClickFix / fake-converter lures and SEO poisoning
*KongTuke FileFix → Interlock RAT.* Source:
https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/
*BengalSEO SEO-poisoning campaign (2026).* Source:
https://thedfirreport.com/2026/08/24/bengalseo-part-1-anatomy-of-the-operation/

- **Initial access:** users are walked into running a command themselves — a "fix this file"
  prompt or a poisoned search result — so the execution parent is the user's own shell or
  file manager, not an exploit.
- **Shape:** the lure and the payload live on infrastructure the user reached by searching, not
  by mail; mail-only hunting will miss this entire family.

**Discriminators:** shell started by a browser or file manager with a paste-style one-liner;
user profile downloads followed by an installer; search-referral traffic preceding execution.

## C6 — Multi-stage loader chain with a long dwell
*Lunar Spider: tax-form lure → MSI → Brute Ratel, plus additional loaders.*
Source: https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/

- **Initial access:** a script file disguised as a document, delivered to the user, launching an
  installer that deployed a commercial-grade C2 framework.
- **Dwell:** the intrusion ran for weeks with multiple malware families — detection has to
  survive reboots, re-images and tool changes, not just the first day.

**Discriminators:** document-shaped script files launching installers; commercial C2 frameworks
in an estate that has no red-team engagement booked; long quiet periods punctuated by tooling
changes.

## How to use the casebook in a hunt

1. Pick the case whose **initial access** matches your exposure.
2. Take its per-tactic behaviours as the hypothesis set for the matching `hunt-*` skills.
3. Hunt the discriminator, not the IOC: the same tool will be renamed, the parent-child shape
   will not.
4. Report new discriminators back into this file — with a source link, never with victim data.

## C7 — Exposed exploitation infrastructure sets the noise floor
*Bissa scanner server.* Source:
https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/

- An exposed scanning server gave visibility into industrialised, multi-victim exploitation with
  credential harvesting — automated, continuous, and credential-aware rather than opportunistic.
- Calibration value: the scanner traffic in your edge logs is the *background*, and a single
  source that deviates from it (slower, targeted, one product) is the signal.
