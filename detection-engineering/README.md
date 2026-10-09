# Custom Wazuh Correlation Rule — SMB Brute-Force Detection (Rule 100100)

## Background
While building SOC Home Lab detections for SMB brute-force (Event ID 4625), I found
Wazuh ships a built-in correlation rule for this:

- **Rule 60204** ("Multiple Windows Logon Failures"): groups failures by
  `win.eventdata.ipAddress`, using the `$MS_FREQ` variable (default 8 attempts) over a
  240-second window. It covers the entire `authentication_failed` group — not just SMB —
  and carries no MITRE ATT&CK mapping.

Rather than duplicate this, I built a tuned, narrower rule on top of it.

## Custom Rule (100100)
```xml
<group name="windows,authentication_failures,custom,">
  <rule id="100100" level="12" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Possible brute force: 5+ failed Windows logons (4625) from same source IP within 60s</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>
</group>
```

| | Rule 60204 (built-in) | Rule 100100 (custom) |
|---|---|---|
| Scope | Any `authentication_failed` event | Specifically SMB 4625 (SID 60122) |
| Threshold | 8 attempts / 240s | 5 attempts / 60s |
| MITRE mapping | None | T1110.001 (Password Guessing) |
| Alert level | 10 | 12 |

## Testing

**Attack tooling:** NetExec (`nxc`) against SMB — Hydra's legacy SMBv1 module failed
against the target (Windows 11 disables SMBv1 by default; confirmed via
`Get-WindowsOptionalFeature`).

**Positive test:** Ran `nxc smb <target> -u hawk -p passwords.txt` (8 passwords) from
Kali (172.16.62.132) against the Windows 11 VM (172.16.62.134). Rule 100100 fired at
level 12, correctly correlating 5 failures from the same source IP within the 60s
window. See `evidence/positive-test-alert.json` for the full alert, including the
matched `ipAddress` field and MITRE enrichment.

**Negative test:** Ran the same attack with only 3 passwords
(`head -3 passwords.txt > few.txt`). Only individual rule 60122 events were logged —
100100 did not fire, confirming the 5-attempt threshold is enforced correctly rather
than triggering on any failure. See `evidence/negative-test-results.json`.

## Limitations
- Misses distributed brute-force (same password tried across many source IPs).
- Misses slow/low-and-slow attacks that stay under 5 attempts per 60s.
- Local logons report no IP (`-`), so they won't group under this rule.
- Kerberos authentication failures (Event ID 4771) aren't covered — only NTLM/4625.

## Next steps
- Add a complementary rule grouped by target username instead of source IP, to catch
  password-spraying from many IPs against one account.
- Extend coverage to Event ID 4771 for Kerberos-based brute-force.
