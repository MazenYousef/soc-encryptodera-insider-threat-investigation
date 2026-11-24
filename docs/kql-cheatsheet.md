# KQL Techniques Used in This Investigation

[← Back to the main README](../README.md)

| Technique | Pattern | Used for |
|---|---|---|
| Look up a value once, reuse it | `let barry_ip = toscalar(Employees \| where name == "Barry Shmelly" \| project ip_addr);` | Pivoting from a person to their IP, host or username |
| Build a list, then filter by it | `let hosts = ProcessEvents \| where ... \| distinct hostname;` then `\| where hostname in (hosts)` | Finding login sources common to all discovery hosts |
| Enrich with the directory | `\| join kind=inner (Employees \| project ip_addr, name, role) on $left.src_ip == $right.ip_addr` | Turning IPs into people and roles |
| Scope an incident | `\| summarize hosts = dcount(hostname), first_seen = min(timestamp)` | 306 ransomed hosts; first ransom note |
| Find patient zero | `\| order by timestamp asc \| take 1` | First victim; first discovery host |
| Temporal analysis | `\| where timestamp between (datetime(2024-02-16) .. datetime(2024-02-18))` | Everything that ran around the encryption |
| Search several terms | `\| where process_commandline has_any ("sekurlsa", "lsadump")` | Behaviour-based detection |
| Pattern matching | `\| where filename matches regex @"\.(docx\|xlsx)\.exe$"` | Double-extension payloads |
| Extract and decode | `extract(@"(?i)-enc\w*\s+([A-Za-z0-9+/=]+)", 1, cmd)` then `base64_decode_tostring()` | Revealing encoded PowerShell |
| Baseline a flow | `\| summarize active_days = dcount(bin(timestamp, 1d)), total_bytes = sum(bytes)` | Showing that Jane's FTP traffic was recurring |
| Rank by volume | `\| summarize sum(bytes) by dest_ip \| top 5 by sum_bytes desc` | Spotting the exfiltration destination |
| External-only traffic | `\| where not(ipv4_is_private(dest_ip))` | Outbound FTP detection |

## Investigation pivots used

```
Ransom note ─► first host ─► encryption cmd ─► binary drop time ─► nearby cmds (gpupdate, PowerShell)
     └► GPO means domain admin ─► discovery hosts ─► common login IP ─► DC login account
          └► where that account was used ─► Mimikatz ─► how the actor got there (local admin)
               └► non-IT user of local admin (Robin) ─► phish from Barry ─► Barry's sign-in IP
```

## Commands an analyst should recognise

| Command | Why it matters |
|---|---|
| `systeminfo` | Host reconnaissance, often the first thing run after compromise |
| `nltest /dclist:<domain>` | Lists domain controllers; the attacker is looking for the crown jewels |
| `gpupdate /force` | Forces a Group Policy refresh; can push malware domain-wide from a compromised DC |
| `sekurlsa::logonpasswords` | Mimikatz: dumps credentials from LSASS memory |
| `powershell -enc <base64>` | Encoded PowerShell, hides the real command from casual review |
| `7z a -p<password>` | Password-protected archive; defeats content inspection by DLP |
