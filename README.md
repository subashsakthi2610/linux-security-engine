# 🔐 Automated Linux Security Engine

A Python-based security automation suite that performs **CIS Benchmark auditing**, **SSH/sudo attack detection via log parsing**, and **automated fleet-wide remediation over SSH** using Paramiko.

---

## Features

| Module | What It Does |
|---|---|
| `CISAuditor` | Scans local Linux system against CIS Benchmark checks and generates a scored report |
| `LogParser` | Parses `/var/log/auth.log` with regex to detect SSH brute-force IPs and sudo abuse, then blocks them via `iptables` |
| `FleetRemediator` | SSHes into multiple remote Linux servers via Paramiko and auto-applies security fixes |

---

## Architecture

```
security_engine.py
├── CISAuditor          ── runs on local machine
│   ├── check_ssh_root_login()
│   ├── check_password_max_days()
│   ├── check_firewall_active()
│   ├── check_world_writable_files()
│   ├── check_ssh_protocol()
│   ├── check_sudo_log_enabled()
│   └── generate_report()  ──► audit_report.json
│
├── LogParser           ── reads /var/log/auth.log
│   ├── parse()         ──► flagged IPs + users
│   └── block_ips()     ──► iptables DROP rules
│
└── FleetRemediator     ── connects via SSH (Paramiko)
    ├── remediate_host()
    └── remediate_fleet()  ──► applies STANDARD_REMEDIATIONS
```

---

## Requirements

- Python 3.10+
- Linux (Ubuntu / Debian / CentOS)
- `paramiko` for remote SSH remediation

```bash
pip install paramiko
```

---

## Quick Start

### Run locally
```bash
git clone https://github.com/subashsakthi279/linux-security-engine.git
cd linux-security-engine
pip install paramiko
python3 security_engine.py
```

### Expected output
```
[1/3] Running CIS Audit...
✅ [PASS] SSH Root Login Disabled
❌ [FAIL] Sudo Logging Enabled
⚠️  [WARN] SSH Protocol 2

  CIS AUDIT REPORT
  ═══════════════════════════════════
  Total Checks : 6
  Passed       : 4
  Failed       : 1
  Warnings     : 1
  Score        : 67%

[2/3] Parsing auth logs for attacks...
  SSH attack IPs  : ['192.168.1.101']
  Sudo abuse users: ['baduser']

[3/3] Fleet Remediation ready.
```

Audit results are saved to `audit_report.json`.

---

## CIS Benchmark Checks

| Check | CIS Reference | What It Verifies |
|---|---|---|
| SSH Root Login Disabled | 5.2.8 | `PermitRootLogin no` in sshd_config |
| Password Max Days ≤ 365 | 5.4.1.1 | `PASS_MAX_DAYS` in login.defs |
| Firewall Active | 3.6 | ufw or iptables running |
| No World-Writable Files | 6.1.10 | No `chmod o+w` files outside /tmp |
| SSH Protocol 2 | 5.2.2 | Protocol version in sshd_config |
| Sudo Logging Enabled | 5.3.4 | `Defaults logfile` in sudoers |

---

## Fleet Remediation

Connect to remote servers and auto-apply fixes:

```python
from security_engine import FleetRemediator, STANDARD_REMEDIATIONS

remediator = FleetRemediator(
    username="admin",
    key_path="/path/to/private_key.pem"
)

fleet = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
results = remediator.remediate_fleet(fleet, STANDARD_REMEDIATIONS)
```

### Standard Remediations Applied
- Disable SSH root login
- Set password max days to 90
- Enable UFW firewall
- Enable sudo logging
- Remove world-writable file permissions

---

## Attack Detection & IP Blocking

```python
from security_engine import LogParser

parser = LogParser(log_path="/var/log/auth.log", threshold=5)
attack_data = parser.parse()

# Block flagged IPs (dry_run=False to actually block)
parser.block_ips(attack_data["flagged_ips"], dry_run=True)
```

Set `dry_run=False` to apply real `iptables DROP` rules.

---

## Where to Run This

| Environment | How |
|---|---|
| **Local VM** | Install Ubuntu on VirtualBox — free, safe to test |
| **AWS EC2** | Spin up a free-tier Linux instance — most resume-realistic |
| **Multiple VMs** | Use FleetRemediator to SSH into 2–3 VMs and simulate a real server fleet |

> ⚠️ Never run on a machine you don't own. `iptables` and `sshd_config` changes are real system modifications.

---

## Project Structure

```
linux-security-engine/
├── security_engine.py     # Main script (all 3 modules)
├── audit_report.json      # Generated after running (auto-created)
├── security_engine.log    # Log file (auto-created)
└── README.md
```

---

## Skills Demonstrated

- Python scripting (`subprocess`, `re`, `logging`, `json`)
- Linux security hardening (CIS Benchmarks, SSH, iptables)
- Log parsing and attack detection with regex
- Remote server automation via Paramiko SSH
- Best practices: dry-run safety, IP validation, error handling

---

## Resume Bullet Points

> *"Built Python security suite for automated CIS hardening and auditing across Linux systems; engineered log parsing (re, subprocess) to detect and block SSH/sudo attacks; orchestrated fleet-wide remediation via Paramiko SSH."*

---

## Tech Stack

`Python 3.12` `Paramiko` `subprocess` `regex` `iptables` `CIS Benchmarks` `Linux`
