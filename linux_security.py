#!/usr/bin/env python3
"""
=============================================================
  Automated Linux Security Engine
  CIS Hardening | Log Parsing | Fleet Remediation via SSH
=============================================================
"""

import re
import subprocess
import logging
import json
from datetime import datetime
from collections import defaultdict

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("security_engine.log"),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# MODULE 1: CIS HARDENING & AUDITING
# ─────────────────────────────────────────────

class CISAuditor:
    """
    Audits the local Linux system against a subset of CIS Benchmark checks.
    Each check returns a dict: { 'check': str, 'status': 'PASS'|'FAIL'|'WARN', 'detail': str }
    """

    def run_command(self, cmd: str) -> tuple[int, str]:
        """Run a shell command and return (returncode, output)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.returncode, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return -1, "Command timed out"
        except Exception as e:
            return -1, str(e)

    def check_ssh_root_login(self) -> dict:
        """CIS 5.2.8 — Ensure SSH root login is disabled."""
        _, output = self.run_command("grep -i '^PermitRootLogin' /etc/ssh/sshd_config")
        if "no" in output.lower():
            return {"check": "SSH Root Login Disabled", "status": "PASS", "detail": output}
        return {"check": "SSH Root Login Disabled", "status": "FAIL",
                "detail": output or "PermitRootLogin not set to 'no'"}

    def check_password_max_days(self) -> dict:
        """CIS 5.4.1.1 — Ensure password expiration is 365 days or less."""
        _, output = self.run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
        try:
            days = int(output.split()[1])
            if days <= 365:
                return {"check": "Password Max Days ≤ 365", "status": "PASS", "detail": output}
            return {"check": "Password Max Days ≤ 365", "status": "FAIL",
                    "detail": f"PASS_MAX_DAYS is {days} (should be ≤ 365)"}
        except (IndexError, ValueError):
            return {"check": "Password Max Days ≤ 365", "status": "WARN",
                    "detail": "Could not determine PASS_MAX_DAYS"}

    def check_firewall_active(self) -> dict:
        """CIS 3.6 — Ensure a firewall (ufw/iptables) is active."""
        code, output = self.run_command("ufw status")
        if code == 0 and "active" in output.lower():
            return {"check": "Firewall Active (ufw)", "status": "PASS", "detail": "ufw is active"}
        code2, _ = self.run_command("iptables -L -n")
        if code2 == 0:
            return {"check": "Firewall Active (iptables)", "status": "WARN",
                    "detail": "iptables present but ufw inactive"}
        return {"check": "Firewall Active", "status": "FAIL", "detail": "No active firewall detected"}

    def check_world_writable_files(self) -> dict:
        """CIS 6.1.10 — Ensure no world-writable files exist outside /tmp."""
        _, output = self.run_command(
            "find / -xdev -type f -perm -0002 ! -path '/tmp/*' 2>/dev/null | head -20"
        )
        if not output:
            return {"check": "No World-Writable Files", "status": "PASS",
                    "detail": "No world-writable files found outside /tmp"}
        return {"check": "No World-Writable Files", "status": "FAIL",
                "detail": f"World-writable files found:\n{output}"}

    def check_ssh_protocol(self) -> dict:
        """CIS 5.2.2 — Ensure SSH Protocol 2 is used."""
        _, output = self.run_command("grep -i '^Protocol' /etc/ssh/sshd_config")
        if "2" in output:
            return {"check": "SSH Protocol 2", "status": "PASS", "detail": output}
        return {"check": "SSH Protocol 2", "status": "WARN",
                "detail": "Protocol line not explicitly set (defaults to 2 on modern systems)"}

    def check_sudo_log_enabled(self) -> dict:
        """CIS 5.3.4 — Ensure sudo logging is enabled."""
        _, output = self.run_command("grep -r 'logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
        if output:
            return {"check": "Sudo Logging Enabled", "status": "PASS", "detail": output}
        return {"check": "Sudo Logging Enabled", "status": "FAIL",
                "detail": "No sudo logfile directive found"}

    def run_all_checks(self) -> list[dict]:
        """Run all CIS checks and return a list of results."""
        checks = [
            self.check_ssh_root_login,
            self.check_password_max_days,
            self.check_firewall_active,
            self.check_world_writable_files,
            self.check_ssh_protocol,
            self.check_sudo_log_enabled,
        ]
        results = []
        for check_fn in checks:
            result = check_fn()
            results.append(result)
            status_icon = "✅" if result["status"] == "PASS" else ("❌" if result["status"] == "FAIL" else "⚠️")
            logger.info(f"{status_icon}  [{result['status']}] {result['check']}: {result['detail']}")
        return results

    def generate_report(self, results: list[dict]) -> str:
        """Generate a summary report from audit results."""
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        warned = sum(1 for r in results if r["status"] == "WARN")
        total = len(results)
        score = int((passed / total) * 100) if total else 0

        report = [
            "\n" + "=" * 55,
            "  CIS AUDIT REPORT",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 55,
            f"  Total Checks : {total}",
            f"  Passed       : {passed}",
            f"  Failed       : {failed}",
            f"  Warnings     : {warned}",
            f"  Score        : {score}%",
            "=" * 55,
        ]
        for r in results:
            report.append(f"  [{r['status']:4s}] {r['check']}")
        report.append("=" * 55)
        return "\n".join(report)


# ─────────────────────────────────────────────
# MODULE 2: LOG PARSER — ATTACK DETECTION
# ─────────────────────────────────────────────

class LogParser:
    """
    Parses /var/log/auth.log (or a provided log file) for:
      - SSH brute-force attempts
      - sudo privilege escalation abuse
    Returns offending IPs and usernames with attempt counts.
    """

    # Regex patterns for common auth log events
    SSH_FAILURE_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+)"
    )
    SSH_INVALID_USER_PATTERN = re.compile(
        r"Invalid user (\S+) from ([\d\.]+)"
    )
    SUDO_FAILURE_PATTERN = re.compile(
        r"sudo:.*?(\w+).*?3 incorrect password attempts"
    )
    SUDO_BAD_USER_PATTERN = re.compile(
        r"sudo:.*?user (\w+) NOT in sudoers"
    )

    def __init__(self, log_path: str = "/var/log/auth.log", threshold: int = 5):
        self.log_path = log_path
        self.threshold = threshold  # attempts before flagging as attack

    def parse(self) -> dict:
        """
        Parse the log file and return a dict of:
          - ssh_attacks: { ip: count }
          - sudo_attacks: { username: count }
          - flagged_ips: [ ip, ... ]   (above threshold)
          - flagged_users: [ user, ... ]
        """
        ssh_attempts = defaultdict(int)   # ip -> count
        sudo_attempts = defaultdict(int)  # user -> count

        try:
            with open(self.log_path, "r", errors="replace") as f:
                for line in f:
                    # SSH failures
                    for pattern in [self.SSH_FAILURE_PATTERN, self.SSH_INVALID_USER_PATTERN]:
                        match = pattern.search(line)
                        if match:
                            _, ip = match.group(1), match.group(2)
                            ssh_attempts[ip] += 1

                    # Sudo abuse
                    for pattern in [self.SUDO_FAILURE_PATTERN, self.SUDO_BAD_USER_PATTERN]:
                        match = pattern.search(line)
                        if match:
                            user = match.group(1)
                            sudo_attempts[user] += 1

        except FileNotFoundError:
            logger.warning(f"Log file not found: {self.log_path}. Using demo data.")
            # Demo data for testing without root access
            ssh_attempts = {"192.168.1.101": 87, "10.0.0.55": 12, "172.16.0.4": 3}
            sudo_attempts = {"baduser": 6, "tempaccount": 2}

        flagged_ips = [ip for ip, count in ssh_attempts.items() if count >= self.threshold]
        flagged_users = [u for u, count in sudo_attempts.items() if count >= self.threshold]

        logger.info(f"Log parsing complete. Flagged IPs: {flagged_ips}, Flagged users: {flagged_users}")

        return {
            "ssh_attacks": dict(ssh_attempts),
            "sudo_attacks": dict(sudo_attempts),
            "flagged_ips": flagged_ips,
            "flagged_users": flagged_users,
        }

    def block_ips(self, flagged_ips: list[str], dry_run: bool = True) -> list[str]:
        """
        Block flagged IPs using iptables.
        If dry_run=True, only prints commands without executing.
        Returns list of commands run (or would run).
        """
        commands = []
        for ip in flagged_ips:
            # Basic IP validation before blocking
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                logger.warning(f"Skipping invalid IP: {ip}")
                continue
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            commands.append(cmd)
            if dry_run:
                logger.info(f"[DRY RUN] Would run: {cmd}")
            else:
                code, out = subprocess.run(cmd, shell=True, capture_output=True, text=True).returncode, ""
                if code == 0:
                    logger.info(f"Blocked IP: {ip}")
                else:
                    logger.error(f"Failed to block IP {ip}")
        return commands


# ─────────────────────────────────────────────
# MODULE 3: FLEET REMEDIATION VIA PARAMIKO
# ─────────────────────────────────────────────

class FleetRemediator:
    """
    Connects to remote hosts via SSH (Paramiko) and applies
    security remediations automatically.
    """

    def __init__(self, username: str, key_path: str = None, password: str = None, port: int = 22):
        if not PARAMIKO_AVAILABLE:
            raise ImportError("Paramiko is not installed. Run: pip install paramiko")
        self.username = username
        self.key_path = key_path
        self.password = password
        self.port = port

    def _connect(self, host: str) -> paramiko.SSHClient:
        """Establish an SSH connection to a host."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {
            "hostname": host,
            "port": self.port,
            "username": self.username,
            "timeout": 15,
        }
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise ValueError("Provide either key_path or password for SSH authentication.")

        client.connect(**connect_kwargs)
        return client

    def run_remote_command(self, host: str, command: str) -> tuple[bool, str]:
        """Run a single command on a remote host. Returns (success, output)."""
        try:
            client = self._connect(host)
            _, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            client.close()
            if error:
                return False, error
            return True, output
        except Exception as e:
            logger.error(f"[{host}] Connection/command failed: {e}")
            return False, str(e)

    def remediate_host(self, host: str, remediations: list[dict]) -> dict:
        """
        Apply a list of remediations to a single host.

        Each remediation is a dict:
            { 'name': str, 'command': str }

        Returns a result dict per remediation.
        """
        host_results = {"host": host, "results": []}
        logger.info(f"Starting remediation on {host}...")

        try:
            client = self._connect(host)
        except Exception as e:
            logger.error(f"Cannot connect to {host}: {e}")
            host_results["results"].append({"status": "CONNECTION_FAILED", "error": str(e)})
            return host_results

        for task in remediations:
            name = task.get("name", "Unnamed task")
            cmd = task.get("command", "")
            try:
                _, stdout, stderr = client.exec_command(cmd)
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                status = "OK" if not err else "WARN"
                logger.info(f"  [{host}] {name}: {status}")
                host_results["results"].append({
                    "name": name,
                    "command": cmd,
                    "status": status,
                    "output": out,
                    "error": err,
                })
            except Exception as e:
                logger.error(f"  [{host}] {name} FAILED: {e}")
                host_results["results"].append({
                    "name": name,
                    "command": cmd,
                    "status": "FAILED",
                    "error": str(e),
                })

        client.close()
        return host_results

    def remediate_fleet(self, hosts: list[str], remediations: list[dict]) -> list[dict]:
        """Apply remediations across a fleet of hosts."""
        all_results = []
        for host in hosts:
            result = self.remediate_host(host, remediations)
            all_results.append(result)
        return all_results


# ─────────────────────────────────────────────
# STANDARD REMEDIATIONS LIBRARY
# ─────────────────────────────────────────────

STANDARD_REMEDIATIONS = [
    {
        "name": "Disable SSH root login",
        "command": "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
    },
    {
        "name": "Set password max days to 90",
        "command": "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
    },
    {
        "name": "Enable UFW firewall",
        "command": "ufw --force enable",
    },
    {
        "name": "Enable sudo logging",
        "command": "echo 'Defaults logfile=/var/log/sudo.log' >> /etc/sudoers",
    },
    {
        "name": "Remove world-writable permissions (outside /tmp)",
        "command": "find / -xdev -type f -perm -0002 ! -path '/tmp/*' -exec chmod o-w {} \\; 2>/dev/null",
    },
]


# ─────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

def main():
    print("\n" + "=" * 55)
    print("  AUTOMATED LINUX SECURITY ENGINE")
    print("=" * 55)

    # ── Step 1: CIS Audit ──────────────────────────────────
    print("\n[1/3] Running CIS Audit...\n")
    auditor = CISAuditor()
    results = auditor.run_all_checks()
    print(auditor.generate_report(results))

    # Save audit report as JSON
    with open("audit_report.json", "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Audit report saved to audit_report.json")

    # ── Step 2: Log Parsing ────────────────────────────────
    print("\n[2/3] Parsing auth logs for attacks...\n")
    parser = LogParser(log_path="/var/log/auth.log", threshold=5)
    attack_data = parser.parse()

    print(f"  SSH attack IPs  : {attack_data['flagged_ips']}")
    print(f"  Sudo abuse users: {attack_data['flagged_users']}")

    if attack_data["flagged_ips"]:
        print("\n  Blocking flagged IPs (dry run)...")
        parser.block_ips(attack_data["flagged_ips"], dry_run=True)

    # ── Step 3: Fleet Remediation ──────────────────────────
    print("\n[3/3] Fleet Remediation (demo — no real hosts)\n")
    print("  To run on real hosts, initialize FleetRemediator like this:")
    print("""
    remediator = FleetRemediator(
        username="admin",
        key_path="/path/to/private_key.pem"
    )
    fleet = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    results = remediator.remediate_fleet(fleet, STANDARD_REMEDIATIONS)
    """)
    print("  STANDARD_REMEDIATIONS includes:")
    for r in STANDARD_REMEDIATIONS:
        print(f"    • {r['name']}")

    print("\n✅ Security Engine run complete. See security_engine.log for details.\n")


if __name__ == "__main__":
    main()