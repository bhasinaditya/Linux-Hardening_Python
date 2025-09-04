import os
import subprocess
import platform
import re
import sys


def run_command(command, shell=False):
    """Run a shell command and return output, handling errors."""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        return result.stdout.strip(), True
    except subprocess.CalledProcessError as e:
        return e.stderr.strip(), False


def detect_distro():
    """Detect Linux distribution family (debian or rhel)."""
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release') as f:
            os_release = f.read().lower()
        if 'debian' in os_release or 'ubuntu' in os_release:
            return 'debian'
        elif 'centos' in os_release or 'rhel' in os_release or 'amazon' in os_release or 'fedora' in os_release:
            return 'rhel'
    return 'unknown'


def check_initial_setup(distro):
    """Check initial setup configurations."""
    print("\nStep 1: Initial Setup")

    # 1.1 Check for Updates and Patches
    print("1.1 System Updates and Patches")
    if distro == 'debian':
        output, success = run_command(['apt', 'list', '--upgradable'])
        current = "Updates available" if success and output else "System up-to-date"
        recommended = "System fully updated (run 'apt update && apt upgrade')"
    elif distro == 'rhel':
        output, success = run_command(['yum', 'check-update'])
        current = "Updates available" if success and output else "System up-to-date"
        recommended = "System fully updated (run 'yum update')"
    else:
        current = "Unknown distribution"
        recommended = "Identify distribution and apply updates"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 1.2 Check for Unnecessary Packages (e.g., telnet)
    print("\n1.2 Unnecessary Packages (e.g., telnet)")
    output, success = run_command(['which', 'telnet'])
    current = "Telnet installed" if success and output else "Telnet not installed"
    recommended = "Remove telnet if installed"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 1.3 Check Automatic Updates
    print("\n1.3 Automatic Updates")
    if distro == 'debian':
        output, success = run_command(['dpkg', '-l', 'unattended-upgrades'])
        current = "unattended-upgrades installed" if success else "unattended-upgrades not installed"
        recommended = "Install and configure unattended-upgrades"
    elif distro == 'rhel':
        output, success = run_command(['rpm', '-q', 'yum-cron'])
        current = "yum-cron installed" if success else "yum-cron not installed"
        recommended = "Install and enable yum-cron"
    else:
        current = "Unknown distribution"
        recommended = "Configure automatic updates"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


def check_file_system_configuration():
    """Check file system configurations."""
    print("\nStep 2: File System Configuration")

    # 2.1 Check Partition Options
    print("2.1 Partition Options")
    current = "Manual check required for /etc/fstab"
    recommended = "Add nosuid, nodev, noexec to /tmp, /var, etc. in /etc/fstab"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 2.2 Check Disabled File Systems
    print("\n2.2 Disabled File Systems")
    cis_conf = '/etc/modprobe.d/CIS.conf'
    filesystems = ['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf']
    current = []
    if os.path.exists(cis_conf):
        with open(cis_conf) as f:
            content = f.read()
            for fs in filesystems:
                if f'install {fs} /bin/true' in content:
                    current.append(f"{fs} disabled")
                else:
                    current.append(f"{fs} not disabled")
    else:
        current = [f"{fs} not disabled (CIS.conf missing)" for fs in filesystems]
    recommended = f"Disable {', '.join(filesystems)} in {cis_conf}"
    print(f"Current: {', '.join(current)}")
    print(f"Recommended: {recommended}")

    # 2.3 Check USB Storage
    print("\n2.3 USB Storage")
    usb_conf = '/etc/modprobe.d/usb-storage.conf'
    current = "USB storage disabled" if os.path.exists(usb_conf) and "install usb-storage /bin/true" in open(
        usb_conf).read() else "USB storage enabled"
    recommended = "Disable USB storage in /etc/modprobe.d/usb-storage.conf"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


def check_network_configuration(distro):
    """Check network configurations."""
    print("\nStep 3: Network Configuration")

    # 3.1 Check Unnecessary Services
    print("3.1 Unnecessary Network Services")
    services = ['telnet.socket', 'rlogin', 'rsh']
    current = []
    for service in services:
        output, success = run_command(['systemctl', 'is-enabled', service])
        current.append(f"{service}: {output}" if success else f"{service}: not installed")
    recommended = f"Disable {', '.join(services)}"
    print(f"Current: {', '.join(current)}")
    print(f"Recommended: {recommended}")

    # 3.2 Check Hostname and DNS
    print("\n3.2 Hostname and DNS")
    with open('/etc/hostname') as f:
        hostname = f.read().strip()
    hosts_content = open('/etc/hosts').read()
    current = f"Hostname: {hostname}, in /etc/hosts: {'yes' if hostname in hosts_content else 'no'}"
    recommended = "Set hostname in /etc/hostname and add to /etc/hosts"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 3.3 Check Firewall
    print("\n3.3 Firewall")
    if distro == 'debian':
        output, success = run_command(['ufw', 'status'])
        current = output if success else "ufw not installed"
        recommended = "Install and enable ufw with SSH allowed"
    elif distro == 'rhel':
        output, success = run_command(['firewall-cmd', '--state'])
        current = output if success else "firewalld not installed"
        recommended = "Install and enable firewalld with SSH allowed"
    else:
        current = "Unknown distribution"
        recommended = "Configure firewall"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 3.4 Check IPv6
    print("\n3.4 IPv6")
    output, success = run_command(['sysctl', 'net.ipv6.conf.all.disable_ipv6'])
    current = output if success else "IPv6 status unknown"
    recommended = "Disable IPv6 if not needed (net.ipv6.conf.all.disable_ipv6 = 1)"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 3.5 Check Network Parameters
    print("\n3.5 Network Parameters")
    params = [
        'net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects',
        'net.ipv4.conf.default.send_redirects', 'net.ipv4.conf.all.accept_source_route',
        'net.ipv4.conf.default.accept_source_route', 'net.ipv4.conf.all.accept_redirects',
        'net.ipv4.conf.default.accept_redirects', 'net.ipv4.conf.all.log_martians',
        'net.ipv4.conf.default.log_martians'
    ]
    current = []
    for param in params:
        output, success = run_command(['sysctl', param])
        current.append(output if success else f"{param}: unknown")
    recommended = "Set ip_forward=0, send_redirects=0, accept_source_route=0, accept_redirects=0, log_martians=1"
    print(f"Current: {', '.join(current)}")
    print(f"Recommended: {recommended}")


def check_user_authentication(distro):
    """Check user and authentication configurations."""
    print("\nStep 4: User and Authentication Configurations")

    # 4.1 Check Password Policies
    print("4.1 Password Policies")
    pwquality_conf = '/etc/security/pwquality.conf'
    current = []
    if os.path.exists(pwquality_conf):
        with open(pwquality_conf) as f:
            content = f.read()
            for setting in ['minlen', 'dcredit', 'ucredit', 'lcredit', 'ocredit']:
                match = re.search(rf'^{setting}\s*=\s*(\S+)', content, re.MULTILINE)
                current.append(f"{setting}: {match.group(1) if match else 'not set'}")
    else:
        current = ["pwquality.conf not found"]
    recommended = "minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1"
    print(f"Current: {', '.join(current)}")
    print(f"Recommended: {recommended}")

    # 4.2 Check Account Lockout Policy
    print("\n4.2 Account Lockout Policy")
    auth_file = '/etc/pam.d/common-auth' if distro == 'debian' else '/etc/pam.d/system-auth'
    current = "pam_tally2 configured" if os.path.exists(auth_file) and "pam_tally2.so" in open(
        auth_file).read() else "pam_tally2 not configured"
    recommended = "Configure pam_tally2 with deny=5, unlock_time=900"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 4.3 Check Root Login
    print("\n4.3 Root Login via SSH")
    sshd_config = '/etc/ssh/sshd_config'
    current = "PermitRootLogin no" if os.path.exists(sshd_config) and "PermitRootLogin no" in open(
        sshd_config).read() else "PermitRootLogin not disabled"
    recommended = "Set PermitRootLogin no in /etc/ssh/sshd_config"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 4.4 Check SSH Password Authentication
    print("\n4.4 SSH Password Authentication")
    current = "PasswordAuthentication no" if os.path.exists(sshd_config) and "PasswordAuthentication no" in open(
        sshd_config).read() else "PasswordAuthentication enabled"
    recommended = "Set PasswordAuthentication no in /etc/ssh/sshd_config"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


def check_logging_auditing(distro):
    """Check logging and auditing configurations."""
    print("\nStep 5: Logging and Auditing")

    # 5.1 Check Auditd
    print("5.1 Auditd")
    output, success = run_command(['systemctl', 'is-enabled', 'auditd'])
    current = output if success else "auditd not installed"
    recommended = "Enable and start auditd"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 5.2 Check Auditing Rules
    print("\n5.2 Auditing Rules")
    audit_rules = '/etc/audit/rules.d/audit.rules'
    rules = ['/etc/passwd', '/etc/shadow', '/etc/group', '/var/log/lastlog']
    current = []
    if os.path.exists(audit_rules):
        with open(audit_rules) as f:
            content = f.read()
            for rule in rules:
                current.append(f"{rule}: {'monitored' if rule in content else 'not monitored'}")
    else:
        current = [f"{rule}: not monitored" for rule in rules]
    recommended = f"Monitor {', '.join(rules)} in {audit_rules}"
    print(f"Current: {', '.join(current)}")
    print(f"Recommended: {recommended}")

    # 5.3 Check Rsyslog
    print("\n5.3 Rsyslog")
    output, success = run_command(['systemctl', 'is-enabled', 'rsyslog'])
    current = output if success else "rsyslog not installed"
    recommended = "Enable and start rsyslog"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 5.4 Check Log Rotation
    print("\n5.4 Log Rotation")
    current = "Manual check required for /etc/logrotate.conf"
    recommended = "Review and configure log rotation in /etc/logrotate.conf"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


def check_intrusion_detection(distro):
    """Check intrusion detection and file integrity."""
    print("\nStep 6: Intrusion Detection and File Integrity")

    # 6.1 Check AIDE
    print("6.1 AIDE")
    output, success = run_command(['rpm', '-q', 'aide'] if distro == 'rhel' else ['dpkg', '-l', 'aide'])
    current = "AIDE installed" if success else "AIDE not installed"
    recommended = "Install and initialize AIDE, set up cron job"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


def check_security_audits(distro):
    """Check security audits and monitoring."""
    print("\nStep 7: Security Audits and Monitoring")

    # 7.1 Check Lynis
    print("7.1 Lynis")
    output, success = run_command(['rpm', '-q', 'lynis'] if distro == 'rhel' else ['dpkg', '-l', 'lynis'])
    current = "Lynis installed" if success else "Lynis not installed"
    recommended = "Install and run Lynis for system audit"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")

    # 7.2 Monitoring Tools
    print("\n7.2 Monitoring Tools")
    current = "Manual check for Prometheus, Telegraf, Grafana"
    recommended = "Install monitoring tools as needed"
    print(f"Current: {current}")
    print(f"Recommended: {recommended}")


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    distro = detect_distro()
    print(f"Detected distribution: {distro.upper()}")

    check_initial_setup(distro)
    check_file_system_configuration()
    check_network_configuration(distro)
    check_user_authentication(distro)
    check_logging_auditing(distro)
    check_intrusion_detection(distro)
    check_security_audits(distro)

    print("\nAudit complete. Review the current and recommended settings above.")

 """
        -------------______________<Under Construction>______________-------------
 """