import os
import sys
import subprocess

def detect_distro():
    """Detect Linux distribution family (debian or rhel)."""
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release') as f:
            os_release = f.read()
        if 'debian' in os_release.lower() or 'ubuntu' in os_release.lower():
            return 'debian'
        elif 'centos' in os_release.lower() or 'rhel' in os_release.lower() or 'amazon' in os_release.lower() or 'fedora' in os_release.lower():
            return 'rhel'
    print("Unsupported distribution.")
    sys.exit(1)

def run_command(command, shell=False):
    """Run a shell command and handle errors."""
    try:
        result = subprocess.run(command, shell=shell, check=True, capture_output=True, text=True)
        print(f"Command '{' '.join(command)}' executed successfully.")
        if result.stdout:
            print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing '{' '.join(command)}': {e.stderr}")
        sys.exit(1)

def revert_step1_initial_setup(distro):
    """Revert Step 1: Initial Setup"""
    print("\nReverting Step 1: Initial Setup")

    # 1.1 Cannot undo system updates, print warning
    print("1.1 System updates cannot be safely undone. Skipping.")

    # 1.2 Reinstall removed packages (e.g., telnet)
    print("1.2 Reinstalling removed packages (e.g., telnet)...")
    if distro == 'debian':
        run_command(['apt', 'install', 'telnet', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'install', 'telnet', '-y'])

    # 1.3 Disable and remove automatic updates
    print("1.3 Disabling and removing automatic updates...")
    if distro == 'debian':
        run_command(['apt', 'remove', 'unattended-upgrades', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'yum-cron', '-y'])
        run_command(['systemctl', 'disable', 'yum-cron'], shell=True)
        run_command(['systemctl', 'stop', 'yum-cron'], shell=True)

def revert_step2_file_system_configuration():
    """Revert Step 2: File System Configuration"""
    print("\nReverting Step 2: File System Configuration")

    # 2.1 Cannot undo partition changes, print warning
    print("2.1 Partition changes cannot be undone automatically. Review /etc/fstab manually.")

    # 2.2 Re-enable unused file systems by removing CIS.conf
    print("2.2 Re-enabling file systems by removing CIS.conf...")
    cis_conf = '/etc/modprobe.d/CIS.conf'
    if os.path.exists(cis_conf):
        os.remove(cis_conf)
        print(f"Removed {cis_conf}")
    else:
        print(f"{cis_conf} not found, skipping.")

    # 2.3 Re-enable USB storage
    print("2.3 Re-enabling USB storage...")
    usb_conf = '/etc/modprobe.d/usb-storage.conf'
    if os.path.exists(usb_conf):
        os.remove(usb_conf)
        print(f"Removed {usb_conf}")
    else:
        print(f"{usb_conf} not found, skipping.")

def revert_step3_network_configuration(distro):
    """Revert Step 3: Network Configuration"""
    print("\nReverting Step 3: Network Configuration")

    # 3.1 Re-enable disabled network services
    print("3.1 Re-enabling network services (e.g., telnet)...")
    services = ['telnet.socket', 'rlogin', 'rsh']
    for service in services:
        run_command(['systemctl', 'enable', service], shell=True)
        run_command(['systemctl', 'start', service], shell=True)

    # 3.2 Cannot fully revert hostname without original, print warning
    print("3.2 Hostname and /etc/hosts changes cannot be automatically reverted. Restore manually.")

    # 3.3 Remove firewall configurations
    print("3.3 Removing firewall configurations...")
    if distro == 'debian':
        run_command(['ufw', 'disable'])
        run_command(['apt', 'remove', 'ufw', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['systemctl', 'stop', 'firewalld'])
        run_command(['systemctl', 'disable', 'firewalld'])
        run_command(['yum', 'remove', 'firewalld', '-y'])

    # 3.4 Re-enable IPv6
    print("3.4 Re-enabling IPv6...")
    sysctl_conf = '/etc/sysctl.conf'
    if os.path.exists(sysctl_conf):
        with open(sysctl_conf, 'r') as f:
            lines = f.readlines()
        with open(sysctl_conf, 'w') as f:
            for line in lines:
                if not any(x in line for x in ['net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6']):
                    f.write(line)
        run_command(['sysctl', '-p'])

    # 3.5 Remove network hardening parameters
    print("3.5 Removing network hardening parameters...")
    if os.path.exists(sysctl_conf):
        with open(sysctl_conf, 'r') as f:
            lines = f.readlines()
        with open(sysctl_conf, 'w') as f:
            for line in lines:
                if not any(x in line for x in [
                    'net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects',
                    'net.ipv4.conf.default.send_redirects', 'net.ipv4.conf.all.accept_source_route',
                    'net.ipv4.conf.default.accept_source_route', 'net.ipv4.conf.all.accept_redirects',
                    'net.ipv4.conf.default.accept_redirects', 'net.ipv4.conf.all.log_martians',
                    'net.ipv4.conf.default.log_martians']):
                    f.write(line)
        run_command(['sysctl', '-p'])

def revert_step4_user_authentication(distro):
    """Revert Step 4: User and Authentication Configurations"""
    print("\nReverting Step 4: User and Authentication Configurations")

    # 4.1 Remove password policy changes
    print("4.1 Removing password policy changes...")
    pwquality_conf = '/etc/security/pwquality.conf'
    if os.path.exists(pwquality_conf):
        with open(pwquality_conf, 'r') as f:
            lines = f.readlines()
        with open(pwquality_conf, 'w') as f:
            for line in lines:
                if not any(x in line for x in ['minlen', 'dcredit', 'ucredit', 'lcredit', 'ocredit']):
                    f.write(line)

    # 4.2 Remove account lockout policy
    print("4.2 Removing account lockout policy...")
    if distro == 'debian':
        auth_file = '/etc/pam.d/common-auth'
    elif distro == 'rhel':
        auth_file = '/etc/pam.d/system-auth'
    if os.path.exists(auth_file):
        with open(auth_file, 'r') as f:
            lines = f.readlines()
        with open(auth_file, 'w') as f:
            for line in lines:
                if 'pam_tally2.so' not in line:
                    f.write(line)

    # 4.3 Re-enable root login via SSH
    print("4.3 Re-enabling root login via SSH...")
    sshd_config = '/etc/ssh/sshd_config'
    if os.path.exists(sshd_config):
        with open(sshd_config, 'r') as f:
            lines = f.readlines()
        with open(sshd_config, 'w') as f:
            for line in lines:
                if 'PermitRootLogin' not in line:
                    f.write(line)
            f.write("PermitRootLogin yes\n")
        run_command(['systemctl', 'reload', 'sshd'])

    # 4.4 Re-enable password-based SSH authentication
    print("4.4 Re-enabling password-based SSH authentication...")
    if os.path.exists(sshd_config):
        with open(sshd_config, 'r') as f:
            lines = f.readlines()
        with open(sshd_config, 'w') as f:
            for line in lines:
                if 'PasswordAuthentication' not in line:
                    f.write(line)
            f.write("PasswordAuthentication yes\n")
        run_command(['systemctl', 'reload', 'sshd'])

def revert_step5_logging_auditing(distro):
    """Revert Step 5: Logging and Auditing"""
    print("\nReverting Step 5: Logging and Auditing")

    # 5.1 Disable and remove auditd
    print("5.1 Disabling and removing auditd...")
    run_command(['systemctl', 'stop', 'auditd'])
    run_command(['systemctl', 'disable', 'auditd'])
    if distro == 'debian':
        run_command(['apt', 'remove', 'auditd', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'audit', '-y'])

    # 5.2 Remove auditing rules
    print("5.2 Removing auditing rules...")
    audit_rules = '/etc/audit/rules.d/audit.rules'
    if os.path.exists(audit_rules):
        with open(audit_rules, 'r') as f:
            lines = f.readlines()
        with open(audit_rules, 'w') as f:
            for line in lines:
                if not any(x in line for x in ['passwd_changes', 'shadow_changes', 'group_changes', 'logins']):
                    f.write(line)
        run_command(['systemctl', 'restart', 'auditd'])

    # 5.3 Disable rsyslog
    print("5.3 Disabling rsyslog...")
    run_command(['systemctl', 'stop', 'rsyslog'])
    run_command(['systemctl', 'disable', 'rsyslog'])
    if distro == 'debian':
        run_command(['apt', 'remove', 'rsyslog', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'rsyslog', '-y'])

def revert_step6_intrusion_detection(distro):
    """Revert Step 6: Intrusion Detection and File Integrity"""
    print("\nReverting Step 6: Intrusion Detection and File Integrity")

    # 6.1 Remove AIDE and its cron job
    print("6.1 Removing AIDE and its cron job...")
    if distro == 'debian':
        run_command(['apt', 'remove', 'aide', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'aide', '-y'])
    if os.path.exists('/var/lib/aide/aide.db.gz'):
        os.remove('/var/lib/aide/aide.db.gz')
    crontab = '/etc/crontab'
    if os.path.exists(crontab):
        with open(crontab, 'r') as f:
            lines = f.readlines()
        with open(crontab, 'w') as f:
            for line in lines:
                if '/usr/sbin/aide --check' not in line:
                    f.write(line)

def revert_step7_security_audits(distro):
    """Revert Step 7: Security Audits and Ongoing Monitoring"""
    print("\nReverting Step 7: Security Audits and Ongoing Monitoring")

    # 7.1 Remove Lynis
    print("7.1 Removing Lynis...")
    if distro == 'debian':
        run_command(['apt', 'remove', 'lynis', '--purge', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'lynis', '-y'])

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    distro = detect_distro()
    print(f"Detected distribution: {distro.upper()}")

    revert_step1_initial_setup(distro)
    revert_step2_file_system_configuration()
    revert_step3_network_configuration(distro)
    revert_step4_user_authentication(distro)
    revert_step5_logging_auditing(distro)
    revert_step6_intrusion_detection(distro)
    revert_step7_security_audits(distro)

    print("\nReversion complete. Review changes and reboot if necessary.")