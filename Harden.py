import os
import sys
import subprocess
import platform
import re

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


def step1_initial_setup(distro):
    """Step 1: Initial Setup"""
    print("\nStep 1: Initial Setup")

    # 1.1 Install Updates and Patches
    print("1.1 Installing updates and patches...")
    if distro == 'debian':
        run_command(['apt', 'update', '-y'])
        run_command(['apt', 'upgrade', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'update', '-y'])

    # 1.2 Remove Unnecessary Packages - Example: remove telnet if installed
    print("1.2 Removing unnecessary packages (e.g., telnet)...")
    if distro == 'debian':
        run_command(['apt', 'remove', '--purge', 'telnet', '-y'], shell=True)
    elif distro == 'rhel':
        run_command(['yum', 'remove', 'telnet', '-y'], shell=True)
    # Add more packages as needed

    # 1.3 Enable Automatic Updates
    print("1.3 Enabling automatic updates...")
    if distro == 'debian':
        run_command(['apt', 'install', 'unattended-upgrades', '-y'])
        run_command(['dpkg-reconfigure', '-plow', 'unattended-upgrades'])
    elif distro == 'rhel':
        run_command(['yum', 'install', 'yum-cron', '-y'])
        run_command(['systemctl', 'enable', 'yum-cron'])
        run_command(['systemctl', 'start', 'yum-cron'])


def step2_file_system_configuration():
    """Step 2: File System Configuration"""
    print("\nStep 2: File System Configuration")

    # 2.1 Create Separate Partitions - Cannot automate post-install, print warning
    print("2.1 Separate partitions should be set during installation. Check /etc/fstab manually.")
    print("Example: Add nosuid, nodev, noexec to /tmp, /var, etc.")

    # 2.2 Disable Unused File Systems
    print("2.2 Disabling unused file systems...")
    cis_conf = '/etc/modprobe.d/CIS.conf'
    with open(cis_conf, 'a') as f:
        f.write("\ninstall cramfs /bin/true\n")
        f.write("install freevxfs /bin/true\n")
        f.write("install jffs2 /bin/true\n")
        f.write("install hfs /bin/true\n")
        f.write("install hfsplus /bin/true\n")
        f.write("install squashfs /bin/true\n")
        f.write("install udf /bin/true\n")

    # 2.3 Disable Mounting of USB Storage
    print("2.3 Disabling USB storage...")
    usb_conf = '/etc/modprobe.d/usb-storage.conf'
    with open(usb_conf, 'w') as f:
        f.write("install usb-storage /bin/true\n")


def step3_network_configuration(distro):
    """Step 3: Network Configuration"""
    print("\nStep 3: Network Configuration")

    # 3.1 Disable Unnecessary Network Services
    print("3.1 Disabling unnecessary services (e.g., telnet)...")
    services = ['telnet.socket', 'rlogin', 'rsh']  # Add more if needed
    for service in services:
        run_command(['systemctl', 'disable', service], shell=True)
        run_command(['systemctl', 'stop', service], shell=True)

    # 3.2 Configure Hostname and DNS Settings
    print("3.2 Configure hostname (prompting user)...")
    hostname = input("Enter desired hostname: ")
    with open('/etc/hostname', 'w') as f:
        f.write(hostname + '\n')
    # Update /etc/hosts - assume 127.0.1.1
    with open('/etc/hosts', 'a') as f:
        f.write(f"127.0.1.1 {hostname}\n")

    # 3.3 Configure the Firewall
    print("3.3 Configuring firewall...")
    if distro == 'debian':
        run_command(['apt', 'install', 'ufw', '-y'])
        run_command(['ufw', 'allow', 'ssh'])
        run_command(['ufw', 'enable', '-y'])
    elif distro == 'rhel':
        run_command(['yum', 'install', 'firewalld', '-y'])
        run_command(['systemctl', 'start', 'firewalld'])
        run_command(['firewall-cmd', '--permanent', '--add-service=ssh'])
        run_command(['firewall-cmd', '--reload'])

        # 3.4 Disable IPv6 if Not Needed
        print("3.4 Disabling IPv6...")
        with open('/etc/sysctl.conf', 'a') as f:
            f.write("\nnet.ipv6.conf.all.disable_ipv6 = 1\n")
            f.write("net.ipv6.conf.default.disable_ipv6 = 1\n")
        run_command(['sysctl', '-p'])

        # 3.5 Harden Network Parameters
        print("3.5 Hardening network parameters...")
        with open('/etc/sysctl.conf', 'a') as f:
            f.write("\nnet.ipv4.ip_forward = 0\n")
            f.write("net.ipv4.conf.all.send_redirects = 0\n")
            f.write("net.ipv4.conf.default.send_redirects = 0\n")
            f.write("net.ipv4.conf.all.accept_source_route = 0\n")
            f.write("net.ipv4.conf.default.accept_source_route = 0\n")
            f.write("net.ipv4.conf.all.accept_redirects = 0\n")
            f.write("net.ipv4.conf.default.accept_redirects = 0\n")
            f.write("net.ipv4.conf.all.log_martians = 1\n")
            f.write("net.ipv4.conf.default.log_martians = 1\n")
        run_command(['sysctl', '-p'])

    def step4_user_authentication(distro):
        """Step 4: User and Authentication Configurations"""
        print("\nStep 4: User and Authentication Configurations")

        # 4.1 Set Password Policies
        print("4.1 Setting password policies...")
        pwquality_conf = '/etc/security/pwquality.conf'
        with open(pwquality_conf, 'a') as f:
            f.write("\nminlen = 14\n")
            f.write("dcredit = -1\n")
            f.write("ucredit = -1\n")
            f.write("lcredit = -1\n")
            f.write("ocredit = -1\n")

        # 4.2 Configure Account Lockout Policy
        print("4.2 Configuring account lockout policy...")
        if distro == 'debian':
            auth_file = '/etc/pam.d/common-auth'
        elif distro == 'rhel':
            auth_file = '/etc/pam.d/system-auth'
        with open(auth_file, 'a') as f:
            f.write("\nauth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900\n")

        # 4.3 Restrict Root Login
        print("4.3 Restricting root login via SSH...")
        sshd_config = '/etc/ssh/sshd_config'
        with open(sshd_config, 'a') as f:
            f.write("\nPermitRootLogin no\n")
        run_command(['systemctl', 'reload', 'sshd'])

        # 4.4 Use SSH Key-based Authentication
        print("4.4 Disabling password-based SSH authentication...")
        with open(sshd_config, 'a') as f:
            f.write("\nPasswordAuthentication no\n")
        run_command(['systemctl', 'reload', 'sshd'])

    def step5_logging_auditing(distro):
        """Step 5: Logging and Auditing"""
        print("\nStep 5: Logging and Auditing")

        # 5.1 Enable Auditd
        print("5.1 Enabling auditd...")
        if distro == 'debian':
            run_command(['apt', 'install', 'auditd', '-y'])
        elif distro == 'rhel':
            run_command(['yum', 'install', 'audit', '-y'])
        run_command(['systemctl', 'enable', 'auditd'])
        run_command(['systemctl', 'start', 'auditd'])

        # 5.2 Configure Auditing for Key Events
        print("5.2 Configuring auditing rules...")
        audit_rules = '/etc/audit/rules.d/audit.rules'
        with open(audit_rules, 'a') as f:
            f.write("\n-w /etc/passwd -p wa -k passwd_changes\n")
            f.write("-w /etc/shadow -p wa -k shadow_changes\n")
            f.write("-w /etc/group -p wa -k group_changes\n")
            f.write("-w /var/log/lastlog -p wa -k logins\n")
        run_command(['systemctl', 'restart', 'auditd'])

        # 5.3 Enable Logging for Important System Events
        print("5.3 Enabling rsyslog...")
        run_command(['yum' if distro == 'rhel' else 'apt', 'install', 'rsyslog', '-y'])
        run_command(['systemctl', 'enable', 'rsyslog'])
        run_command(['systemctl', 'start', 'rsyslog'])

        # 5.4 Configure Log Rotation - Assume default is fine, print message
        print("5.4 Log rotation is configured by default in /etc/logrotate.conf. Review manually.")

    def step6_intrusion_detection(distro):
        """Step 6: Intrusion Detection and File Integrity"""
        print("\nStep 6: Intrusion Detection and File Integrity")

        # 6.1 Install and Configure AIDE
        print("6.1 Installing and configuring AIDE...")
        if distro == 'debian':
            run_command(['apt', 'install', 'aide', '-y'])
        elif distro == 'rhel':
            run_command(['yum', 'install', 'aide', '-y'])
        run_command(['aide', '--init'])
        run_command(['mv', '/var/lib/aide/aide.db.new.gz', '/var/lib/aide/aide.db.gz'])

        # Set up cron job
        cron_job = "0 5 * * * /usr/sbin/aide --check\n"
        with open('/etc/crontab', 'a') as f:
            f.write(cron_job)
        """
        -------------______________<Under Construction>______________-------------
        """