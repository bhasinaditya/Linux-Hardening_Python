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


        """
        -------------______________<Under Construction>______________-------------
        """