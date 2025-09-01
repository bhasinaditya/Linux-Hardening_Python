# Step-by-Step Guide to Linux System Hardening for CIS Compliance

Securing a Linux system to meet CIS (Center for Internet Security) standards involves configuring the operating system to minimize vulnerabilities and enhance protection against cyber threats. The CIS benchmarks provide detailed recommendations for securing Linux environments. Below is a comprehensive guide to harden a Linux system, tailored for CIS compliance.

---

### Step 1: System Setup and Preparation

#### 1.1 Apply Security Updates

Keep your system current by installing the latest security patches and updates to address known vulnerabilities.

For CentOS, RHEL, or Amazon Linux:
```bash
sudo dnf update -y
```

For Ubuntu or Debian:
```bash
sudo apt update && sudo apt full-upgrade -y
```

#### 1.2 Eliminate Unneeded Software

Reduce the attack surface by removing unnecessary or unused packages.

For CentOS/RHEL:
```bash
sudo dnf remove package-name -y
```

For Ubuntu/Debian:
```bash
sudo apt remove --purge package-name -y
```

#### 1.3 Configure Automatic Updates

Enable automatic updates to ensure timely patching of vulnerabilities.

For Ubuntu/Debian:
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

For CentOS/RHEL:
```bash
sudo dnf install dnf-automatic -y
sudo systemctl enable --now dnf-automatic.timer
```

---

### Step 2: File System Security

#### 2.1 Partition Sensitive Directories

Use separate partitions for critical directories to limit the impact of a breach. Recommended partitions include:

- `/var`
- `/tmp`
- `/home`
- `/var/log`

Modify `/etc/fstab` to apply secure mount options like `nosuid`, `nodev`, and `noexec`. Example for `/tmp`:

```bash
UUID=<partition-uuid> /tmp ext4 defaults,nosuid,nodev,noexec 0 0
```

#### 2.2 Restrict Unused File Systems

Prevent the use of unnecessary file systems by disabling their kernel modules. Add the following to `/etc/modprobe.d/cis-hardening.conf`:

```bash
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

#### 2.3 Block USB Storage Devices

Disable USB storage to prevent unauthorized data transfers. Add to `/etc/modprobe.d/usb-storage.conf`:

```bash
install usb-storage /bin/true
```

---

### Step 3: Network Security Configuration

#### 3.1 Disable Unnecessary Services

Turn off unused network services to minimize exposure. For example, disable `telnet`:

```bash
sudo systemctl disable telnet.socket
sudo systemctl stop telnet.socket
```

#### 3.2 Set Hostname and DNS

Configure the hostname in `/etc/hostname` and ensure `/etc/hosts` maps the hostname to the correct IP address.

#### 3.3 Implement Firewall Rules

Set up a firewall to control incoming and outgoing traffic.

For CentOS/RHEL (using `firewalld`):
```bash
sudo dnf install firewalld -y
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

For Ubuntu (using `ufw`):
```bash
sudo apt install ufw -y
sudo ufw allow ssh
sudo ufw enable
```

#### 3.4 Disable IPv6 if Unused

If IPv6 is not required, disable it by adding to `/etc/sysctl.conf`:

```bash
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

Apply changes:
```bash
sudo sysctl -p
```

#### 3.5 Secure Network Parameters

Enhance network security by configuring `/etc/sysctl.conf`:

```bash
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
```

Apply settings:
```bash
sudo sysctl -p
```

---

### Step 4: User Account and Authentication

#### 4.1 Enforce Strong Passwords

Set robust password requirements in `/etc/security/pwquality.conf`:

```bash
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
```

#### 4.2 Implement Account Lockout

Configure lockout policies to prevent brute-force attacks. Edit `/etc/pam.d/common-auth` (Ubuntu) or `/etc/pam.d/system-auth` (CentOS/RHEL):

```bash
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
```

#### 4.3 Restrict Root Access

Prevent direct root login via SSH by editing `/etc/ssh/sshd_config`:

```bash
PermitRootLogin no
```

Reload SSH:
```bash
sudo systemctl reload sshd
```

#### 4.4 Enable SSH Key Authentication

Disable password-based SSH logins in `/etc/ssh/sshd_config`:

```bash
PasswordAuthentication no
```

Reload SSH:
```bash
sudo systemctl reload sshd
```

---

### Step 5: System Logging and Auditing

#### 5.1 Install and Enable Auditd

Set up `auditd` to monitor system activity:

For CentOS/RHEL:
```bash
sudo dnf install audit -y
```

For Ubuntu:
```bash
sudo apt install auditd -y
```

Enable and start:
```bash
sudo systemctl enable auditd
sudo systemctl start auditd
```

#### 5.2 Audit Critical Files

Add rules to `/etc/audit/rules.d/audit.rules` to monitor key files:

```bash
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /var/log/lastlog -p wa -k logins
```

Restart `auditd`:
```bash
sudo systemctl restart auditd
```

#### 5.3 Enable System Logging

Ensure `rsyslog` is active for logging system events:

```bash
sudo dnf install rsyslog -y  # CentOS/RHEL
sudo apt install rsyslog -y  # Ubuntu
sudo systemctl enable --now rsyslog
```

#### 5.4 Configure Log Rotation

Verify `/etc/logrotate.conf` is set to rotate logs regularly to manage disk space and retain logs appropriately.

---

### Step 6: File Integrity Monitoring

#### 6.1 Deploy AIDE for Integrity Checks

Install AIDE to monitor file changes:

For CentOS/RHEL:
```bash
sudo dnf install aide -y
```

For Ubuntu:
```bash
sudo apt install aide -y
```

Initialize the AIDE database:
```bash
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

Schedule daily checks via cron (`sudo crontab -e`):
```bash
0 5 * * * /usr/sbin/aide --check
```

---

### Step 7: Security Auditing and Monitoring

#### 7.1 Perform Audits with Lynis

Use Lynis to identify security gaps:

```bash
sudo apt install lynis -y  # Ubuntu/Debian
sudo dnf install lynis -y  # CentOS/RHEL
sudo lynis audit system
```

#### 7.2 Deploy Monitoring Solutions

Use tools like Prometheus and Grafana to monitor system performance and detect anomalies.

---

### Step 8: Continuous Security Maintenance

- Regularly update and patch the system.
- Review user accounts and permissions periodically.
- Conduct security scans using tools like Lynis or OpenSCAP.
- Implement intrusion detection tools like Fail2Ban to monitor services such as SSH.

This guide provides a structured approach to hardening a Linux system in alignment with CIS benchmarks, significantly enhancing its security posture.