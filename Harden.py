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
