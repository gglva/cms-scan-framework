import subprocess
import sys
import os
import shutil

def run_command(command, use_shell=False):
    try:
        print(f"[>>] Running: {' '.join(command) if isinstance(command, list) else command}")
        subprocess.run(command, shell=use_shell, check=True)
    except subprocess.CalledProcessError:
        print(f"[!!] ERROR: Failed to execute: {command}")
        sys.exit(1)

def install_apt_packages():
    print("\n[==] Installing APT packages...\n")
    packages = [
        "joomscan", "curl", "metasploit-framework", "ruby", "ruby-dev",
        "libcurl4-openssl-dev", "make", "unzip", "golang-go", "git",
        "whatweb", "python3-pip", "python3-bs4"
    ]
    run_command(["sudo", "apt", "update"])
    run_command(["sudo", "apt", "install", "-y"] + packages)

def install_pip_packages():
    print("\n[==] Installing Python packages (pip)...\n")
    packages = ["requests", "colorama", "droopescan", "beautifulsoup4", "packaging"]
    run_command([sys.executable, "-m", "pip", "install", "--break-system-packages"] + packages)

def install_wpscan():
    print("\n[==] Installing WPScan...\n")
    if shutil.which("wpscan") is None:
        run_command(["sudo", "gem", "install", "wpscan"])
    else:
        print("[--] WPScan is already installed.")

def install_searchsploit():
    print("\n[==] Setting up SearchSploit (exploitdb)...\n")
    if not os.path.exists("/opt/exploitdb"):
        run_command(["sudo", "git", "clone", "https://gitlab.com/exploit-database/exploitdb.git", "/opt/exploitdb"])
    run_command(["sudo", "ln", "-sf", "/opt/exploitdb/searchsploit", "/usr/local/bin/searchsploit"])

def clone_cmseek():
    print("\n[==] Cloning CMSeeK...\n")
    if not os.path.exists("CMSeeK"):
        run_command(["git", "clone", "https://github.com/Tuhinshubhra/CMSeeK.git"])
    else:
        print("[--] CMSeeK directory already exists.")

def clone_check_bitrix():
    print("\n[==] Cloning check_bitrix...\n")
    if not os.path.exists("check_bitrix"):
        run_command(["git", "clone", "https://github.com/k1rurk/check_bitrix.git"])
    else:
        print("[--] check_bitrix directory already exists.")

def main():
    print("\n========================================")
    print("   CMS Exploitation Framework Installer")
    print("========================================\n")

    install_apt_packages()
    install_pip_packages()
    install_wpscan()
    install_searchsploit()
    clone_cmseek()
    clone_check_bitrix()

    print("\n[OK] All required tools and libraries have been successfully installed.\n")

if __name__ == "__main__":
    main()
