import os
import subprocess
import socket

from cms_detector import detect_cms
from wpscan_scanner import scan_wordpress
from joomscan_scanner import scan_joomla
from droopescan_scanner import scan_drupal
from bitrix_scanner import run_bitrix_scan
from modx_scanner import scan_modx
from auto_exploit import run_auto_exploit
from logger import logger
from cve_finder import search_cves

from colorama import Fore, Style, init
init(autoreset=True)


def print_banner():
    banner = f"""{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}
 ██████╗  ██████╗ ██╗    ██╗   ██╗ █████╗        
██╔════╝ ██╔════╝ ██║    ██║   ██║██╔══██╗       
██║  ███╗██║  ███╗██║    ██║   ██║███████║       
██║   ██║██║   ██║██║    ╚██╗ ██╔╝██╔══██║       
╚██████╔╝╚██████╔╝███████╗╚████╔╝ ██║  ██║       
 ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝╚═╝  ╚═╝        

███████╗ ██████╗ █████╗ ███╗   ██╗       ██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╗╚════██╗
███████╗██║     ███████║██╔██╗ ██║    ╚═╝ █████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║    ██╗ ╚═══██╗
███████║╚██████╗██║  ██║██║ ╚████║    ╚═╝██████╔╝
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═════╝  
{Style.RESET_ALL}"""
    print(banner)


def run_install_if_needed():
    if not os.path.exists("installed.flag"):
        print(Fore.LIGHTMAGENTA_EX + "[INFO] First-time setup detected. Running installer...")
        subprocess.run(["python3", "install.py"])
        with open("installed.flag", "w") as f:
            f.write("installed\n")
        print(Fore.LIGHTMAGENTA_EX + "[INFO] Installation complete. Starting main program...\n")
    else:
        print(Fore.LIGHTMAGENTA_EX + "[INFO] Installation already done. Skipping install step.")


def resolve_ip_from_url(url):
    try:
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not resolve IP address from URL: {e}")
        return None


def main():
    print_banner()
    run_install_if_needed()

    print(Fore.LIGHTWHITE_EX + "\n=== Welcome to the CMS Exploitation Framework ===\n")

    target_url = input(Fore.LIGHTCYAN_EX + "[INPUT] Enter full target URL (e.g., http://example.com/): ").strip()
    target_ip = resolve_ip_from_url(target_url)
    if not target_ip:
        print(Fore.RED + "[ERROR] Could not resolve IP address. Exiting.")
        return
    print(Fore.LIGHTMAGENTA_EX + f"[INFO] Resolved target IP: {target_ip}")

    cms_info = detect_cms(target_url)
    if not cms_info:
        print(Fore.RED + "[ERROR] CMS detection failed. Exiting.")
        return

    cms = cms_info["cms"]
    version = cms_info["version"]
    print(Fore.LIGHTMAGENTA_EX + f"[INFO] Detected CMS: {cms} (Version: {version})")

    cms_lower = cms.lower()
    scan_results = None

    if "wordpress" in cms_lower:
        scan_results = scan_wordpress(target_url)
    elif "joomla" in cms_lower:
        scan_results = scan_joomla(target_url)
    elif "drupal" in cms_lower or "silverstripe" in cms_lower:
        scan_results = scan_drupal(target_url)
    elif "bitrix" in cms_lower:
        scan_results = run_bitrix_scan(target_url)
        raw = scan_results.get("raw_output")
        print(f"\n{Fore.LIGHTWHITE_EX}[RAW check_bitrix OUTPUT]\n")
        print(raw if raw else "[No output captured]\n")

        print(f"{Fore.LIGHTYELLOW_EX}[INFO] Version enumeration for Bitrix is not possible via public tools.")
        print("[INFO] The following results relate to the Bitrix platform in general.")
        print("[INFO] You'll need to manually test which ones work on your target.\n")

        found_cves = search_cves("bitrix", "unknown")
        if len(found_cves) > 20:
            print(Fore.LIGHTYELLOW_EX + "\n[WARNING] Too many CVEs found for this CMS.")
            print("[INFO] Searching exploits for all of them may take significant time.")
            print("[INFO] Please enter one or more CVE IDs you want to explore (comma-separated):\n")
            for idx, cve in enumerate(found_cves, 1):
                desc = cve['description']
                print(f"{idx:2}. {Fore.LIGHTCYAN_EX}{cve['id']} {Fore.WHITE}- {desc[:80]}{'...' if len(desc) > 80 else ''}")
            user_input = input(Fore.LIGHTCYAN_EX + "\n[INPUT] Enter CVE IDs (e.g. CVE-2020-1234,CVE-2019-5678): ").strip()
            selected_ids = [x.strip().upper() for x in user_input.split(",") if x.strip().startswith("CVE-")]
            filtered = [cve for cve in found_cves if cve["id"] in selected_ids]
            if not filtered:
                print(Fore.RED + "[ERROR] No matching CVEs selected. Exiting exploit phase.")
                return
            run_auto_exploit("bitrix", "unknown", filtered, target_ip, target_url, [])
        else:
            run_auto_exploit("bitrix", "unknown", found_cves, target_ip, target_url, [])
        return
    elif "modx" in cms_lower:
        scan_results = scan_modx(target_url)
    else:
        print(Fore.YELLOW + "[WARNING] CMS is not supported by this tool. Exiting.")
        return

    if not scan_results:
        print(Fore.YELLOW + "[WARNING] No scan results returned. Exiting.")
        return

    if version.lower() == "unknown":
        scanned_version = scan_results.get("version")
        if scanned_version:
            version = scanned_version
            print(Fore.LIGHTYELLOW_EX + f"[INFO] CMS version updated from scanner: {version}")

    if "modx" in cms_lower and version == "unknown":
        print(f"{Fore.LIGHTYELLOW_EX}[INFO] Version enumeration for MODX was not successful.")
        print("[INFO] The following results relate to the MODX platform in general.")
        print("[INFO] You'll need to manually test which ones work on your specific installation.\n")

        found_cves = search_cves("modx", "unknown")
        if len(found_cves) > 20:
            print(Fore.LIGHTYELLOW_EX + "\n[WARNING] Too many CVEs found for this CMS.")
            print("[INFO] Searching exploits for all of them may take significant time.")
            print("[INFO] Please enter one or more CVE IDs you want to explore (comma-separated):\n")
            for idx, cve in enumerate(found_cves, 1):
                desc = cve['description']
                print(f"{idx:2}. {Fore.LIGHTCYAN_EX}{cve['id']} {Fore.WHITE}- {desc[:80]}{'...' if len(desc) > 80 else ''}")
            user_input = input(Fore.LIGHTCYAN_EX + "\n[INPUT] Enter CVE IDs (e.g. CVE-2020-1234,CVE-2019-5678): ").strip()
            selected_ids = [x.strip().upper() for x in user_input.split(",") if x.strip().startswith("CVE-")]
            filtered = [cve for cve in found_cves if cve["id"] in selected_ids]
            if not filtered:
                print(Fore.RED + "[ERROR] No matching CVEs selected. Exiting exploit phase.")
                return
            run_auto_exploit("modx", "unknown", filtered, target_ip, target_url, [])
        else:
            run_auto_exploit("modx", "unknown", found_cves, target_ip, target_url, [])
        return

    plugins = scan_results.get("plugins", []) + scan_results.get("components", [])
    themes = scan_results.get("themes", [])
    plugins_themes = plugins + themes

    print(Fore.LIGHTMAGENTA_EX + "[INFO] Searching for CVEs via NVD API...")
    found_cves = search_cves(cms, version, plugins, themes)

    if found_cves:
        print(Fore.LIGHTWHITE_EX + f"\n[INFO] Total relevant CVEs found: {len(found_cves)}")
    else:
        print(Fore.YELLOW + "[WARNING] No relevant CVEs found — switching to heuristic exploit search.\n")

    run_auto_exploit(cms, version, found_cves, target_ip, target_url, plugins_themes)


if __name__ == "__main__":
    main()
