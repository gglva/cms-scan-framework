import subprocess
import re
import os
from logger import logger
from colorama import Fore

CHECK_BITRIX_PATH = "check_bitrix/test_bitrix.py"
SUBDOMAIN_INTERACTION = "http://subdomain.oastify.com"

def run_bitrix_scan(url):
    """
    Runs check_bitrix scan against the target URL.
    Returns parsed results including version (if found), components, and potential vulnerabilities.
    """
    if not os.path.exists(CHECK_BITRIX_PATH):
        logger.error("check_bitrix is not installed or path is incorrect.")
        print(Fore.RED + "[ERROR] check_bitrix not found. Please clone it into the current directory.")
        return None

    print(Fore.LIGHTMAGENTA_EX + f"[INFO] Running check_bitrix scan on {url}...")

    try:
        result = subprocess.run(
            ["python3", CHECK_BITRIX_PATH, "-t", url, "scan", "-s", SUBDOMAIN_INTERACTION],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"check_bitrix execution failed: {e}")
        print(Fore.RED + "[ERROR] check_bitrix execution failed.")
        return None

    print(Fore.LIGHTBLACK_EX + "\n" + "=" * 60)
    print("[RAW check_bitrix OUTPUT]")
    print("=" * 60 + "\n")
    print(result.stdout.strip() + "\n")

    return parse_check_bitrix_output(result.stdout)


def parse_check_bitrix_output(output):
    """
    Parses output from check_bitrix and extracts key information:
    - version: always "unknown" for now
    - components: paths or features mentioned in URLs
    - vulnerabilities: green-labeled positives
    - raw: full tool output for debugging/logging
    """
    lines = output.splitlines()
    components = []
    vulnerabilities = []
    version = "unknown"

    for line in lines:
        # Extract paths from URLs containing bitrix directory
        if "bitrix/" in line and ("Status code" in line or "NOT available" in line):
            path_match = re.search(r"https?://[^ ]+/([^ ]+)", line)
            if path_match:
                path = path_match.group(1).strip()
                if path:
                    components.append(path)

        
        if "potential vulnerability" in line.lower():
            vulnerabilities.append(line.strip())

    result = {
        "version": version,
        "components": sorted(set(components)),
        "vulnerabilities": sorted(set(vulnerabilities)),
        "raw": output
    }

    logger.info("Parsed check_bitrix results.")
    return result
