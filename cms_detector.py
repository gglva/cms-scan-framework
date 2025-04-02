import os
import json
import subprocess
import re
from logger import logger


def detect_cms(url):
    """
    Attempts to detect CMS using CMSeeK.
    Falls back to WhatWeb if CMSeeK fails.
    """
    print(f"[INFO] Running CMSeeK to detect CMS on {url}...")

    try:
        command = f"python3 CMSeeK/cmseek.py -u {url} --batch"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            print("[ERROR] CMSeeK execution failed.")
            logger.error(f"CMSeeK execution failed: {result.stderr}")
            return fallback_with_whatweb(url)

        
        ip = url.split("//")[-1].split("/")[0]
        cms_result_path = os.path.join("CMSeeK", "Result", ip, "cms.json")

        if not os.path.exists(cms_result_path):
            print("[ERROR] CMSeeK result file not found.")
            logger.error("CMSeeK output not found.")
            return fallback_with_whatweb(url)

        with open(cms_result_path, "r") as f:
            data = json.load(f)

        cms = data.get("cms_name", "unknown")
        version = data.get("cms_version", "unknown")

        print(f"[SUCCESS] CMS detected: {cms} (Version: {version})")
        logger.info(f"CMS detected: {cms} (Version: {version})")
        return {"cms": cms, "version": version}

    except Exception as e:
        print(f"[ERROR] An error occurred during CMS detection: {e}")
        logger.error(f"CMS detection error: {e}")
        return fallback_with_whatweb(url)


def fallback_with_whatweb(url):
    """
    Attempts CMS detection using WhatWeb as a fallback.
    Prompts manual input if WhatWeb also fails.
    """
    print(f"[INFO] Attempting CMS detection with WhatWeb for {url}...")
    try:
        result = subprocess.run(["whatweb", "--no-errors", "--color=never", url],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print("[ERROR] WhatWeb failed to execute.")
            logger.error(f"WhatWeb failed: {result.stderr}")
            return manual_cms_input()

        print(f"\n[RAW WhatWeb OUTPUT]\n{result.stdout}")

        cms = "unknown"
        version = "unknown"

        match = re.search(r"\b(WordPress|Joomla|Drupal|MODX|Bitrix)[\s:]*(\d+[\.\d+]*)?", result.stdout, re.IGNORECASE)
        if match:
            cms = match.group(1).strip()
            if match.group(2):
                version = match.group(2).strip()

        if cms != "unknown":
            print(f"[SUCCESS] CMS detected via WhatWeb: {cms} (Version: {version})")
            logger.info(f"WhatWeb CMS detected: {cms} (Version: {version})")
            return {"cms": cms, "version": version}
        else:
            print("[WARNING] WhatWeb could not determine CMS.")
            return manual_cms_input()

    except Exception as e:
        print(f"[ERROR] WhatWeb detection failed: {e}")
        logger.error(f"WhatWeb fallback error: {e}")
        return manual_cms_input()


def manual_cms_input():
    """
    Prompts user for manual CMS and version input.
    """
    print("\n[INFO] Please enter the CMS and version manually.")
    cms = input("Enter CMS name (e.g., WordPress, Joomla, Drupal): ").strip()
    version = input("Enter CMS version (or 'unknown' if unsure): ").strip()

    if not cms:
        print("[ERROR] CMS name cannot be empty. Exiting.")
        return None

    print(f"[SUCCESS] Manually entered CMS: {cms} (Version: {version})")
    logger.info(f"User manually entered CMS: {cms} (Version: {version})")
    return {"cms": cms, "version": version}


if __name__ == "__main__":
    url = input("Enter the website URL: ")
    result = detect_cms(url)

    if result:
        print(f"[INFO] CMS: {result['cms']} | Version: {result['version']}")
    else:
        print("[ERROR] CMS detection failed.")
