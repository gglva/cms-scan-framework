import requests
import re
from bs4 import BeautifulSoup
from logger import logger
from colorama import Fore
from bs4 import Comment

def scan_modx(url):
    """
    Scans a MODX site to extract CMS version using known passive techniques.
    Returns a dictionary with version, components (if any), and raw findings.
    """
    print(Fore.LIGHTMAGENTA_EX + f"[INFO] Scanning MODX site: {url}")

    findings = []
    version = "unknown"
    components = []

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=10)
        content = resp.text
        soup = BeautifulSoup(content, "html.parser")

        # --- 1. HTML comment analysis ---
        findings.append("[*] Trying to extract version from HTML comments...")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        comment_found = False
        for c in comments:
            if "MODX" in c and re.search(r'\d+\.\d+\.\d+', c):
                version = re.search(r'\d+\.\d+\.\d+', c).group()
                findings.append(f"[+] Found version in HTML comment: {c.strip()}")
                comment_found = True
                break
        if not comment_found:
            findings.append("[-] No version found in HTML comments.")

        # --- 2. Meta tag analysis ---
        findings.append("[*] Trying to extract version from <meta> tags...")
        meta_found = False
        for meta in soup.find_all("meta"):
            content = meta.get("content", "")
            if "MODX" in content and re.search(r'\d+\.\d+\.\d+', content):
                version = re.search(r'\d+\.\d+\.\d+', content).group()
                findings.append(f"[+] Found version in meta tag: {content}")
                meta_found = True
                break
        if not meta_found:
            findings.append("[-] No version found in meta tags.")

        # --- 3. Check /manager/ page ---
        manager_url = url.rstrip("/") + "/manager/"
        findings.append(f"[*] Trying to access /manager/: {manager_url}")
        try:
            r = requests.get(manager_url, headers=headers, timeout=10)
            if "MODX" in r.text:
                findings.append("[+] Found MODX identifier in /manager/ page.")
                match = re.search(r'MODX CMS ([\d\.]+)', r.text)
                if match:
                    version = match.group(1)
                    findings.append(f"[+] Found version in /manager/: {version}")
                else:
                    findings.append("[-] MODX found, but version string not detected in /manager/.")
            else:
                findings.append("[-] /manager/ exists but MODX identifier not found.")
        except Exception as e:
            findings.append(f"[!] Error accessing /manager/: {e}")

    except Exception as e:
        findings.append(f"[!] Error during MODX scan: {e}")
        logger.error(f"MODX scan error: {e}")

    print(Fore.LIGHTWHITE_EX + "\n--- Raw MODX Findings ---\n")
    for f in findings:
        print(Fore.LIGHTYELLOW_EX + f)

    logger.info("MODX scan completed.")
    return {
        "version": version,
        "components": components,
        "raw": findings
    }
