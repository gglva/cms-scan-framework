import re
import requests
from time import sleep
from colorama import Fore

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {
    "User-Agent": "CMS-Vuln-Scanner/1.0"
}

def search_nvd(query):
    """
    Send a search query to the NVD API and return a list of CVEs.
    """
    params = {
        "keywordSearch": query,
        "resultsPerPage": 100,
    }

    try:
        print(f"[INFO] Searching NVD for: {query}")
        resp = requests.get(API_URL, headers=HEADERS, params=params, timeout=15)

        if resp.status_code != 200:
            print(f"[WARNING] NVD query failed: {resp.status_code}")
            return []

        data = resp.json()
        cve_items = data.get("vulnerabilities", [])
        results = []

        for item in cve_items:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description provided.")
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            results.append({
                "id": cve_id,
                "description": description,
                "url": url
            })

        return results

    except Exception as e:
        print(f"[ERROR] NVD API error: {e}")
        return []

def version_in_description(description: str, cms: str, version: str) -> bool:
    """
    Check if the CVE description matches the CMS version, supporting version ranges.
    """
    cms_lower = cms.lower()
    version = version.strip()
    description = description.lower()

    if f"for {cms_lower}" in description:
        return False

    patterns = [
        fr"{cms_lower}\s+{re.escape(version)}\b",
        fr"{cms_lower}\s+version\s+{re.escape(version)}",
        fr"{cms_lower}.*before\s+{re.escape(version)}",
        fr"{cms_lower}.*prior\s+to\s+{re.escape(version)}",
        fr"{cms_lower}.*<=\s*{re.escape(version)}",
        fr"{cms_lower}.*through\s+{re.escape(version)}",
        fr"{cms_lower}\s+{re.escape('.'.join(version.split('.')[:-1]))}\.\*",
        fr"{cms_lower}\s+{re.escape('.'.join(version.split('.')[:-1]))}\.x"
    ]

    for pattern in patterns:
        if re.search(pattern, description, re.IGNORECASE):
            return True

    return False

def search_cves(cms, version, plugins=None, themes=None):
    """
    Search for CVEs based on CMS version and optional plugin/theme keywords.
    Output is grouped by query to show precision level.
    """
    if plugins is None:
        plugins = []
    if themes is None:
        themes = []

    seen_ids = set()
    all_results = []

    if version.lower() == "unknown":
        queries = [cms]
    else:
        parts = version.strip().split(".")
        version_variants = [".".join(parts[:i]) for i in range(len(parts), 0, -1)]
        queries = []
        for v in version_variants:
            queries.append(f"{cms} {v}")
            for item in plugins + themes:
                queries.append(f"{cms} {v} {item}")

    for query in queries:
        results = search_nvd(query)
        relevant = []

        for cve in results:
            if cve["id"] in seen_ids:
                continue
            if version.lower() == "unknown" or version_in_description(cve["description"], cms, version):
                seen_ids.add(cve["id"])
                relevant.append(cve)

        if relevant:
            print(f"\n{'-'*60}")
            print(f"[NVD Matches for]: {query}")
            print(f"{'-'*60}\n")
            for idx, cve in enumerate(relevant, 1):
                print(f"{Fore.LIGHTCYAN_EX}{idx:2}. [{cve['id']}] {Fore.WHITE}{cve['description']}")
            all_results.extend(relevant)

        sleep(15)

    return all_results
