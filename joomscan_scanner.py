import subprocess
from logger import logger
from urllib.parse import urlparse

def run_joomscan(url):
    """
    Runs OWASP JoomScan on the given URL to detect Joomla vulnerabilities.
    Returns the raw output as a string.
    """
    print(f"[INFO] Running JoomScan on {url}...")

    command = f"joomscan --url {url}"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        logger.info(f"JoomScan scan completed for {url}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] JoomScan execution failed: {e}")
        logger.error(f"JoomScan execution failed for {url}: {e}")
        return None


def analyze_joomscan_results(output):
    """
    Parses the JoomScan output to extract relevant information.
    Returns a dictionary with extracted data.
    """
    print("[INFO] Analyzing JoomScan results...")
    results = {
        "version": None,
        "components": [],
        "vulnerabilities": []
    }

    for line in output.splitlines():
        if "Joomla" in line and any(x in line for x in ["Version", "Joomla 1.", "Joomla 2.", "Joomla 3.", "Joomla 4."]):
            if "Joomla" in line and any(char.isdigit() for char in line):
                results["version"] = line.strip().split()[-1]

        elif "directory has directory listing" in line:
            continue  # skip label
        elif line.strip().startswith("http://") or line.strip().startswith("https://"):
            parsed = urlparse(line.strip())
            results["components"].append(parsed.path)

        elif "CVE-" in line:
            results["vulnerabilities"].append(line.strip())

    return results


def scan_joomla(url):
    """
    Executes the full Joomla scanning process.
    """
    print(f"[INFO] Starting JoomScan for {url}...")
    output = run_joomscan(url)

    if output:
        print("\n" + output)  # Show raw output from JoomScan
        scan_results = analyze_joomscan_results(output)

        # Display parsed summary
        print("\n[INFO] Scan completed. Summary:")
        for key, value in scan_results.items():
            print(f"{key.upper()}: {value}")

        return scan_results
    else:
        print("[ERROR] JoomScan failed. No results available.")
        return None
