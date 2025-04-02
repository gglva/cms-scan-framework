import subprocess
from logger import logger


def run_wpscan(url):
    """
    Runs WPScan on the given URL with real-time output.
    Returns the raw output as a string.
    """
    print(f"[INFO] Running WPScan on {url}...")

    command = f"wpscan --url {url} --enumerate vp,vt,u --no-update"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    output_lines = []
    try:
        for line in process.stdout:
            print(line, end="")  # друкуємо в реальному часі
            output_lines.append(line)

        process.wait()
        if process.returncode != 0:
            print(f"[ERROR] WPScan exited with code {process.returncode}")
            return None

        logger.info(f"WPScan scan completed for {url}")
        return "".join(output_lines)

    except Exception as e:
        print(f"[ERROR] WPScan execution error: {e}")
        logger.error(f"WPScan execution failed for {url}: {e}")
        return None

def analyze_wpscan_results(raw_output):
    """
    Parses the WPScan output to extract relevant information.
    Returns a dictionary with extracted data.
    """
    print("[INFO] Analyzing WPScan results...")
    results = {
        "version": None,
        "plugins": [],
        "themes": [],
        "vulnerabilities": []
    }

    current_theme = None

    for line in raw_output.splitlines():
        line = line.strip()

        # Version
        if "WordPress version" in line and "identified" in line:
            parts = line.split()
            for part in parts:
                if part.count(".") >= 1 and part[0].isdigit():
                    results["version"] = part.strip()
                    break

        # Theme name
        elif "WordPress theme in use:" in line:
            current_theme = line.split(":")[-1].strip()
            results["themes"].append(current_theme)

        elif "Version:" in line and current_theme:
            # Ignore version, keep theme name only
            current_theme = None

        # Plugin CVE (for future if token added)
        elif "CVE-" in line:
            results["vulnerabilities"].append(line)

    return results


def scan_wordpress(url):
    """
    Executes the full WordPress scanning process.
    """
    print(f"[INFO] Starting WPScan for {url}...")
    raw_output = run_wpscan(url)

    if raw_output:
        scan_results = analyze_wpscan_results(raw_output)

        # Display results
        print("\n[INFO] Scan completed. Summary:")
        for key, value in scan_results.items():
            print(f"{key.upper()}: {value}")

        return scan_results
    else:
        print("[ERROR] WPScan failed. No results available.")
        return None
