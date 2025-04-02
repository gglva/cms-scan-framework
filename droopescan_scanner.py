import subprocess
from datetime import datetime
from logger import logger
import re


def run_droopescan(url):
    """
    Runs Droopescan on the given URL to detect Drupal information.
    Returns the raw output as string.
    """
    print(f"[INFO] Running Droopescan on {url}...")

    command = f"droopescan scan drupal -u {url}"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        logger.info(f"Droopescan completed for {url}")

        print("\n[RAW DROOPESCAN OUTPUT]\n")
        print(result.stdout)

        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Droopescan execution failed: {e}")
        logger.error(f"Droopescan execution failed for {url}: {e}")
        return None


def analyze_droopescan_results(scan_output):
    """
    Parses the Droopescan results to extract modules and themes.
    Skips version and interesting URLs, which are not needed.
    """
    print("[INFO] Analyzing Droopescan results...")
    results = {
        "modules": [],
        "themes": []
    }

    # ======== MODULES ========
    if "[+] Plugins found:" in scan_output:
        modules_section = scan_output.split("[+] Plugins found:")[1].split("[+]")[0]
        modules = re.findall(r'^\s{4}([^\s]+)(?:\s|$)', modules_section, re.MULTILINE)
        results["modules"] = list(set(modules))

    # ======== THEMES ========
    if "[+] Themes found:" in scan_output:
        themes_section = scan_output.split("[+] Themes found:")[1].split("[+]")[0]
        themes = re.findall(r'^\s{4}([^\s]+)(?:\s|$)', themes_section, re.MULTILINE)
        results["themes"] = list(set(themes))

    return results


def save_results_to_file(results):
    """
    Saves extracted scan results to a timestamped file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"drupal_scan_summary_{timestamp}.txt"

    try:
        with open(filename, "w") as file:
            for key, value in results.items():
                file.write(f"{key.upper()}:\n")
                if isinstance(value, list):
                    file.write("\n".join(value) + "\n\n")
                else:
                    file.write(f"{value}\n\n")

        print(f"[SUCCESS] Processed scan results saved to {filename}")
        logger.info(f"Droopescan summary saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Error saving results to file: {e}")
        logger.error(f"Error saving results to file: {e}")


def scan_drupal(url):
    """
    Executes the full Drupal scanning process using Droopescan.
    """
    print(f"[INFO] Starting Droopescan for {url}...")
    scan_output = run_droopescan(url)

    if scan_output:
        scan_results = analyze_droopescan_results(scan_output)

        # Display results
        print("\n[INFO] Scan completed. Summary:")
        for key, value in scan_results.items():
            print(f"{key.upper()}: {value}")

        # Ask user if they want to save results
        save_choice = input("[PROMPT] Save results to a .txt file? (y/n): ").lower()
        if save_choice == "y":
            save_results_to_file(scan_results)

        return scan_results
    else:
        print("[ERROR] Droopescan failed. No results available.")
        return None
