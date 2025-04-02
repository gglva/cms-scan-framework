# CMS Exploitation Framework

**CMS Exploitation Framework** is an automated security auditing tool focused on detecting, analyzing, and exploiting known vulnerabilities in the most popular CMS platforms used across the Russian-speaking web: WordPress, Joomla, Drupal, 1C-Bitrix, and MODX.

The tool combines fingerprinting, vulnerability scanning, and CVE-based exploit discovery into a streamlined workflow, designed for penetration testers, red teamers, and security researchers.

---

##  Features 

- **Automatic CMS detection** via [CMSeeK] and fallback mechanisms (WhatWeb/manual input).
- **CMS-specific vulnerability scanners**:
  - `wpscan` for WordPress
  - `joomscan` for Joomla
  - `droopescan` for Drupal
  - `check_bitrix` for Bitrix
  - Passive MODX version detection via HTML/meta tags
- **CVE discovery** using the NVD API (filtered by version, plugins, and themes).
- **Exploit search engine**:
  - Integrated with ExploitDB (SearchSploit)
  - CVE module mapping via Metasploit
  - GitHub PoC scraper for CVE IDs
- **Auto-exploitation engine** with PoC execution (Python, PHP, Perl) and Metasploit integration.
- **Modular and extendable design** — easy to add new CMS scanners or exploit workflows.

---

##  Technologies 

- Python 3
- Bash, Ruby, Go (for external tools)
- ExploitDB, Metasploit, GitHub, NVD API

---

##  Legal Disclaimer 

This tool is intended for **educational and authorized penetration testing purposes only**. Unauthorized use against targets without proper consent is strictly prohibited and illegal.
