# -*- coding: utf-8 -*-
# ██╗  ██╗ █████╗ ██╗██████╗  ██████╗ ███████╗
# ██║ ██╔╝██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
# █████╔╝ ███████║██║██████╔╝██║   ██║███████╗
# ██╔═██╗ ██╔══██║██║██╔══██╗██║   ██║╚════██║
# ██║  ██╗██║  ██║██║██████╔╝╚██████╔╝███████║
# ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
#
# KAIROS - The Zenith of Intelligent Site Reconnaissance
# Version: 3.6 "Zenith Prime" (KAI-Enhanced - Hyper-Heuristics & Quantum Analysis Core)
#
# Conceived & Crafted by: Karim Karam (Cyber-Alchemist)
#                     In Collaboration with: K.A.I. (Karm Artificial Intelligence)
#
# Connect & Explore:
#   GitHub:   https://github.com/kareemsoftware (Witness the Evolution)
#   LinkedIn: https://www.linkedin.com/in/karim-karam-ahmed/ (Engage with the Visionary)
#
# Purpose:
#   To empower ethical cybersecurity professionals and enthusiasts with a state-of-the-art,
#   hyper-intelligent framework for comprehensive website information gathering, advanced
#   vulnerability discovery, and proactive security posture assessment. KAIROS aims to be
#   a digital oracle, precise, insightful, and adaptive, in the hands of responsible explorers.
#
# Mission Statement:
#   "Unveiling Digital Universes, One Quantum Bit at a Time."
#
# Ethical Imperative:
#   This instrument is forged for KNOWLEDGE, DEFENSE, and ETHICAL EXPLORATION.
#   Its profound power demands unwavering responsibility. Utilization must ALWAYS be
#   with EXPLICIT, VERIFIABLE PERMISSION from the target system's rightful owners.
#   Misuse is a desecration of trust and the core ethos of this project.
#
# --- [ Zenith Prime v3.6 - Ascendant Features & Enhancements ] ---
#
#   [*] KAIROS CORE REBRANDING & PHILOSOPHY:
#       - Complete system rename to KAIROS, reflecting its advanced intelligence.
#       - Enhanced mission statement and ethical guidelines.
#
#   [*] CONFIGURATION NEXUS (config_kairos.json):
#       - Centralized JSON intelligence hub for unparalleled customization.
#       - Dynamically adapting parameters for a tailored reconnaissance experience.
#
#   [*] SUBDOMAIN HORIZON EXPANSION (ENHANCED):
#       - Integrated `crt.sh` oracle for deeper subdomain lineage discovery.
#       - Enhanced bruteforce engine with adaptive wordlist capabilities & basic wildcard detection.
#
#   [*] CHRONOS ENGINE (Wayback Machine Integration - IMPROVED):
#       - Traverses digital archives, unearthing historical snapshots and forgotten paths.
#       - Added heuristic for identifying potentially sensitive files in archives.
#
#   [*] API PATHFINDER PROTOCOL (ENHANCED):
#       - Heuristic-driven discovery of common API gateways and vital documentation endpoints.
#       - Basic parsing of discovered Swagger/OpenAPI specifications to list defined paths.
#
#   [*] JAVASCRIPT DEEP-DIVE ANALYSIS ("JSense" - IMPROVED):
#       - Intricate dissection of client-side scripts for embedded secrets, latent endpoints,
#         cloud resource IDs, and subtle vulnerabilities. Expanded regex patterns.
#
#   [*] INTELLI-REPORTING SUITE (HTML & Text - REFINED):
#       - Dynamic, collapsible HTML reports with improved severity highlighting and TOC.
#       - Enhanced data visualization and context-aware formatting.
#
#   [*] DNS INTELLIGENCE AUGMENTATION (ROBUST):
#       - Granular analysis of DNS records, focusing on mail server security (SPF, DKIM, DMARC)
#         and DNSSEC status. More robust PTR record handling.
#
#   [*] AD & APP-AD TRACKER VERIFICATION:
#       - Identification of `ads.txt` and `app-ads.txt`.
#
#   [*] SENSITIVE DATA EXPOSURE MATRIX (EXPANDED):
#       - Expanded and refined lexicons for uncovering exposed configuration files,
#         backup archives, logs, and version control artifacts. GitPython for `.git/config`.
#
#   [*] ERROR PAGE FORENSICS (IMPROVED):
#       - Sophisticated fingerprinting of server technologies and frameworks through
#         idiosyncratic error page signatures.
#
#   [*] CVE PREDICTOR LINKAGE (ENHANCED):
#       - Generates proactive search queries for CVEs based on identified software versions.
#       - Integrated more deeply with CMS version detection.
#
#   [*] ARCHITECTURAL REFINEMENT & HYPER-RESILIENCE:
#       - Modularized codebase for enhanced maintainability, scalability, and robustness.
#       - Advanced error handling, adaptive retry mechanisms, and improved async operations.
#
#   [*] ENHANCED SITEMAP DISCOVERY & PARSING:
#       - Recursive processing of sitemap index files.
#       - Improved handling of different sitemap formats (XML, TXT, GZ).
#
#   [*] EXPERIMENTAL FUZZING MODULE (IMPROVED):
#       - Basic path fuzzing with configurable wordlist and optional common extension appending.
#       - Clearer warnings about its active nature.
#
#   [*] RECURSIVE SITEMAP PROCESSING:
#       - Implemented logic to discover and process sitemaps listed within sitemap index files.
#
#   [*] CODE STRUCTURE AND CLI FIXES (v3.6 Prime):
#       - Corrected class structure and CLI invocation issues.
#       - Ensured report generation methods are correctly scoped within the class.
#       - Addressed log level input handling in CLI.
#
# -------------------------------------------------------------------------------------

import os
import asyncio
import json
import logging
import platform
import re
import socket
import ssl
from urllib.parse import urlparse, urljoin # unquote was unused
from datetime import datetime, timezone
import html # For escaping HTML content in reports
# import shutil # Unused: For copying default config
import gzip # For gzipped sitemaps

# External Libraries (ensure these are installed: pip install ...)
import aiohttp
from bs4 import BeautifulSoup, Comment as BsComment
import dns.resolver # type: ignore

try:
    import requests # For crt.sh, wayback machine, etc.
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    # This print statement is fine here as it's a one-time startup warning.
    print(
        "[WARN] 'requests' library not found. Some features like crt.sh subdomain search and Wayback Machine will be skipped. Install with: pip install requests")

try:
    import nmap # type: ignore
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[WARN] python-nmap library not found. Port scanning will be skipped. Install with: pip install python-nmap")

from tqdm.asyncio import tqdm as async_tqdm

try:
    import whois # type: ignore
    # Check for common attributes of the correct 'python-whois' library
    if not hasattr(whois, 'whois') or not hasattr(whois, 'parser'): # 'parser' might not be directly on whois module
        # A more reliable check might be to see if whois.whois('google.com') returns a structured object
        print(
            "[WARN] Potentially incorrect 'whois' library detected or it's corrupted. WHOIS lookups might fail or be limited. Ensure 'python-whois' is installed by running: pip uninstall whois -y; pip install python-whois")
        WHOIS_CORRECT_LIB = False # Assume incorrect if attributes are missing
    else:
        WHOIS_CORRECT_LIB = True
except ImportError:
    print(
        "[WARN] python-whois library not found. WHOIS lookups will be skipped. Install with: pip install python-whois")
    WHOIS_CORRECT_LIB = False

from Wappalyzer import Wappalyzer, WebPage # type: ignore

try:
    import git # type: ignore
    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False
    print(
        "[INFO] GitPython library not found. Advanced .git analysis will be skipped. Install with: pip install GitPython")

# --- Global Configuration & Constants ---
CONFIG_FILE_NAME = "config_kairos.json" # Updated name
DEFAULT_CONFIG = {
    "scanner_version": "3.6 Zenith Prime",
    "default_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0 KAIROS/3.6", # Updated UA
    "request_timeout_seconds": 20,
    "max_concurrent_requests": 15,
    "dns_timeout_seconds": 5,
    "common_subdomains_file": "common_subdomains.txt",
    "default_common_subdomains": [
        "www", "mail", "ftp", "admin", "test", "dev", "api", "shop", "blog", "staging", "beta",
        "app", "my", "support", "secure", "static", "cdn", "portal", "owa", "m", "jira",
        "confluence", "git", "svn", "files", "assets", "images", "docs", "webmail",
        "remote", "vpn", "internal", "corp", "devops", "uat", "accounts", "autodiscover",
        "backup", "cms", "db", "demo", "download", "fileserver", "forum", "gateway", "help",
        "intranet", "ldap", "logs", "metrics", "monitor", "news", "payment", "proxy", "sso",
        "stats", "store", "survey", "upload", "video", "wiki", "chat", "cloud", "dashboard",
        "auth", "identity", "sentry", "status", "careers", "community", "customer", "developer",
        "graphql", "ads", "app-ads", "assets-origin", "origin", "webservice", "ws"
    ],
    "sensitive_paths_categories": {
        "config_files": [
            ".env", ".env.local", ".env.development", ".env.staging", ".env.production", "config.php", "wp-config.php",
            "settings.php",
            "localsettings.php", "web.config", "database.yml", "configuration.php", "appsettings.json",
            "application.ini", "settings.ini", "config.json", "secrets.json", "credentials.json", "params.php",
            ".htpasswd", ".htaccess", "docker-compose.yml", "Procfile", "nginx.conf", "httpd.conf", "apache2.conf",
            "config/config.ini", "config/database.php", "app/config/parameters.yml", "app/config/local.php",
            "config/secrets.yml", "conf/server.xml", "server.xml", "context.xml", "security.xml", "credentials.xml",
            "connectionstrings.config"
        ],
        "backup_archives": [
            "backup.sql", "backup.zip", "dump.sql", "site.tar.gz", "backup.tar.gz", "database.sql.gz",
            "db.zip", "_backup.zip", "data.rar", "website_backup.7z", "backup.bak", "site.bak", "db.bak",
            "backup.sql.zip", "db_backup.sql", "backup.tgz", "data.sql", "full_backup.zip", "site_archive.zip",
            "backup.mdb", "database.mdb"
        ],
        "log_files": [
            "access.log", "error.log", "debug.log", "app.log", "server.log", "audit.log", "catalina.out",
            "system.log", "security.log", "php_errors.log", "laravel.log", "sql.log", "queries.log",
            "trace.axd", "production.log", "development.log", "nohup.out"
        ],
        "exposed_services_info": [
            "phpinfo.php", "info.php", "test.php", "status.php", "server-status", "server-info", "status",
            "/jolokia/list",
            "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/metrics",
            "/actuator/httptrace", "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",
            "/actuator/beans", "/actuator/configprops", "/actuator/mappings",
            "/api/swagger.json", "/swagger-ui.html", "swagger.json", "openapi.json", "api-docs",
            "license.php", "readme.html", "RELEASE_NOTES.txt", "CHANGELOG.md", "INSTALL.md", "UPGRADE.txt",
            "/api/v2/api-docs", "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs",
            "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "Gemfile",
            "Gemfile.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "build.gradle", "pom.xml", "ads.txt", "app-ads.txt"
        ],
        "version_control_exposed": [
            ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index", ".git/FETCH_HEAD", ".git/refs/heads/master",
            ".git/refs/heads/main", ".git/ORIG_HEAD", ".git/COMMIT_EDITMSG", ".git/description", ".git/hooks/",
            ".git/info/exclude", ".git/packed-refs",
            ".svn/entries", ".svn/wc.db", ".svn/pristine/", ".svn/all-wcprops", ".svn/wcprops/",
            ".hg/hgrc", ".hg/store/00manifest.i", ".hg/bookmarks", ".hg/branchmap.cache",
            ".bzr/README", ".bzr/checkout.conf", ".bzr/branch/"
        ],
        "common_admin_interfaces": [
            "admin/", "administrator/", "login/", "wp-admin/", "admin.php", "admin/login.php",
            "phpmyadmin/", "pma/", "cpanel/", "webadmin/", "admin_area/", "controlpanel/", "manage/",
            "user/login", "admin/dashboard", "backend/", "secure_admin/", "admincp/", "webpanel/",
            "django-admin/", "rails/info/properties", "admin123/", "secret-admin/", "admin.html", "login.html"
        ],
        "sensitive_directories": [
            "includes/", "uploads/", "files/", "backup/", "temp/", "tmp/", "private/", "secret/", "admin_files/",
            "config/", "cgi-bin/", "data/", "db/", "protected/", "logs/", "temp_files/", "bak/",
            "vendor/", "node_modules/", "storage/logs", "app/etc", "sites/default/files", "sites/default/private",
            "WEB-INF/", "WEB-INF/web.xml", "WEB-INF/classes/", "assets/private", ".ssh/", ".aws/", ".config/",
            "etc/", "conf/", "settings/"
        ],
        "security_txt_paths_list": ["/.well-known/security.txt", "/security.txt"]
    },
    "malware_php_signatures": [ # Note: Currently not used for server-side PHP file scanning by KAIROS.
                                # These are for potential future features or analysis of downloaded PHP source code (if ever implemented).
        r"eval\s*\(\s*base64_decode\s*\(", r"shell_exec\s*\(", r"system\s*\(", r"passthru\s*\(",
        r"pcntl_exec\s*\(", r"popen\s*\(", r"proc_open\s*\(", r"assert\s*\(", r"create_function\s*\(",
        r"php_uname\s*\(", r"fsockopen\s*\(", r"pfsockopen\s*\(",
        r"preg_replace\s*\(\s*['\"].*/e['\"]\s*,",
        r"\$\_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['\"].*['\"]\s*\]\s*=\s*.*\$\_",
        r"gz(un)?inflate\s*\(\s*base64_decode\s*\(",
        r"move_uploaded_file\s*\(\s*\$\_FILES\[.+?\]\['tmp_name'\]\s*,\s*['\"].+\.(php|phtml|phar|php[3-7]|shtml|cgi|pl|jsp|asp|aspx)['\"]",
        r"<\?php\s+include\s+['\"]\w+\.txt['\"]\s*;", r"phpjm\.com", r"c99shell", r"r57shell"
    ],
    "malware_js_signatures": [
        r"eval\s*\(", r"document\.write\s*\(.*%3Cscript", r"unescape\s*\(", r"decodeURIComponent\s*\(",
        r"String\.fromCharCode\s*\(", r"(?i)iframe.*src\s*=\s*['\"](?:javascript:|data:text/html|http[s]?://[^/]*evil)",
        r"crypto-js\.js", r"miner\.js", r"coinhive\.min\.js", r"webminerpool\.js", r"jsecoin\.com",
        r"\.innerHTML\s*=\s*.*<script>", r"appendChild\s*\(.*createElement\('script'\)",
        r"ws:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"load\s*\(\s*['\"].*evil", r"atob\s*\("
    ],
    "api_key_patterns": {
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Google OAuth ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "Google Cloud Platform API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Firebase API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Access Key (Full)": r"(?<![A-Za-z0-9/+=])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9/+=])",
        "AWS Secret Key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36,76}",
        "Slack Token (Legacy)": r"xox[pbar]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-fA-F0-9]{32}",
        "Slack Webhook": r"https?://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "Stripe API Key": r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}",
        "Twilio SID": r"AC[a-f0-9]{32}",
        "Twilio Auth Token": r"SK[a-f0-9]{32}",
        "SendGrid API Key": r"SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}",
        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
        "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
        "PayPal/Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "Artifactory API Key": r"\bAKC[a-zA-Z0-9]{10,}",
        "Cloudinary URL": r"cloudinary://[0-9]{15}:[0-9A-Za-z_-]{27}@[a-z0-9_-]+",
        "Heroku API Key (UUID)": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "New Relic User API Key": r"NRAK-[A-Z0-9]{27}",
        "OpenAI API Key": r"sk-[A-Za-z0-9]{48}",
        "Generic JWT": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*" # Can be noisy
    },
    "js_interesting_patterns": { # For JSense module
        "Cloud Storage URL (S3)": r"['\"](s3://[a-zA-Z0-9.-]+/[^'\"\s]+|https?://[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9.-]+\.amazonaws\.com/[^'\"\s]*)['\"]",
        "Cloud Storage URL (GCS)": r"['\"](gs://[a-zA-Z0-9.-]+/[^'\"\s]+|https?://storage\.googleapis\.com/[a-zA-Z0-9.-]+/[^'\"\s]*)['\"]",
        "Cloud Storage URL (Azure Blob)": r"['\"](https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net/[^'\"\s]+)['\"]",
        "Internal IP Address": r"['\"](10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.)[0-9]{1,3})['\"]",
        "Developer Comment (TODO/FIXME)": r"//\s*(TODO|FIXME|HACK|XXX|NOTE|OPTIMIZE):?\s*(.+)",
        "Potential Endpoint Path": r"['\"](/api(?:/v[0-9]+)?/[^'\"\s?#]+|/rest/[^'\"\s?#]+|/service/[^'\"\s?#]+|/graphql(?:/[^'\"\s?#]+)?|/_next/data/[^'\"\s?#]+|/\.netlify/functions/[^'\"\s?#]+)['\"]", # Made more specific
        "WebSocket URL": r"['\"](wss?://\S+?)['\"]",
        "Firebase Database URL": r"['\"](https?://[a-zA-Z0-9_-]+\.firebaseio\.com)['\"]"
    },
    "dns_records_to_query": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "DNSKEY", "SPF", "DMARC",
                             "PTR", "HINFO", "RP"],
    "common_ports_to_scan": "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1080,1433,1521,1723,2049,3306,3389,5432,5900,6379,8000,8008,8080,8443,8888,9000,9090,9200,9300,11211,27017,27018,50000,50070",
    "cms_specific_checks": {
        "WordPress": {
            "paths": ["/wp-login.php", "/xmlrpc.php", "/wp-json/", "/wp-content/debug.log", "/wp-cron.php",
                      "/wp-config.php.bak", "/wp-config.php~", "/wp-admin/install.php", "/readme.html", "/license.txt"],
            "signatures_in_html": [r"wp-content/themes", r"wp-includes", r"Yoast SEO", r"Rank Math", r"Elementor",
                                   r"WooCommerce"],
            "version_pattern": [
                r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9\.]+)",
                r"<meta name=\"generator\" content=\"WordPress ([0-9\.]+)\"",
                r"wp-includes/css/dist/block-library/style.min.css\?ver=([0-9\.]+)"
            ],
            "vulnerable_plugins_themes_check": True # Note: This remains a conceptual check without a vulnerability database.
        },
        "Joomla": {
            "paths": ["/administrator/", "/configuration.php-dist", "/README.txt", "/LICENSE.txt",
                      "/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml"],
            "signatures_in_html": [r"com_content", r"Joomla! - Open Source Content Management", r"media/jui/js",
                                   r"templates/system/css/system.css"],
            "version_pattern": [
                r"<meta name=\"generator\" content=\"Joomla! ([0-9\.]+) Platform\"",
                r"/media/cms/js/core\.js\?([a-f0-9]+)", # Often version hash
                r"Joomla! (\d+\.\d+\.\d+) - Open Source Content Management"
            ],
            "vulnerable_plugins_themes_check": True # Conceptual
        },
        "Drupal": {
            "paths": ["/user/login", "/CHANGELOG.txt", "/sites/default/settings.php", "/core/INSTALL.txt",
                      "/update.php", "/MAINTAINERS.txt"],
            "signatures_in_html": [r"Drupal\.settings", r"sites/default/files", r"X-Generator: Drupal",
                                   r"misc/drupal.js"],
            "version_pattern": [
                r"<meta name=\"Generator\" content=\"Drupal ([0-9\.]+)",
                r"Drupal ([0-9\.]+) \(http",
                r"misc/drupal\.js\?v=([0-9\.]+)"
            ],
            "vulnerable_plugins_themes_check": True # Conceptual
        },
        "Magento": {
            "paths": ["/downloader/", "/errors/report.php", "/RELEASE_NOTES.txt", "/app/etc/local.xml",
                      "/magento_version"],
            "signatures_in_html": [r"skin/frontend/", r"Magento", r"static/version", r"requirejs/mage"],
            "version_pattern": [
                r"Magento_Theme/js/responsive\.js\?version=([0-9\.]+)",
                r"<meta name=\"format-detection\" content=\"telephone=no\">\s*<script type=\"text/x-magento-init\">", # Presence indicates Magento 2
                r"MAGENTO_VERSION = '([0-9\.]+)'" # Magento 1
            ],
            "vulnerable_plugins_themes_check": True # Conceptual
        },
        "Shopify": { # SaaS, different kind of checks
            "paths": ["/admin", "/cart.js", "/password", "/collections.json", "/services/javascripts/currencies.js"],
            "signatures_in_html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"ShopifyAnalytics", r"shopify-cloud"],
            "version_pattern": [] # Version not typically exposed this way for Shopify itself. Apps might have versions.
        }
    },
    "security_headers_info": {
        "Strict-Transport-Security": "Instructs browsers to only connect via HTTPS. Check for 'max-age', 'includeSubDomains', 'preload'. High max-age (e.g., 31536000) is recommended.",
        "Content-Security-Policy": "Controls resources the browser is allowed to load. Complex to evaluate automatically, but presence is good. Check for 'unsafe-inline' or 'unsafe-eval' which weaken it.",
        "Content-Security-Policy-Report-Only": "Allows experimenting with CSP. Issues are reported but not blocked.",
        "X-Frame-Options": "Prevents clickjacking. Should be 'DENY' or 'SAMEORIGIN'. 'ALLOW-FROM uri' is deprecated.",
        "X-Content-Type-Options": "Prevents MIME-sniffing. Should be 'nosniff'.",
        "Referrer-Policy": "Controls how much referrer information is sent. 'no-referrer', 'strict-origin-when-cross-origin', or 'same-origin' are good choices.",
        "Permissions-Policy": "Controls browser features available to the page. Presence and restrictive policies are good.",
        "X-XSS-Protection": "Deprecated by modern browsers in favor of CSP, but '1; mode=block' was the strongest. If present, ensure it's not '0'.",
        "Set-Cookie": "Analyze for 'HttpOnly', 'Secure', 'SameSite' attributes (Strict or Lax preferred). Check 'Domain' and 'Path' for scope.",
        "Cross-Origin-Opener-Policy": "Protects against cross-origin attacks. 'same-origin' is a common strong value.",
        "Cross-Origin-Embedder-Policy": "Controls embedding of cross-origin resources. 'require-corp' is a common strong value.",
        "Cross-Origin-Resource-Policy": "Controls how cross-origin resources can be requested. 'same-origin' or 'same-site' are common."
    },
    "wayback_machine_limit": 25,
    "crtsh_timeout_seconds": 20,
    "js_analysis_max_file_size_kb": 1024,
    "enable_nmap_scan": True,
    "enable_whois_lookup": True,
    "enable_subdomain_bruteforce": True,
    "enable_crtsh_subdomain_search": True,
    "enable_wayback_machine_scan": True,
    "enable_js_file_analysis": True,
    "enable_error_page_analysis": True,
    "fuzzing_wordlist_file": "common_paths_fuzz.txt",
    "fuzzing_apply_common_extensions": [".php", ".html", ".txt", ".bak", ".old", ".config", ".json", ".xml", ".log", ".aspx", ".jsp", ".env", ".ini", ".yml", ".yaml"],
    "enable_directory_file_fuzzing": False # Off by default as it's more active
}

CONFIG = {}

# --- Logging Setup ---
logger = logging.getLogger("KAIROS") # Updated logger name
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d (%(funcName)s)] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
if not logger.hasHandlers():
    logger.addHandler(console_handler)


# --- Helper Functions ---
def load_config():
    global CONFIG
    if os.path.exists(CONFIG_FILE_NAME):
        try:
            with open(CONFIG_FILE_NAME, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            # Merge, ensuring user_config overrides defaults, and nested dicts are merged
            CONFIG = DEFAULT_CONFIG.copy() # Start with a fresh copy of defaults
            for key, value in user_config.items():
                if key in CONFIG and isinstance(CONFIG[key], dict) and isinstance(value, dict):
                    CONFIG[key].update(value) # Shallow merge for top-level dicts
                else:
                    CONFIG[key] = value

            # Deep merge specific nested dictionaries
            for key in ["sensitive_paths_categories", "cms_specific_checks", "api_key_patterns",
                        "security_headers_info", "js_interesting_patterns"]:
                if key in user_config and isinstance(DEFAULT_CONFIG.get(key), dict) and isinstance(user_config[key], dict):
                    # For these, ensure the default keys are present if user only provides partial updates
                    merged_dict = DEFAULT_CONFIG[key].copy()
                    merged_dict.update(user_config[key])
                    CONFIG[key] = merged_dict
                elif key in user_config: # If user provided a non-dict type for a dict field, take user's (might be intentional)
                    CONFIG[key] = user_config[key]
                # If key not in user_config, it's already taken from DEFAULT_CONFIG.copy()

            logger.info(f"Loaded configuration from {CONFIG_FILE_NAME}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding {CONFIG_FILE_NAME}: {e}. Using default configuration.")
            CONFIG = DEFAULT_CONFIG.copy()
        except Exception as e:
            logger.error(f"Error loading {CONFIG_FILE_NAME}: {e}. Using default configuration.")
            CONFIG = DEFAULT_CONFIG.copy()
    else:
        logger.info(f"{CONFIG_FILE_NAME} not found. Using default configuration and creating a template file.")
        CONFIG = DEFAULT_CONFIG.copy()
        try:
            with open(CONFIG_FILE_NAME, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
            logger.info(f"Default configuration template saved to {CONFIG_FILE_NAME}")
        except Exception as e:
            logger.error(f"Could not save default configuration template: {e}")

    subdomain_file_path = CONFIG.get("common_subdomains_file", "common_subdomains.txt")
    if os.path.exists(subdomain_file_path):
        try:
            with open(subdomain_file_path, 'r', encoding='utf-8') as f_subs:
                CONFIG["common_subdomains"] = [line.strip() for line in f_subs if
                                               line.strip() and not line.startswith('#')]
            logger.info(f"Loaded {len(CONFIG['common_subdomains'])} subdomains from {subdomain_file_path}")
        except Exception as e:
            logger.warning(f"Could not load subdomains from {subdomain_file_path}: {e}. Using default list.")
            CONFIG["common_subdomains"] = CONFIG.get("default_common_subdomains", []).copy()
    else:
        logger.info(f"Subdomain file {subdomain_file_path} not found. Using default list.")
        CONFIG["common_subdomains"] = CONFIG.get("default_common_subdomains", []).copy()


def generate_severity_tag(severity: str) -> str:
    if platform.system() == "Windows" and not os.getenv('WT_SESSION'):
        return f"[{severity.upper()}]"
    colors = {"CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m",
              "INFO": "\033[92m", "UNKNOWN": "\033[0m"}
    end_color = "\033[0m"
    return f"{colors.get(severity.upper(), colors['UNKNOWN'])}{severity.upper()}{end_color}"


def add_finding(results_dict: dict, category: str, finding_data: dict, log_message: str = "",
                severity_for_log: str = "INFO"):
    if category not in results_dict:
        results_dict[category] = []

    # More robust duplicate check using a signature of key fields
    new_finding_signature_parts = [
        finding_data.get("type"),
        finding_data.get("description"),
        finding_data.get("target_url"), # For findings tied to a specific URL
        str(finding_data.get("evidence_summary", finding_data.get("evidence", "")))[:100] # First 100 chars of evidence
    ]
    # For specific types like 'API Key', include the key name and source if JS
    if finding_data.get("type") == "Sensitive Data Exposure" and "key_name" in finding_data.get("details", {}):
        new_finding_signature_parts.append(finding_data["details"]["key_name"])
        if "source_js_url" in finding_data["details"]:
            new_finding_signature_parts.append(finding_data["details"]["source_js_url"])


    new_finding_signature = tuple(new_finding_signature_parts)

    is_duplicate = False
    for existing_finding in results_dict[category]:
        existing_finding_signature_parts = [
            existing_finding.get("type"),
            existing_finding.get("description"),
            existing_finding.get("target_url"),
            str(existing_finding.get("evidence_summary", existing_finding.get("evidence", "")))[:100]
        ]
        if existing_finding.get("type") == "Sensitive Data Exposure" and "key_name" in existing_finding.get("details", {}):
            existing_finding_signature_parts.append(existing_finding["details"]["key_name"])
            if "source_js_url" in existing_finding["details"]:
                existing_finding_signature_parts.append(existing_finding["details"]["source_js_url"])

        existing_finding_signature_tuple = tuple(existing_finding_signature_parts)

        if new_finding_signature == existing_finding_signature_tuple:
            is_duplicate = True
            # logger.debug(f"Duplicate finding skipped: {new_finding_signature}")
            break

    if not is_duplicate:
        results_dict[category].append(finding_data)

    if log_message:
        log_level_attr = getattr(logging, severity_for_log.upper(), logging.INFO)
        logger.log(log_level_attr, f"{generate_severity_tag(severity_for_log)} {log_message}")


def format_report_section(title: str, data: dict | list | str | None, indent_level: int = 0) -> str:
    indent = "  " * indent_level
    section_str = f"{indent}--- {title} ---\n"
    if data is None:
        section_str += f"{indent}  N/A\n"
    elif isinstance(data, str):
        section_str += "".join([f"{indent}  {line}\n" for line in data.strip().splitlines()])
    elif isinstance(data, list):
        if not data:
            section_str += f"{indent}  None found.\n"
        else:
            for item in data:
                if isinstance(item, dict):
                    section_str += f"{indent}  - "
                    details = []
                    for k, v_item in item.items():
                        v_str = str(v_item)
                        if len(v_str) > 150: v_str = v_str[:147] + "..."
                        details.append(
                            f"{k.replace('_', ' ').title()}: {html.unescape(v_str)}")
                    section_str += ", ".join(details) + "\n"
                else:
                    section_str += f"{indent}  - {html.unescape(str(item))}\n"
    elif isinstance(data, dict):
        if not data:
            section_str += f"{indent}  N/A\n"
        else:
            for key, value in data.items():
                key_title = str(key).replace('_', ' ').title()
                if isinstance(value, list):
                    if not value:
                        val_str = "N/A"
                    elif value and isinstance(value[0], dict):
                        section_str += f"{indent}  {key_title}:\n"
                        section_str += format_report_section("", value, indent_level + 2)
                        continue
                    else:
                        val_str = (', '.join(map(lambda x: html.unescape(str(x)), value)))
                    section_str += f"{indent}  {key_title}: {val_str}\n"
                elif isinstance(value, dict):
                    section_str += f"{indent}  {key_title}:\n"
                    section_str += format_report_section("", value, indent_level + 2)
                else:
                    section_str += f"{indent}  {key_title}: {html.unescape(str(value)) if value is not None else 'N/A'}\n"
    return section_str + "\n"


def generate_vuln_search_url(software_name, version=None):
    query = f"{software_name} {version if version else ''} CVE"
    vulners_url = f"https://vulners.com/search?query={query.replace(' ', '+')}"
    cve_mitre_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query.replace(' ', '+')}"
    nist_nvd_url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query={query.replace(' ', '+')}&search_type=all"
    return {"vulners": vulners_url, "cve_mitre": cve_mitre_url, "nist_nvd": nist_nvd_url}


# --- Main SiteScanner Class ---
class SiteScanner:
    def __init__(self, target_url: str, user_config_overrides: dict | None = None):
        self.raw_target_url = target_url
        self.config = CONFIG.copy()
        if user_config_overrides:
            for key, value in user_config_overrides.items():
                if key in self.config and isinstance(self.config[key], dict) and isinstance(value, dict):
                    self.config[key].update(value)
                else:
                    self.config[key] = value

        parsed_initial_url = urlparse(target_url)
        self.scheme = parsed_initial_url.scheme.lower()
        self.domain = parsed_initial_url.netloc.lower().split(':')[0]
        self.port = parsed_initial_url.port

        if not self.scheme:
            logger.warning(f"No scheme provided for {target_url}. Assuming 'http'. Will attempt HTTPS first.")
            self.scheme = "http"
        if not self.domain:
            if parsed_initial_url.path and not parsed_initial_url.netloc:
                self.domain = parsed_initial_url.path.split('/')[0].lower()
                path_part = parsed_initial_url.path[len(self.domain):]
                logger.info(
                    f"Extracted domain '{self.domain}' from path. Assuming target is {self.scheme}://{self.domain}{path_part}")
                self.target_url = f"{self.scheme}://{self.domain}{path_part}"
            else:
                raise ValueError("Invalid target URL: Could not determine domain.")
        else:
            self.target_url = f"{self.scheme}://{self.domain}"
            if self.port and not (
                    (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)):
                self.target_url += f":{self.port}"
            if parsed_initial_url.path and self.target_url.endswith(self.domain): # Ensure path is appended correctly if base URL is just domain
                self.target_url = urljoin(self.target_url + ("/" if not self.target_url.endswith("/") else ""),
                                          parsed_initial_url.path.lstrip('/'))
            elif parsed_initial_url.path: # If URL already had a path beyond just the domain
                 self.target_url = urljoin(self.target_url, parsed_initial_url.path)

            if parsed_initial_url.query: self.target_url += f"?{parsed_initial_url.query}"
            if parsed_initial_url.fragment: self.target_url += f"#{parsed_initial_url.fragment}"

        self.results: dict = {
            "scan_metadata": {"target_input": self.raw_target_url, "target_normalized": self.target_url,
                              "effective_domain": self.domain, "start_time": None, "end_time": None,
                              "scanner_version": self.config["scanner_version"]},
            "general_info": {"ip_addresses": [], "final_url": self.target_url, "server_location_guess": None},
            "http_details": {"status_code_final": None, "http_version": None, "headers_final": {},
                             "security_headers_analysis": {}, "cookies_set": [], "allowed_methods": [],
                             "redirect_chain": []},
            "dns_information": {"records": {}, "dnssec_status": "Unknown", "mail_servers_config": {},
                                "whois_data": None, "wildcard_dns_detected": False}, # Added wildcard
            "technology_fingerprint": {"server_software": [], "x_powered_by": [], "cms_identified": None,
                                       "frameworks_libraries": [], "analytics_trackers": [], "cdn_providers": [],
                                       "programming_languages_detected": [], "operating_system_guesses": [],
                                       "version_control_type": None, "wappalyzer_findings": [],
                                       "software_versions_found": {}, "error_page_fingerprints": []},
            "content_analysis": {"robots_txt_content": None, "sitemap_urls_found": [], "page_title": None,
                                 "meta_description": None, "meta_keywords": None, "developer_comments_found": [],
                                 "emails_on_page": [], "phone_numbers_on_page": [], "social_media_links_on_page": [],
                                 "internal_links_count": 0, "external_links_count": 0, "suspected_api_keys": [],
                                 "linked_documents": [], "forms_found_count": 0,
                                 "javascript_files": {"count": 0, "files": [], "analysis_summary": []},
                                 "css_files_count": 0, "archived_urls": [], "ads_txt_content": None,
                                 "app_ads_txt_content": None},
            "security_posture": {"open_ports": [], "ssl_tls_config": {}, "vulnerability_findings": [],
                                 "malware_code_signatures": [], "exposed_git_details": None,
                                 "exposed_svn_details": None, "exposed_mercurial_details": None,
                                 "exposed_bazaar_details": None,
                                 "exposed_sensitive_files": [], "directory_listings_found": [],
                                 "security_txt_contents": None, "http_auth_type": None,
                                 "potential_api_endpoints": [], "fuzzed_paths_found": []}, # Added fuzzed paths
            "subdomain_discovery": {"discovered_subdomains": []},
            "cms_specific_findings": {}
        }
        self.session: aiohttp.ClientSession | None = None
        self.user_agent = self.config["default_user_agent"]
        self.request_timeout = aiohttp.ClientTimeout(total=self.config["request_timeout_seconds"])
        self.semaphore = asyncio.Semaphore(self.config["max_concurrent_requests"])
        self._main_page_response_cache: tuple[aiohttp.ClientResponse, bytes] | None = None
        self._main_page_html_cache: str | None = None
        self._main_page_soup_cache: BeautifulSoup | None = None
        self._robots_txt_cache: str | None = None
        self._fetched_js_urls = set()
        self._sitemap_processing_queue: asyncio.Queue[str] = asyncio.Queue() # type: ignore # For sitemap URLs
        self._processed_sitemap_urls: set[str] = set() # Track sitemaps processed to avoid loops


        logger.info(f"KAIROS initialized for target: {self.target_url}")

    async def __aenter__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit_per_host=self.config["max_concurrent_requests"],
                                         force_close=True)
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": self.user_agent},
            connector=connector,
            timeout=self.request_timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        self.results["scan_metadata"]["start_time"] = datetime.now(timezone.utc).isoformat()
        logger.debug("aiohttp.ClientSession opened.")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session and not self.session.closed:
            await self.session.close()
            logger.debug("aiohttp.ClientSession closed.")
        self.results["scan_metadata"]["end_time"] = datetime.now(timezone.utc).isoformat()
        if exc_type:
            logger.error(f"Scanner exited with an error: {exc_type.__name__}: {exc_val}", exc_info=True)

    async def _make_request(self, url: str, method: str = "GET", allow_redirects: bool = True, max_retries: int = 1,
                            **kwargs) -> tuple[aiohttp.ClientResponse | None, bytes | None]:
        full_url = url
        if not url.startswith(("http://", "https://")):
            full_url = urljoin(self.results["general_info"].get("final_url", self.target_url), url)

        retries = 0
        while retries <= max_retries:
            async with self.semaphore:
                if not self.session or self.session.closed:
                    logger.error("Session is closed or uninitialized. Cannot make request.")
                    return None, None
                try:
                    logger.debug(f"Requesting ({method}): {full_url} (Attempt: {retries + 1})")
                    request_timeout_obj = kwargs.pop('timeout', self.request_timeout) # Correctly get timeout object
                    async with self.session.request(method, full_url, allow_redirects=allow_redirects,
                                                    timeout=request_timeout_obj, **kwargs) as response:
                        if (full_url == self.target_url or full_url == self.results["general_info"].get("final_url")) and response.history:
                            self.results["http_details"]["redirect_chain"] = [str(r.url) for r in response.history]
                            self.results["http_details"]["redirect_chain"].append(str(response.url))

                        content_bytes = await response.read()
                        return response, content_bytes
                except aiohttp.ClientConnectorCertificateError as e:
                    logger.warning(f"SSL Certificate error for {full_url}: {e.os_error if hasattr(e, 'os_error') else e}") # type: ignore
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "SSL/TLS Issue",
                                 "description": f"SSL Certificate error: {e.os_error if hasattr(e, 'os_error') else e}", # type: ignore
                                 "target_url": full_url, "severity": "Medium", "evidence_summary": str(e)},
                                log_message=f"SSL Certificate error at {full_url}", severity_for_log="MEDIUM")
                    return None, None
                except aiohttp.ClientConnectorError as e:
                    logger.warning(f"Connection error for {full_url}: {type(e).__name__} - {e.os_error if hasattr(e, 'os_error') else e}") # type: ignore
                except aiohttp.ClientResponseError as e: # type: ignore
                    logger.warning(f"HTTP error {e.status} for {full_url}: {e.message}")
                    try:
                        content_bytes_err = await e.response.read() if hasattr(e, 'response') and e.response else b"" # type: ignore
                    except:
                        content_bytes_err = b""
                    return e.response if hasattr(e, 'response') else None, content_bytes_err # type: ignore
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout during request to {full_url}")
                except Exception as e:
                    logger.error(f"Unexpected error during request to {full_url}: {type(e).__name__} - {e}", exc_info=False)

                retries += 1
                if retries <= max_retries:
                    await asyncio.sleep(1 * retries)
                else:
                    logger.error(f"Max retries reached for {full_url}.")
        return None, None

    async def fetch_and_cache_main_page(self, force_reload: bool = False) -> bool:
        if self._main_page_response_cache and not force_reload:
            logger.debug("Using cached main page response.")
            return True

        initial_target = self.target_url
        if urlparse(initial_target).scheme == "http":
            https_target = initial_target.replace("http://", "https://", 1)
            logger.info(f"Probing HTTPS endpoint: {https_target}")
            # Use a shorter timeout for this probe
            probe_timeout = aiohttp.ClientTimeout(total=10)
            response_https, content_bytes_https = await self._make_request(https_target, timeout=probe_timeout)
            if response_https and response_https.status < 400 and content_bytes_https is not None:
                logger.info(f"HTTPS probe successful for {https_target}. Updating target to HTTPS.")
                self.target_url = https_target
                self.scheme = "https"
                parsed_target = urlparse(self.target_url)
                self.port = parsed_target.port
                self.results["scan_metadata"]["target_normalized"] = self.target_url
            else:
                status_msg = f" (Status: {response_https.status})" if response_https else ""
                logger.info(f"HTTPS probe for {https_target} failed or non-2xx/3xx{status_msg}. Sticking with {initial_target}.")


        response, content_bytes = await self._make_request(self.target_url)

        if not response or content_bytes is None:
            logger.error(f"Failed to fetch main page for {self.target_url}. Critical for many scans.")
            return False

        self._main_page_response_cache = (response, content_bytes)
        self.results["general_info"]["final_url"] = str(response.url)
        self.results["http_details"]["status_code_final"] = response.status
        self.results["http_details"]["http_version"] = f"{response.version.major}.{response.version.minor}" if response.version else "Unknown"
        self.results["http_details"]["headers_final"] = dict(response.headers)

        final_domain = urlparse(str(response.url)).netloc.lower().split(':')[0]
        if final_domain and final_domain != self.domain:
            logger.info(f"Effective domain changed by redirect: {self.domain} -> {final_domain}")
            self.domain = final_domain
            self.results["scan_metadata"]["effective_domain"] = final_domain

        try:
            charset = response.charset if response.charset else 'utf-8'
            self._main_page_html_cache = content_bytes.decode(charset, errors='replace')
        except UnicodeDecodeError:
            logger.warning(f"UnicodeDecodeError for main page with charset {response.charset or 'unknown'}. Trying 'latin-1'.")
            try:
                self._main_page_html_cache = content_bytes.decode('latin-1', errors='replace')
            except Exception as e_latin1:
                 logger.error(f"Failed to decode main page HTML with latin-1 fallback: {e_latin1}")
                 self._main_page_html_cache = None
        except Exception as e:
            logger.error(f"Failed to decode main page HTML: {e}")
            self._main_page_html_cache = None

        if self._main_page_html_cache:
            try:
                self._main_page_soup_cache = BeautifulSoup(self._main_page_html_cache, 'html.parser')
                logger.info(f"Successfully fetched and parsed main page: {self.results['general_info']['final_url']} (Status: {response.status})")
            except Exception as e_soup:
                logger.error(f"BeautifulSoup failed to parse main page HTML: {e_soup}")
                self._main_page_soup_cache = None # Ensure it's None if parsing fails
                # Still return True if response was successful, but HTML parsing failed
                return response.status < 400
        else:
            logger.error("Main page HTML content could not be decoded or is empty.")
            return response.status < 400 # Return True if response ok, even if HTML empty
        return True

    async def run_full_scan(self):
        logger.info(f"Starting KAIROS full scan for {self.raw_target_url} (Normalized: {self.target_url})...")
        if not await self.fetch_and_cache_main_page():
            logger.critical("Aborting full scan: Could not fetch or parse the main target page.")
            if self.config.get("enable_whois_lookup", True) and WHOIS_CORRECT_LIB:
                await self.gather_whois_information()
            await self.gather_dns_information() # Attempt DNS even if main page fails
            return

        logger.info("--- Stage: Core Information Gathering ---")
        core_tasks = [
            self.gather_ip_addresses(),
            self.gather_dns_information(), # Wildcard check is now part of this
            self.analyze_http_response_details(),
            self.fingerprint_technologies(),
            self.analyze_web_content(),
            self.fetch_and_analyze_robots_txt(), # Queues sitemaps found here
            self.fetch_ads_txt_files(),
            self.discover_and_fetch_sitemaps(), # Queues common/HTML-linked sitemaps
            self.perform_ssl_tls_analysis(),
            self.check_http_options_and_auth(),
        ]
        if self.config.get("enable_whois_lookup", True) and WHOIS_CORRECT_LIB:
            core_tasks.append(self.gather_whois_information())
        if self.config.get("enable_wayback_machine_scan", True) and REQUESTS_AVAILABLE:
            core_tasks.append(self.fetch_wayback_urls())
        if self.config.get("enable_error_page_analysis", True):
            core_tasks.append(self.analyze_common_error_pages())

        await self._execute_task_group(core_tasks, "Core Info Gathering")

        # After initial sitemap discovery, process the queue iteratively
        await self._process_sitemap_queue_iteratively()


        logger.info("--- Stage: Security-Oriented Scans ---")
        security_tasks = [
            self.scan_for_exposed_paths_and_files(),
            self.check_for_version_control_exposure(),
            self.scan_page_for_malware_signatures(self._main_page_html_cache, self.results["general_info"]["final_url"], "HTML"),
            self.conduct_basic_vulnerability_checks(),
            self.fetch_and_analyze_security_txt(),
            self.discover_api_endpoints()
        ]
        if self.config.get("enable_nmap_scan", True) and NMAP_AVAILABLE:
            security_tasks.append(self.scan_for_open_ports())
        else:
            if not NMAP_AVAILABLE:
                logger.info("Nmap library not available, skipping port scan.")
            else: # Nmap available but disabled
                logger.info("Nmap scan disabled in configuration, skipping port scan.")
            self.results["security_posture"]["open_ports"] = [{"status": "Skipped - Nmap library not found or scan disabled."}]

        if self.config.get("enable_js_file_analysis", True):
            security_tasks.append(self.analyze_linked_javascript_files())

        if self.config.get("enable_directory_file_fuzzing", False):
            security_tasks.append(self.fuzz_common_paths())

        await self._execute_task_group(security_tasks, "Security Scans")

        logger.info("--- Stage: Enumeration ---")
        enumeration_tasks = [
            self.enumerate_and_verify_subdomains(),
        ]
        await self._execute_task_group(enumeration_tasks, "Enumeration")

        logger.info("--- Stage: Contextual & CMS-Specific Scans ---")
        await self.run_cms_specific_scans_if_detected()

        logger.info(f"KAIROS full scan completed for {self.target_url}.")

    async def _execute_task_group(self, tasks: list, group_name: str):
        logger.info(f"Starting task group: {group_name} ({len(tasks)} tasks)")
        valid_tasks = [task for task in tasks if task is not None]
        if not valid_tasks:
            logger.info(f"No tasks to execute in group: {group_name}")
            return

        # Wraps asyncio.as_completed for tqdm progress bar
        for task_future in async_tqdm(asyncio.as_completed(valid_tasks), total=len(valid_tasks), desc=group_name, unit="task", leave=False, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]'):
            try:
                await task_future
            except Exception as e_task_group:
                # This logging helps identify which task in the group might have failed if the task itself doesn't log its error well.
                logger.error(f"Unhandled exception in task group '{group_name}': {type(e_task_group).__name__} - {e_task_group}", exc_info=True)

    async def gather_ip_addresses(self):
        logger.info(f"Resolving IP addresses for {self.domain}...")
        loop = asyncio.get_event_loop()
        found_ips = set()
        primary_ip_type_preference = [socket.AF_INET, socket.AF_INET6]

        for fam in primary_ip_type_preference:
            try:
                ainfo = await loop.run_in_executor(None, socket.getaddrinfo, self.domain, None, fam, socket.SOCK_STREAM) # type: ignore
                for res in ainfo: # type: ignore
                    ip_addr = res[4][0] # type: ignore
                    ip_version = 4 if fam == socket.AF_INET else 6
                    if ip_addr not in found_ips:
                        self.results["general_info"]["ip_addresses"].append({"ip": ip_addr, "version": ip_version})
                        found_ips.add(ip_addr)
                        logger.debug(f"IPv{ip_version} address found: {ip_addr}")
            except socket.gaierror:
                logger.warning(f"Could not resolve IPv{4 if fam == socket.AF_INET else 6} address for {self.domain}.")
            except Exception as e_ip_res:
                logger.error(f"Error resolving IPv{4 if fam == socket.AF_INET else 6} for {self.domain}: {e_ip_res}")

        if not self.results["general_info"]["ip_addresses"]:
            logger.error(f"Failed to resolve any IP address for {self.domain}.")
            add_finding(self.results["security_posture"], "vulnerability_findings",
                        {"type": "Configuration Issue", "description": "Domain does not resolve to any IP address.",
                         "target_url": self.domain, "severity": "High", "evidence_summary": "DNS resolution failed"},
                        log_message=f"Domain {self.domain} failed to resolve.", severity_for_log="HIGH")
        else:
            logger.info(f"IP addresses for {self.domain}: {[ip_info['ip'] for ip_info in self.results['general_info']['ip_addresses']]}")

    async def gather_dns_information(self):
        logger.info(f"Gathering DNS records for {self.domain}...")
        dns_results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config["dns_timeout_seconds"]
        resolver.lifetime = self.config["dns_timeout_seconds"] * 2

        # Basic wildcard DNS check (moved earlier)
        try:
            wildcard_test_host = f"kairos-nonexistent-test-{os.urandom(4).hex()}.{self.domain}"
            await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, wildcard_test_host, "A") # type: ignore
            self.results["dns_information"]["wildcard_dns_detected"] = True
            logger.warning(f"Potential wildcard DNS detected for *.{self.domain}. Subdomain enumeration results may include false positives.")
            add_finding(self.results["dns_information"], "dns_issues", # Store in a new sub-category
                        {"type": "Wildcard DNS",
                         "description": f"Wildcard DNS seems to be configured for *.{self.domain}. This means non-existent subdomains might resolve.",
                         "severity": "Info"}, # Info, as it's a configuration choice, not a vuln per se
                         log_message=f"Wildcard DNS detected for *.{self.domain}", severity_for_log="INFO")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self.results["dns_information"]["wildcard_dns_detected"] = False
        except Exception as e_wildcard: # Catch any other errors during this non-critical check
            logger.debug(f"Error during wildcard DNS check: {e_wildcard}")


        for record_type in self.config["dns_records_to_query"]:
            try:
                logger.debug(f"Querying DNS {record_type} record for {self.domain}")
                if record_type == "PTR": # PTR needs IP, must be handled after A/AAAA or if IP is known
                    ptr_records = []
                    # Ensure gather_ip_addresses has run or ips are available
                    if not self.results["general_info"]["ip_addresses"]:
                        logger.debug(f"Skipping PTR for {self.domain} as no IPs resolved yet/available for it.")
                        dns_results[record_type] = ["Info: Skipped, no IP resolved for primary domain to PTR query"]
                        continue

                    for ip_info in self.results["general_info"]["ip_addresses"]:
                        try:
                            rev_name = dns.reversename.from_address(ip_info["ip"])
                            answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, rev_name, record_type) # type: ignore
                            ptr_records.extend([rdata.to_text().strip('"').strip() for rdata in answers]) # type: ignore
                        except dns.resolver.NXDOMAIN:
                            logger.debug(f"No PTR record for IP {ip_info['ip']}.")
                        except Exception as e_ptr_ip:
                            logger.warning(f"Error querying PTR for {ip_info['ip']}: {e_ptr_ip}")
                    if ptr_records: dns_results[record_type] = sorted(list(set(ptr_records))) # Ensure unique
                    else: dns_results[record_type] = []
                    continue

                answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, self.domain, record_type) # type: ignore
                processed_answers = []
                for rdata in answers: # type: ignore
                    if record_type == "SOA":
                        processed_answers.append(f"MNAME: {rdata.mname}, RNAME: {rdata.rname}, Serial: {rdata.serial}") # type: ignore
                    elif record_type == "MX":
                        processed_answers.append(f"{rdata.preference} {rdata.exchange}") # type: ignore
                    elif record_type == "SRV":
                        processed_answers.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}") # type: ignore
                    else:
                        processed_answers.append(rdata.to_text().strip('"').strip()) # type: ignore
                dns_results[record_type] = sorted(list(set(processed_answers))) # Ensure unique records

            except dns.resolver.NoAnswer:
                logger.debug(f"No {record_type} record found for {self.domain}.")
                dns_results[record_type] = []
            except dns.resolver.NXDOMAIN:
                logger.error(f"DNS resolution failed (NXDOMAIN) for {self.domain} while querying {record_type}.")
                dns_results[record_type] = ["Error: NXDOMAIN"]
                if record_type in ["A", "AAAA"] and not self.results["general_info"]["ip_addresses"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "DNS Issue", "description": f"Domain {self.domain} does not exist (NXDOMAIN).",
                                 "target_url": self.domain, "severity": "Critical",
                                 "evidence_summary": f"{record_type} query failed"},
                                log_message=f"NXDOMAIN for {self.domain} on {record_type}", severity_for_log="CRITICAL")
                break
            except dns.exception.Timeout:
                logger.warning(f"DNS query timeout for {record_type} record of {self.domain}.")
                dns_results[record_type] = ["Error: Timeout"]
            except dns.rdatatype.UnknownRdatatype: # type: ignore
                logger.debug(f"DNS record type {record_type} is unknown or not directly queryable for {self.domain}.")
            except Exception as e_dns:
                logger.error(f"Error fetching DNS {record_type} for {self.domain}: {type(e_dns).__name__} - {e_dns}")
                dns_results[record_type] = [f"Error: {type(e_dns).__name__}"]

        self.results["dns_information"]["records"] = dns_results

        mail_config = {}
        if "MX" in dns_results and dns_results["MX"] and not any("Error:" in r for r in dns_results["MX"]):
            mail_config["mx_records"] = dns_results["MX"]

        txt_records = dns_results.get("TXT", [])

        spf_record_val = next((txt for txt in txt_records if "v=spf1" in txt.lower()), None)
        if dns_results.get("SPF") and not any("Error:" in r for r in dns_results["SPF"]): # Check dedicated SPF type too
            mail_config["spf_record_type"] = dns_results["SPF"]
            if not spf_record_val and dns_results["SPF"]: # Prioritize dedicated SPF if TXT based one is not found
                 spf_record_val = dns_results["SPF"][0] if isinstance(dns_results["SPF"], list) and dns_results["SPF"] else None


        if spf_record_val:
            mail_config["spf_record_effective"] = spf_record_val # Store the effective SPF record
            if "~all" in spf_record_val or "?all" in spf_record_val:
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "SPF Policy Weak",
                             "description": f"SPF record uses '{'~all (SoftFail)' if '~all' in spf_record_val else '?all (Neutral)'}' which is less secure than '-all (Fail)'.",
                             "severity": "Low", "evidence_summary": spf_record_val},
                            log_message=f"Weak SPF policy ({'~all' if '~all' in spf_record_val else '?all'}) found", severity_for_log="LOW")

        dmarc_record_val = None
        try:
            dmarc_answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, f"_dmarc.{self.domain}", "TXT") # type: ignore
            dmarc_from_subdomain = [rdata.to_text().strip('"').strip() for rdata in dmarc_answers if "v=dmarc1" in rdata.to_text().lower()] # type: ignore
            if dmarc_from_subdomain:
                dmarc_record_val = dmarc_from_subdomain[0]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug(f"No DMARC record found at _dmarc.{self.domain}. Checking base domain TXT records.")
            # Fallback to checking TXT records on the base domain if _dmarc doesn't exist
            dmarc_record_val = next((txt for txt in txt_records if "v=dmarc1" in txt.lower()), None)
        except Exception as e_dmarc:
            logger.warning(f"Error querying DMARC for _dmarc.{self.domain}: {e_dmarc}")

        if dmarc_record_val:
            mail_config["dmarc_record_effective"] = dmarc_record_val
            if "p=none" in dmarc_record_val.lower():
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "DMARC Policy Weak",
                             "description": "DMARC policy is 'p=none' (monitor mode). Consider 'p=quarantine' or 'p=reject' for enforcement.",
                             "severity": "Medium", "evidence_summary": dmarc_record_val},
                            log_message="DMARC policy 'p=none' found", severity_for_log="MEDIUM")
        else:
            add_finding(self.results["dns_information"], "mail_servers_config_issues",
                        {"type": "DMARC Policy Missing",
                         "description": "No DMARC record found. This can make the domain more susceptible to email spoofing.",
                         "severity": "Medium", "evidence_summary": "DMARC not found"},
                        log_message="DMARC record missing", severity_for_log="MEDIUM")

        dkim_selectors = ["default._domainkey", "google._domainkey", "selector1._domainkey", "selector2._domainkey",
                          "k1._domainkey", "dkim._domainkey", "mandrill._domainkey", "smtp._domainkey", "zoho._domainkey", "pm._domainkey"] # Added more
        dkim_found = []
        for selector in dkim_selectors:
            try:
                full_dkim_query = f"{selector}.{self.domain}"
                answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, full_dkim_query, "TXT") # type: ignore
                for rdata in answers: # type: ignore
                    if "v=dkim1" in rdata.to_text().lower(): # type: ignore
                        dkim_found.append(f"{selector}: {rdata.to_text().strip()}") # type: ignore
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e_dkim:
                logger.debug(f"Error querying DKIM selector {selector}: {e_dkim}")
        if dkim_found: mail_config["dkim_records_found_heuristic"] = dkim_found

        self.results["dns_information"]["mail_servers_config"] = mail_config

        if "DNSKEY" in dns_results and dns_results["DNSKEY"] and not any("Error:" in r for r in dns_results["DNSKEY"]):
            self.results["dns_information"]["dnssec_status"] = "Likely Enabled (DNSKEY found). Full validation requires a validating resolver."
            logger.info("DNSSEC appears to be enabled (DNSKEY records found).")
        else:
            self.results["dns_information"]["dnssec_status"] = "Not Enabled or Not Verifiable (No DNSKEY/Error)"
            logger.info("DNSSEC not detected or DNSKEY query failed/empty.")
        logger.info(f"DNS information gathering for {self.domain} complete.")

    async def gather_whois_information(self):
        if not self.config.get("enable_whois_lookup", True):
            logger.info("WHOIS lookup disabled by configuration.")
            self.results["dns_information"]["whois_data"] = {"status": "Skipped - Disabled in config."}
            return
        if not WHOIS_CORRECT_LIB:
            logger.warning("Skipping WHOIS lookup due to missing or incorrect 'python-whois' library.")
            self.results["dns_information"]["whois_data"] = {"status": "Skipped - python-whois library issue."}
            return

        logger.info(f"Fetching WHOIS information for {self.domain}...")
        try:
            # The whois library can sometimes be slow, run in executor
            whois_data_obj = await asyncio.get_event_loop().run_in_executor(None, whois.whois, self.domain)

            # The python-whois library returns a class instance or None.
            # Access data using attributes or .get() on its __dict__
            if whois_data_obj and (getattr(whois_data_obj, 'domain_name', None) or getattr(whois_data_obj, 'DOMAIN_NAME', None) or getattr(whois_data_obj, 'name', None) ):
                sanitized_whois = {}
                # Iterate over __dict__ for attributes
                for key, value in whois_data_obj.__dict__.items():
                    k_lower = key.lower() if isinstance(key, str) else key
                    if isinstance(value, list):
                        sanitized_whois[k_lower] = [item.isoformat() if isinstance(item, datetime) else str(item) for item in value]
                    elif isinstance(value, datetime):
                        sanitized_whois[k_lower] = value.isoformat()
                    else:
                        sanitized_whois[k_lower] = str(value) if value is not None else None
                self.results["dns_information"]["whois_data"] = sanitized_whois
                logger.info(f"WHOIS data successfully retrieved for {self.domain}.")

                # Check for privacy protection
                privacy_keywords = ["privacy", "redacted for privacy", "whoisguard", "domains by proxy", "contactprivacy", "private registration", "data protected", "proxy", "shielded"]
                registrant_info_str = "".join([str(sanitized_whois.get(field, "")).lower() for field in ["registrant_name", "registrant_organization", "registrant_email", "name", "org", "email", "admin_name", "admin_email", "tech_email", "tech_name"]])

                if any(keyword in registrant_info_str for keyword in privacy_keywords) or \
                   any(keyword in str(sanitized_whois.get("emails", "")).lower() for keyword in privacy_keywords):
                    self.results["dns_information"]["whois_privacy_enabled"] = True
                    logger.info("WHOIS privacy protection appears to be enabled.")
                else:
                    self.results["dns_information"]["whois_privacy_enabled"] = False

            elif whois_data_obj and hasattr(whois_data_obj, 'text') and whois_data_obj.text and "limit exceeded" in whois_data_obj.text.lower():
                logger.warning(f"WHOIS lookup for {self.domain} failed due to rate limiting.")
                self.results["dns_information"]["whois_data"] = {"status": "Rate limit exceeded", "raw_text": whois_data_obj.text}
            elif whois_data_obj: # Fallback for unexpected structure or partial data
                raw_text_preview = str(whois_data_obj.text)[:200] if hasattr(whois_data_obj, 'text') else str(whois_data_obj)[:200]
                logger.warning(f"Partial or unusual WHOIS data for {self.domain}. Raw text preview: {raw_text_preview}")
                try: # Try to serialize its dict form
                    self.results["dns_information"]["whois_data"] = {k.lower() if isinstance(k,str) else k: str(v) for k,v in whois_data_obj.__dict__.items()}
                except Exception:
                     self.results["dns_information"]["whois_data"] = {"status": "Partial/Unusual data", "raw_text_preview": raw_text_preview}
            else:
                logger.warning(f"No WHOIS data returned for {self.domain}.")
                self.results["dns_information"]["whois_data"] = {"status": "No data found"}

        except whois.parser.PywhoisError as e_whois_parse: # type: ignore
            logger.error(f"WHOIS parsing error for {self.domain}: {e_whois_parse}")
            self.results["dns_information"]["whois_data"] = {"error": f"WHOIS Parsing Error: {e_whois_parse}"}
        except AttributeError as ae_whois: # Typically from wrong 'whois' lib or unexpected object
            logger.error(f"AttributeError during WHOIS lookup for {self.domain}: {ae_whois}. Ensure 'python-whois' is installed or WHOIS server returned unexpected data.")
            self.results["dns_information"]["whois_data"] = {"error": f"WHOIS Library AttributeError or Data Issue: {ae_whois}. Ensure 'python-whois' is installed."}
        except Exception as e_whois_generic:
            logger.error(f"An unexpected error occurred during WHOIS lookup for {self.domain}: {type(e_whois_generic).__name__} - {e_whois_generic}", exc_info=False)
            self.results["dns_information"]["whois_data"] = {"error": f"Unexpected WHOIS Error: {type(e_whois_generic).__name__}"}

    async def analyze_http_response_details(self):
        logger.info("Analyzing HTTP response details (headers, cookies)...")
        if not self._main_page_response_cache:
            logger.warning("Cannot analyze HTTP response: Main page not fetched.")
            return

        response, _ = self._main_page_response_cache
        headers = response.headers

        sec_headers_analysis = {}
        for header_name, description in self.config["security_headers_info"].items():
            header_value = headers.get(header_name)
            status = "Present" if header_value else "Missing"
            actual_value = headers.getall(header_name) if header_name == "Set-Cookie" else header_value
            sec_headers_analysis[header_name] = {"value": actual_value, "status": status, "description": description}

            if header_value:
                logger.info(f"Security Header Found: {header_name}: {header_value}")
                # Specific checks for present headers
                if header_name == "Strict-Transport-Security":
                    if "preload" not in header_value.lower():
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice", "description": "HSTS header present but 'preload' directive is missing.",
                                     "severity": "Low", "evidence_summary": f"HSTS: {header_value}",
                                     "recommendation": "Consider adding 'preload' to HSTS for better security if site meets preload criteria."},
                                    log_message="HSTS 'preload' missing", severity_for_log="LOW")
                    if "max-age" in header_value.lower():
                        try:
                            max_age_match = re.search(r"max-age=(\d+)", header_value, re.I)
                            if max_age_match: # Check if match was found
                                max_age = int(max_age_match.group(1))
                                if max_age < 31536000: # Less than 1 year
                                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                                {"type": "Security Best Practice",
                                                 "description": f"HSTS 'max-age' is {max_age}, less than the recommended minimum of 1 year (31536000).",
                                                 "severity": "Low", "evidence_summary": f"HSTS: {header_value}"},
                                                log_message=f"HSTS 'max-age' is {max_age} (low)", severity_for_log="LOW")
                        except (AttributeError, ValueError, TypeError): # Catch if regex fails or conversion fails
                            logger.warning(f"Could not parse HSTS max-age from: {header_value}")
                elif header_name == "X-Frame-Options" and header_value.lower() not in ["deny", "sameorigin"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Security Misconfiguration",
                                 "description": f"X-Frame-Options is '{header_value}' which might be too permissive or deprecated (e.g. ALLOW-FROM).",
                                 "severity": "Low", "evidence_summary": f"X-Frame-Options: {header_value}",
                                 "recommendation": "Use 'DENY' or 'SAMEORIGIN', or rely on Content-Security-Policy frame-ancestors."},
                                log_message=f"X-Frame-Options potentially permissive/deprecated: {header_value}", severity_for_log="LOW")
                elif header_name == "Content-Security-Policy":
                    # Improved CSP checks
                    if "unsafe-inline" in header_value.lower() and ("script-src" in header_value.lower() or "default-src" in header_value.lower() and "style-src" not in header_value.lower()): # Avoid flagging unsafe-inline for styles only
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration", "description": "CSP allows 'unsafe-inline' scripts, increasing XSS risk.",
                                     "severity": "Medium", "evidence_summary": "CSP: ...unsafe-inline... in script-src/default-src"},
                                    log_message="CSP allows 'unsafe-inline' scripts", severity_for_log="MEDIUM")
                    if "unsafe-eval" in header_value.lower() and ("script-src" in header_value.lower() or "default-src" in header_value.lower()):
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration", "description": "CSP allows 'unsafe-eval' scripts, increasing XSS risk.",
                                     "severity": "Medium", "evidence_summary": "CSP: ...unsafe-eval... in script-src/default-src"},
                                    log_message="CSP allows 'unsafe-eval' scripts", severity_for_log="MEDIUM")
                    # Check for wildcard source with proper boundaries (e.g., ' ', ';', or end of string)
                    if re.search(r"(\s|;)['\"]\*['\"](\s|;|$)", header_value) or header_value.strip() == "'*'":
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration", "description": "CSP uses wildcard '*' source, which might be overly permissive.",
                                     "severity": "Low", "evidence_summary": "CSP: ...'*'... as a source"},
                                    log_message="CSP uses wildcard '*' source", severity_for_log="LOW")
            else: # Header is missing
                # Determine severity for missing headers
                severity = "Medium" # Default for important headers
                log_sev = "MEDIUM"
                desc_extra = ""
                if header_name == "X-XSS-Protection": # Deprecated
                    severity = "Info"
                    log_sev = "INFO"
                    desc_extra = " This header is deprecated; CSP is preferred."
                elif header_name not in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]:
                    severity = "Low" # For newer/less critical headers if missing
                    log_sev = "LOW"

                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Security Hardening", "description": f"Security header '{header_name}' is missing.{desc_extra}",
                             "severity": severity, "recommendation": f"Consider implementing {header_name} for enhanced security."},
                            log_message=f"Missing security header: {header_name}", severity_for_log=log_sev)
        self.results["http_details"]["security_headers_analysis"] = sec_headers_analysis

        cookies_data = []
        if self.session and self.session.cookie_jar:
            final_url_for_cookies = urlparse(self.results["general_info"]["final_url"])
            for cookie_obj in self.session.cookie_jar:
                # Check if cookie domain matches or is a superdomain of the final URL's domain
                cookie_domain_raw = cookie_obj["domain"]
                cookie_domain = cookie_domain_raw[1:] if cookie_domain_raw.startswith(".") else cookie_domain_raw

                if not final_url_for_cookies.hostname or not final_url_for_cookies.hostname.endswith(cookie_domain): # type: ignore
                    continue

                cookie_info = {
                    "name": cookie_obj.key, "value": cookie_obj.value, "domain": cookie_obj['domain'],
                    "path": cookie_obj['path'], "expires": cookie_obj['expires'], # Already datetime object or None if from Morsel
                    "secure": bool(cookie_obj['secure']), "httponly": bool(cookie_obj['httponly']),
                    "samesite": cookie_obj.get('samesite', None) # Morsel might not have samesite directly
                }
                # Attempt to parse expires if it's a string (e.g., from direct Set-Cookie header parsing if that was used)
                if isinstance(cookie_info["expires"], str):
                    try:
                        # Handle various possible date formats for expires, common one first
                        cookie_info["expires"] = datetime.strptime(cookie_info["expires"], "%a, %d-%b-%Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
                    except ValueError:
                        try: # Another common variant
                            cookie_info["expires"] = datetime.strptime(cookie_info["expires"], "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                        except ValueError:
                             logger.debug(f"Could not parse cookie expiry string: {cookie_info['expires']}")


                cookies_data.append(cookie_info)

                if not cookie_info["httponly"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security", "description": f"Cookie '{cookie_obj.key}' is missing 'HttpOnly' flag.",
                                 "severity": "Medium", "evidence_summary": f"Cookie: {cookie_obj.key} (No HttpOnly)"},
                                log_message=f"Cookie '{cookie_obj.key}' missing HttpOnly", severity_for_log="MEDIUM")
                if not cookie_info["secure"] and self.scheme == "https": # Check scheme of final_url
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security", "description": f"Cookie '{cookie_obj.key}' is missing 'Secure' flag despite site being HTTPS.",
                                 "severity": "Medium", "evidence_summary": f"Cookie: {cookie_obj.key} (No Secure on HTTPS)"},
                                log_message=f"Cookie '{cookie_obj.key}' missing Secure flag on HTTPS", severity_for_log="MEDIUM")
                if cookie_info["samesite"] and cookie_info["samesite"].lower() == "none" and not cookie_info["secure"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security", "description": f"Cookie '{cookie_obj.key}' has 'SameSite=None' but is not 'Secure'. This will be rejected by modern browsers.",
                                 "severity": "Medium", "evidence_summary": f"Cookie: {cookie_obj.key} (SameSite=None without Secure)"},
                                log_message=f"Cookie '{cookie_obj.key}' SameSite=None without Secure", severity_for_log="MEDIUM")
                if not cookie_info["samesite"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security", "description": f"Cookie '{cookie_obj.key}' is missing 'SameSite' attribute. Modern browsers might default to 'Lax'.",
                                 "severity": "Low", "evidence_summary": f"Cookie: {cookie_obj.key} (No SameSite)"},
                                log_message=f"Cookie '{cookie_obj.key}' missing SameSite attribute", severity_for_log="LOW")
        self.results["http_details"]["cookies_set"] = cookies_data
        logger.info(f"HTTP response analysis complete. Found {len(cookies_data)} cookies from session jar for domain {final_url_for_cookies.hostname}.")

    async def fingerprint_technologies(self):
        logger.info("Fingerprinting technologies...")
        if not self._main_page_response_cache or not self._main_page_html_cache:
            logger.warning("Cannot fingerprint technologies: Main page data not available.")
            return

        response, _ = self._main_page_response_cache
        headers = response.headers
        tech_results = self.results["technology_fingerprint"]

        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage(url=str(response.url), html=self._main_page_html_cache, headers=dict(headers))
            tech_detected_by_wappalyzer = wappalyzer.analyze_with_versions_and_categories(webpage)
            wappalyzer_findings_list = []
            for tech_name, tech_data in tech_detected_by_wappalyzer.items():
                version = tech_data.get("versions", [None])[0] if tech_data.get("versions") else None
                categories = [cat['name'] for cat in tech_data.get('categories', [])]
                wappalyzer_findings_list.append({"name": tech_name, "version": version, "categories": categories})
                entry = tech_name + (f" v{version}" if version else "")
                if "CMS" in categories and not tech_results["cms_identified"]:
                    tech_results["cms_identified"] = tech_name
                    if version: tech_results["software_versions_found"][tech_name] = version
                elif any(c in categories for c in ["Web servers", "Reverse proxies"]):
                    if entry not in tech_results["server_software"]: tech_results["server_software"].append(entry)
                elif any(c in categories for c in ["JavaScript frameworks", "UI frameworks", "Web frameworks"]):
                    if entry not in tech_results["frameworks_libraries"]: tech_results["frameworks_libraries"].append(entry)
                elif any(c in categories for c in ["Analytics", "Tag managers", "Marketing automation"]):
                    if entry not in tech_results["analytics_trackers"]: tech_results["analytics_trackers"].append(entry)
                elif "CDN" in categories:
                    if entry not in tech_results["cdn_providers"]: tech_results["cdn_providers"].append(entry)
                elif "Programming languages" in categories:
                    if entry not in tech_results["programming_languages_detected"]: tech_results["programming_languages_detected"].append(entry)
                elif "Operating systems" in categories:
                    if entry not in tech_results["operating_system_guesses"]: tech_results["operating_system_guesses"].append(entry)
                if version and tech_name not in tech_results["software_versions_found"]: # Ensure version is stored
                    tech_results["software_versions_found"][tech_name] = version
            tech_results["wappalyzer_findings"] = wappalyzer_findings_list
            logger.info(f"Wappalyzer detected: {list(tech_detected_by_wappalyzer.keys())}")
        except Exception as e_wapp:
            logger.error(f"Wappalyzer analysis failed: {type(e_wapp).__name__} - {e_wapp}", exc_info=True)
            tech_results["wappalyzer_findings"] = [{"error": f"Wappalyzer failed: {e_wapp}"}]

        server_header = headers.get("Server")
        if server_header:
            normalized_server_header = server_header.strip()
            if normalized_server_header not in tech_results["server_software"]: tech_results["server_software"].append(normalized_server_header)
            logger.info(f"Server header: {normalized_server_header}")
            match = re.search(r"([\w.-]+)(?:[/\s-]([0-9.]+))?", normalized_server_header) # More flexible version parsing
            if match and match.group(1) not in tech_results["software_versions_found"]:
                sw_name = match.group(1)
                sw_version = match.group(2) if len(match.groups()) > 1 and match.group(2) else None
                if sw_version: tech_results["software_versions_found"][sw_name] = sw_version
                elif sw_name not in tech_results["software_versions_found"]: tech_results["software_versions_found"][sw_name] = "Unknown"

        x_powered_by = headers.get("X-Powered-By")
        if x_powered_by:
            normalized_xpb = x_powered_by.strip()
            if normalized_xpb not in tech_results["x_powered_by"]: tech_results["x_powered_by"].append(normalized_xpb)
            logger.info(f"X-Powered-By header: {normalized_xpb}")
            match = re.search(r"([\w.-]+)(?:[/\s-]([0-9.]+))?", normalized_xpb)
            if match and match.group(1) not in tech_results["software_versions_found"]:
                lang_name = match.group(1)
                lang_version = match.group(2) if len(match.groups()) > 1 and match.group(2) else None
                if lang_version: tech_results["software_versions_found"][lang_name] = lang_version
                elif lang_name not in tech_results["software_versions_found"]: tech_results["software_versions_found"][lang_name] = "Unknown"
                if lang_name not in tech_results["programming_languages_detected"]: tech_results["programming_languages_detected"].append(lang_name)

        aspnet_version = headers.get("X-AspNet-Version")
        if aspnet_version:
            entry = f"ASP.NET v{aspnet_version}"
            if entry not in tech_results["frameworks_libraries"]: tech_results["frameworks_libraries"].append(entry)
            if "ASP.NET" not in tech_results["software_versions_found"]: tech_results["software_versions_found"]["ASP.NET"] = aspnet_version
        aspnetmvc_version = headers.get("X-AspNetMvc-Version")
        if aspnetmvc_version:
            entry = f"ASP.NET MVC v{aspnetmvc_version}"
            if entry not in tech_results["frameworks_libraries"]: tech_results["frameworks_libraries"].append(entry)
            if "ASP.NET MVC" not in tech_results["software_versions_found"]: tech_results["software_versions_found"]["ASP.NET MVC"] = aspnetmvc_version

        x_generator = headers.get("X-Generator")
        if x_generator:
            logger.info(f"X-Generator header: {x_generator}")
            if x_generator not in tech_results["frameworks_libraries"] and x_generator not in tech_results["cms_identified"]:
                tech_results["frameworks_libraries"].append(f"Generator: {x_generator}")

        if not tech_results["cms_identified"] and self._main_page_soup_cache:
            for cms_name, checks in self.config["cms_specific_checks"].items():
                for sig in checks.get("signatures_in_html", []):
                    if self._main_page_soup_cache.find(string=re.compile(sig, re.IGNORECASE)) or \
                       self._main_page_soup_cache.find(attrs={"src": re.compile(sig, re.IGNORECASE)}) or \
                       self._main_page_soup_cache.find(attrs={"href": re.compile(sig, re.IGNORECASE)}) or \
                       self._main_page_soup_cache.find(attrs={"class": re.compile(sig, re.IGNORECASE)}) or \
                       self._main_page_soup_cache.find(attrs={"id": re.compile(sig, re.IGNORECASE)}):
                        tech_results["cms_identified"] = cms_name
                        logger.info(f"CMS {cms_name} identified via HTML signature: '{sig}'")
                        break
                if tech_results["cms_identified"]: break

        if tech_results["software_versions_found"]:
            tech_results["software_version_cve_search_links"] = {}
            for sw, ver in tech_results["software_versions_found"].items():
                tech_results["software_version_cve_search_links"][f"{sw} {ver if ver != 'Unknown' else ''}"] = generate_vuln_search_url(sw, ver if ver != 'Unknown' else None)

        logger.info("Technology fingerprinting complete.")

    async def analyze_web_content(self):
        logger.info("Analyzing web content from main page...")
        if not self._main_page_soup_cache:
            logger.warning("Cannot analyze web content: Main page HTML not parsed.")
            return

        soup = self._main_page_soup_cache
        content_results = self.results["content_analysis"]

        title_tag = soup.find("title")
        if title_tag and title_tag.string: content_results["page_title"] = title_tag.string.strip()

        desc_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if desc_tag and desc_tag.get("content"): content_results["meta_description"] = desc_tag["content"].strip()

        keywords_tag = soup.find("meta", attrs={"name": re.compile(r"keywords", re.I)})
        if keywords_tag and keywords_tag.get("content"): content_results["meta_keywords"] = keywords_tag["content"].strip()

        comments = soup.find_all(string=lambda text: isinstance(text, BsComment))
        dev_comments = []
        for comment_node in comments:
            comment_text = comment_node.strip()
            # Filter more common boilerplate comments
            if len(comment_text) > 10 and not comment_text.startswith("<![") and not comment_text.startswith("[if") \
               and not comment_text.lower().startswith("copyright") and "google" not in comment_text.lower() \
               and "msapplication" not in comment_text.lower(): # Added more common filters
                dev_comments.append(comment_text)
        if dev_comments:
            content_results["developer_comments_found"] = dev_comments
            logger.info(f"Found {len(dev_comments)} potentially interesting developer comments.")

        page_text_content = soup.get_text(separator=" ")
        html_content_for_regex = self._main_page_html_cache or ""

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails_found = set(re.findall(email_pattern, html_content_for_regex))
        content_results["emails_on_page"] = sorted(list(emails_found))

        phone_pattern = r"\(?\+?[0-9]{1,4}\)?[\s.-]?[0-9]{2,}[\s.-]?[0-9]{2,}[\s.-]?[0-9]{2,}(?:[\s.-]?[0-9]{2,})?"
        content_results["phone_numbers_on_page"] = sorted(list(set(re.findall(phone_pattern, page_text_content))))

        social_media_domains = ["twitter.com", "facebook.com", "linkedin.com", "instagram.com", "youtube.com",
                                "github.com", "pinterest.com", "reddit.com", "tiktok.com", "t.me", "wa.me", "vk.com", "medium.com"] # Added more
        social_links = set()
        internal_links = set()
        external_links = set()
        doc_extensions = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.odt', '.ods',
                          '.odp', '.rtf', '.xml', '.json', '.md', '.sql', '.log', '.cfg', '.ini', '.yaml', '.yml', '.conf') # Added .conf

        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url_for_join = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if not href or href.startswith("#") or href.lower().startswith("javascript:"): continue

            full_url = urljoin(base_url_for_join, href)
            parsed_link = urlparse(full_url)

            if parsed_link.netloc == final_url_parsed.netloc:
                internal_links.add(full_url)
            else:
                if parsed_link.netloc:
                    external_links.add(full_url)
                    for sm_domain in social_media_domains:
                        if sm_domain in parsed_link.netloc.lower():
                            social_links.add(full_url)
                            break
            path_lower = parsed_link.path.lower()
            if any(path_lower.endswith(ext) for ext in doc_extensions):
                if full_url not in content_results["linked_documents"]:
                    content_results["linked_documents"].append(full_url)

        content_results["internal_links_count"] = len(internal_links)
        content_results["external_links_count"] = len(external_links)
        content_results["social_media_links_on_page"] = sorted(list(social_links))

        content_to_search_keys = html_content_for_regex + "\n".join(dev_comments)
        for key_name, pattern in self.config["api_key_patterns"].items():
            try:
                for match in re.finditer(pattern, content_to_search_keys):
                    matched_value = match.group(0)
                    # Basic entropy check
                    entropy = 0
                    if len(matched_value) > 10:
                        from collections import Counter
                        import math
                        counts = Counter(matched_value)
                        entropy = -sum((count / len(matched_value)) * math.log2(count / len(matched_value)) for count in counts.values())
                    if len(matched_value) > 20 and entropy < 2.5 and key_name not in ["Google OAuth ID", "AWS Secret Access Key (Full)", "Generic JWT"]: # Exclude low entropy but valid patterns
                        logger.debug(f"Skipping low entropy API key match for {key_name}: {matched_value[:20]}... (Entropy: {entropy:.2f})")
                        continue

                    # Avoid matching on common example keys or placeholders
                    if "example" in matched_value.lower() or "placeholder" in matched_value.lower() or "test" in matched_value.lower() or "xxxx" in matched_value.lower():
                        logger.debug(f"Skipping likely placeholder key match for {key_name}: {matched_value[:30]}...")
                        continue

                    context_start = max(0, match.start() - 50)
                    context_end = min(len(content_to_search_keys), match.end() + 50)
                    context_snippet = content_to_search_keys[context_start:context_end].replace("\n", " ")

                    api_key_info = {"key_name": key_name, "matched_value": matched_value, "context_snippet": context_snippet, "entropy": round(entropy, 2) if entropy else "N/A"}

                    # Check for duplicates before adding
                    is_dup_key = any(k.get("matched_value") == matched_value and k.get("key_name") == key_name for k in content_results["suspected_api_keys"])
                    if not is_dup_key:
                        content_results["suspected_api_keys"].append(api_key_info)
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Sensitive Data Exposure", "description": f"Potential API key '{key_name}' found in page source.",
                                     "severity": "Medium", "evidence_summary": f"Key: {matched_value[:20]}...", "details": api_key_info},
                                    log_message=f"Potential API key '{key_name}' found in HTML/comments", severity_for_log="MEDIUM")
            except re.error as ree_api:
                logger.error(f"Regex error for API key pattern '{key_name}': {ree_api}")

        content_results["forms_found_count"] = len(soup.find_all("form"))

        js_links = set()
        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get("src")
            if src: js_links.add(urljoin(base_url_for_join, src))
        content_results["javascript_files"]["count"] = len(js_links)
        content_results["javascript_files"]["files"] = sorted(list(js_links))

        css_links = set()
        for link_tag in soup.find_all("link", rel="stylesheet", href=True):
            href = link_tag.get("href")
            if href: css_links.add(urljoin(base_url_for_join, href))
        content_results["css_files_count"] = len(css_links)

        logger.info("Web content analysis complete.")

    async def fetch_ads_txt_files(self):
        logger.info("Fetching ads.txt and app-ads.txt...")
        ads_txt_url = urljoin(self.results["general_info"]["final_url"], "/ads.txt")
        app_ads_txt_url = urljoin(self.results["general_info"]["final_url"], "/app-ads.txt")

        response_ads, content_ads = await self._make_request(ads_txt_url)
        if response_ads and response_ads.status == 200 and content_ads:
            try:
                self.results["content_analysis"]["ads_txt_content"] = content_ads.decode(response_ads.charset or 'utf-8', errors='replace')
                logger.info(f"ads.txt found and fetched from {ads_txt_url}")
            except Exception as e:
                logger.warning(f"Error decoding ads.txt from {ads_txt_url}: {e}")
                self.results["content_analysis"]["ads_txt_content"] = "Error decoding content."
        else:
            logger.info(f"ads.txt not found or not accessible at {ads_txt_url}.")
            self.results["content_analysis"]["ads_txt_content"] = "Not found or not accessible."

        response_app_ads, content_app_ads = await self._make_request(app_ads_txt_url)
        if response_app_ads and response_app_ads.status == 200 and content_app_ads:
            try:
                self.results["content_analysis"]["app_ads_txt_content"] = content_app_ads.decode(response_app_ads.charset or 'utf-8', errors='replace')
                logger.info(f"app-ads.txt found and fetched from {app_ads_txt_url}")
            except Exception as e:
                logger.warning(f"Error decoding app-ads.txt from {app_ads_txt_url}: {e}")
                self.results["content_analysis"]["app_ads_txt_content"] = "Error decoding content."
        else:
            logger.info(f"app-ads.txt not found or not accessible at {app_ads_txt_url}.")
            self.results["content_analysis"]["app_ads_txt_content"] = "Not found or not accessible."

    async def fetch_and_analyze_robots_txt(self):
        logger.info("Fetching and analyzing robots.txt...")
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        robots_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"
        robots_url = urljoin(robots_base_url, "/robots.txt")

        response, content_bytes = await self._make_request(robots_url)

        if response and response.status == 200 and content_bytes:
            try:
                self._robots_txt_cache = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                self.results["content_analysis"]["robots_txt_content"] = self._robots_txt_cache
                logger.info(f"robots.txt found and fetched from {robots_url}")

                sitemap_pattern = re.compile(r"Sitemap:\s*(.*)", re.IGNORECASE)
                sitemaps_in_robots = sitemap_pattern.findall(self._robots_txt_cache)
                if sitemaps_in_robots:
                    for sm_url_str in sitemaps_in_robots:
                        sm_url_str = sm_url_str.strip()
                        if sm_url_str not in self.results["content_analysis"]["sitemap_urls_found"]: # Avoid duplicates if already found
                            self.results["content_analysis"]["sitemap_urls_found"].append(sm_url_str)
                            await self._sitemap_processing_queue.put(sm_url_str) # Add to queue for processing
                    logger.info(f"Sitemap URLs found in robots.txt and queued: {sitemaps_in_robots}")

                disallowed_paths = []
                allowed_paths = []
                interesting_paths_robots = []
                for line in self._robots_txt_cache.splitlines():
                    line_lower = line.lower().strip()
                    if line_lower.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed_paths.append(path)
                            if len(path) > 1 and path != "/": # Avoid just "/"
                                # Expanded sensitive keywords
                                if any(admin_path_part in path.lower() for admin_path_part in ["admin", "login", "api", "config", "secret", "private", "wp-admin", "administrator", "includes", "cgi-bin", "backup", "logs", "etc", "conf", "settings"]):
                                    interesting_paths_robots.append({"type": "Disallow (Sensitive Keyword)", "path": path, "line": line.strip()})
                    elif line_lower.startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path: allowed_paths.append(path)
                if disallowed_paths: self.results["content_analysis"].setdefault("robots_disallowed_paths", disallowed_paths)
                if allowed_paths: self.results["content_analysis"].setdefault("robots_allowed_paths", allowed_paths)
                if interesting_paths_robots:
                    self.results["content_analysis"].setdefault("robots_interesting_paths", interesting_paths_robots)
                    for item in interesting_paths_robots:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Information Disclosure (Potential)", "description": f"Interesting path '{item['path']}' found in robots.txt ({item['type'].split('(')[0].strip()}).",
                                     "severity": "Low", "evidence_summary": f"robots.txt line: {item['line']}"},
                                    log_message=f"Interesting path in robots.txt: {item['path']}", severity_for_log="LOW")
            except Exception as e_robots:
                logger.error(f"Error processing robots.txt content from {robots_url}: {e_robots}")
                self.results["content_analysis"]["robots_txt_content"] = f"Error parsing: {e_robots}"
        else:
            status_msg = f"Status: {response.status}" if response else "Fetch failed"
            logger.info(f"robots.txt not found or not accessible at {robots_url}. ({status_msg})")
            self.results["content_analysis"]["robots_txt_content"] = "Not found or not accessible."

    async def discover_and_fetch_sitemaps(self):
        logger.info("Discovering sitemaps...")
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        sitemap_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"

        # Initial sitemaps from robots.txt already added to self._sitemap_processing_queue
        # Now add common paths and HTML-linked sitemaps to the queue

        common_sitemap_paths = [
            "/sitemap.xml", "/sitemap_index.xml", "/sitemap.php", "/sitemap.txt",
            "/sitemap.xml.gz", "/post-sitemap.xml", "/page-sitemap.xml", "/category-sitemap.xml",
            "/product-sitemap.xml", "/system/sitemap", "/sitemap-main.xml", "/news-sitemap.xml",
            "/sitemap/", "/sitemap_index.xml" # Common for WordPress with Yoast, already there but harmless
        ]
        for common_path in common_sitemap_paths:
            full_sitemap_url = urljoin(sitemap_base_url, common_path)
            # Check if it's worth queueing (not already processed or identical to one in found list)
            if full_sitemap_url not in self._processed_sitemap_urls and full_sitemap_url not in self.results["content_analysis"]["sitemap_urls_found"]:
                 await self._sitemap_processing_queue.put(full_sitemap_url)

        if self._main_page_soup_cache:
            for link_tag in self._main_page_soup_cache.find_all(['a', 'link'], href=True):
                href = link_tag.get('href', '')
                if 'sitemap' in href.lower() and (href.lower().endswith(('.xml', '.xml.gz', '.txt'))): # Common sitemap extensions
                    linked_sitemap_url = urljoin(sitemap_base_url, href)
                    if linked_sitemap_url not in self._processed_sitemap_urls and linked_sitemap_url not in self.results["content_analysis"]["sitemap_urls_found"]:
                        await self._sitemap_processing_queue.put(linked_sitemap_url)

        # Actual fetching and parsing is now in _process_sitemap_queue_iteratively
        logger.info("Sitemap discovery phase complete. Queued sitemaps will be processed.")

    async def _process_sitemap_url(self, sitemap_url_to_check: str, all_urls_from_sitemaps: set):
        """Helper to process a single sitemap URL. Adds URLs to all_urls_from_sitemaps and new sitemap indexes to queue."""
        if sitemap_url_to_check in self._processed_sitemap_urls:
            return # Already processed
        self._processed_sitemap_urls.add(sitemap_url_to_check)

        logger.debug(f"Processing sitemap: {sitemap_url_to_check}")
        response, content_bytes = await self._make_request(sitemap_url_to_check, timeout=aiohttp.ClientTimeout(total=30)) # Longer timeout for sitemaps

        if response and response.status == 200 and content_bytes:
            # Add to list of successfully fetched sitemap files if not already there
            if sitemap_url_to_check not in self.results["content_analysis"]["sitemap_urls_found"]:
                 self.results["content_analysis"]["sitemap_urls_found"].append(sitemap_url_to_check)
            logger.info(f"Successfully fetched sitemap: {sitemap_url_to_check} (Size: {len(content_bytes)} bytes)")

            sitemap_content_str = ""
            try:
                if sitemap_url_to_check.endswith(".gz"):
                    sitemap_content_str = gzip.decompress(content_bytes).decode(response.charset or 'utf-8', errors='replace')
                else:
                    sitemap_content_str = content_bytes.decode(response.charset or 'utf-8', errors='replace')
            except Exception as e_decode:
                logger.error(f"Error decoding/decompressing sitemap {sitemap_url_to_check}: {e_decode}")
                return # Cannot parse if not decoded

            # Parse XML sitemaps (including sitemap indexes)
            # Check based on extension or if common XML tags are present
            if sitemap_url_to_check.endswith((".xml", ".xml.gz")) or "<urlset" in sitemap_content_str[:200].lower() or "<sitemapindex" in sitemap_content_str[:200].lower():
                try:
                    sitemap_soup = BeautifulSoup(sitemap_content_str, 'xml') # Use 'xml' parser for sitemaps
                    # Check if it's a sitemap index file
                    sitemap_index_locs = sitemap_soup.find_all("sitemap") # <sitemap> tags in an index file
                    if sitemap_index_locs:
                        logger.info(f"Sitemap {sitemap_url_to_check} is an index file. Adding nested sitemaps to queue.")
                        for s_loc_tag in sitemap_index_locs:
                            loc_tag = s_loc_tag.find("loc") # <loc> inside <sitemap>
                            if loc_tag and loc_tag.string:
                                nested_sitemap_url = loc_tag.string.strip()
                                if nested_sitemap_url not in self._processed_sitemap_urls: # Check if already processed
                                    await self._sitemap_processing_queue.put(nested_sitemap_url) # Add to main queue
                        return # This was an index, further processing will handle its children

                    # Regular sitemap with <url> entries
                    url_locs = sitemap_soup.find_all("url") # <url> tags in a regular sitemap
                    for url_entry_tag in url_locs:
                        loc_tag = url_entry_tag.find("loc") # <loc> inside <url>
                        if loc_tag and loc_tag.string:
                            all_urls_from_sitemaps.add(loc_tag.string.strip())
                except Exception as e_sitemap_parse_xml:
                    logger.error(f"Error parsing XML sitemap content from {sitemap_url_to_check}: {e_sitemap_parse_xml}")
            # Parse plain text sitemaps
            elif sitemap_url_to_check.endswith(".txt"):
                for line in sitemap_content_str.splitlines():
                    line = line.strip()
                    if line.startswith("http"): # Basic validation
                        all_urls_from_sitemaps.add(line)
            else:
                logger.info(f"Sitemap {sitemap_url_to_check} is not a recognized XML or .txt format based on extension/content peek. Skipping detailed parsing.")

        elif response and 300 <= response.status < 400: # Handle redirects for sitemaps
            redirected_sitemap_url = response.headers.get("Location")
            if redirected_sitemap_url:
                full_redirect_url = urljoin(sitemap_url_to_check, redirected_sitemap_url)
                logger.info(f"Sitemap {sitemap_url_to_check} redirected to {full_redirect_url}. Adding to queue.")
                if full_redirect_url not in self._processed_sitemap_urls:
                     await self._sitemap_processing_queue.put(full_redirect_url)
        # else: # Sitemap not found or error - already logged by _make_request or debugged here


    async def _process_sitemap_queue_iteratively(self):
        logger.info(f"Starting iterative processing of sitemap queue (Initial size: {self._sitemap_processing_queue.qsize()})...")
        all_urls_from_sitemaps: set[str] = set()

        # Limit iterations to prevent infinite loops with malformed sitemaps or circular references
        max_iterations = 50 # Max depth of sitemap index processing
        iterations = 0

        while not self._sitemap_processing_queue.empty() and iterations < max_iterations:
            sitemap_url = await self._sitemap_processing_queue.get()
            if sitemap_url not in self._processed_sitemap_urls: # Double check, though _process_sitemap_url also checks
                 await self._process_sitemap_url(sitemap_url, all_urls_from_sitemaps)
            self._sitemap_processing_queue.task_done()
            iterations += 1
            if iterations % 10 == 0 and not self._sitemap_processing_queue.empty():
                logger.info(f"Sitemap processing: {iterations} iterations done, queue size: {self._sitemap_processing_queue.qsize()}")

        if iterations >= max_iterations and not self._sitemap_processing_queue.empty():
            logger.warning(f"Sitemap processing reached max iterations ({max_iterations}) with {self._sitemap_processing_queue.qsize()} items still in queue. Possible circular reference or very deep sitemap structure.")

        if all_urls_from_sitemaps:
            self.results["content_analysis"]["sitemap_extracted_url_count"] = len(all_urls_from_sitemaps)
            sample_size = 50
            self.results["content_analysis"]["sitemap_extracted_url_sample"] = sorted(list(all_urls_from_sitemaps))[:sample_size]
            logger.info(f"Extracted {len(all_urls_from_sitemaps)} URLs from sitemaps. Storing a sample of up to {sample_size}.")

        # Ensure sitemap_urls_found is a list of found sitemaps, or a message if none
        if not self.results["content_analysis"]["sitemap_urls_found"]: # If list is still empty
             self.results["content_analysis"]["sitemap_urls_found"] = ["None found or accessible"]
        logger.info("Sitemap processing complete.")

    async def perform_ssl_tls_analysis(self):
        logger.info(f"Performing SSL/TLS analysis for {self.domain}...")
        parsed_final_ssl_url = urlparse(self.results["general_info"]["final_url"])

        if parsed_final_ssl_url.scheme != "https":
            logger.info("Skipping SSL/TLS analysis: Target is not HTTPS or effective URL is not HTTPS.")
            self.results["security_posture"]["ssl_tls_config"] = {"status": "Not HTTPS or effective URL not HTTPS"}
            return

        target_host_for_ssl = parsed_final_ssl_url.hostname
        target_port_for_ssl = parsed_final_ssl_url.port or 443

        if not target_host_for_ssl:
            logger.error("Cannot perform SSL/TLS analysis: No valid hostname determined from final URL.")
            self.results["security_posture"]["ssl_tls_config"] = {"error": "No valid hostname for SSL check"}
            return

        try:
            ssl_context_for_check = ssl.create_default_context() # Uses system CAs
            # For stricter checks, you might enable these, but it can cause failures for many sites:
            # ssl_context_for_check.check_hostname = True # This can be very strict
            # ssl_context_for_check.verify_mode = ssl.CERT_REQUIRED

            logger.debug(f"Attempting SSL connection to {target_host_for_ssl}:{target_port_for_ssl}")
            conn_timeout = self.config["dns_timeout_seconds"] # Reuse DNS timeout for this quick check

            # Use asyncio.open_connection for non-blocking socket connection with SSL context
            # Server_hostname is important for SNI and certificate validation
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=target_host_for_ssl, port=target_port_for_ssl, ssl=ssl_context_for_check, server_hostname=target_host_for_ssl),
                timeout=conn_timeout
            )

            peer_cert = writer.get_extra_info('peercert')
            ssl_object = writer.get_extra_info('ssl_object')

            if not peer_cert or not ssl_object:
                logger.error("Failed to retrieve certificate or SSL object after connection.")
                self.results["security_posture"]["ssl_tls_config"] = {"error": "Failed to retrieve cert/SSL object"}
                writer.close()
                await writer.wait_closed()
                return

            ssl_info = {
                "issuer": dict(x[0] for x in peer_cert.get("issuer", []) if x),
                "subject": dict(x[0] for x in peer_cert.get("subject", []) if x),
                "valid_from": peer_cert.get("notBefore"), "valid_until": peer_cert.get("notAfter"),
                "serial_number": peer_cert.get("serialNumber"), "version": peer_cert.get("version"),
                "subject_alt_names": [name[1] for name in peer_cert.get("subjectAltName", []) if name and len(name) > 1],
                "ocsp_responders": peer_cert.get("OCSP", []), "ca_issuers": peer_cert.get("caIssuers", []),
                "crl_distribution_points": peer_cert.get("crlDistributionPoints", []),
                "cipher_suite": ssl_object.cipher()[0] if ssl_object.cipher() else "Unknown",
                "tls_version": ssl_object.version() if ssl_object.version() else "Unknown",
                "signature_algorithm": peer_cert.get("signatureAlgorithm", "Unknown") # New
            }
            self.results["security_posture"]["ssl_tls_config"] = ssl_info
            logger.info(f"SSL/TLS analysis successful. TLS Version: {ssl_info['tls_version']}, Cipher: {ssl_info['cipher_suite']}")

            if ssl_info["valid_until"]:
                try:
                    expiry_date_str = ssl_info["valid_until"]
                    # Handle potential fractional seconds and ensure GMT for strptime
                    if '.' in expiry_date_str: expiry_date_str = expiry_date_str.split('.')[0] + " GMT"
                    expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z') # type: ignore
                    expiry_date_utc = expiry_date.replace(tzinfo=timezone.utc) # type: ignore
                    now_utc = datetime.now(timezone.utc)
                    days_to_expiry = (expiry_date_utc - now_utc).days
                    ssl_info["days_to_expiry"] = days_to_expiry

                    if expiry_date_utc < now_utc:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue", "description": "SSL/TLS certificate has expired.", "severity": "High", "evidence_summary": f"Expired on: {ssl_info['valid_until']}"},
                                    log_message="SSL certificate EXPIRED", severity_for_log="HIGH")
                    elif days_to_expiry < 14:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue", "description": f"SSL/TLS certificate is expiring soon (in {days_to_expiry} days).", "severity": "Medium", "evidence_summary": f"Expires on: {ssl_info['valid_until']}"},
                                    log_message=f"SSL certificate expiring in {days_to_expiry} days", severity_for_log="MEDIUM")
                    elif days_to_expiry < 30: # Warning for less than 30 days
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue", "description": f"SSL/TLS certificate is expiring in {days_to_expiry} days.", "severity": "Low", "evidence_summary": f"Expires on: {ssl_info['valid_until']}"},
                                    log_message=f"SSL certificate expiring in {days_to_expiry} days", severity_for_log="LOW")
                except ValueError as ve_ssl_date:
                    logger.warning(f"Could not parse SSL certificate expiry date '{ssl_info['valid_until']}': {ve_ssl_date}.")
                except Exception as date_exc_ssl: # Catch any other date processing errors
                    logger.error(f"Error processing SSL certificate expiry date: {date_exc_ssl}")

            cn_from_subject = ssl_info.get("subject", {}).get("commonName", "")
            sans = ssl_info.get("subject_alt_names", [])
            domain_matches_cert = False
            if target_host_for_ssl in sans: domain_matches_cert = True
            elif cn_from_subject:
                if cn_from_subject.startswith("*."):
                    cn_base = cn_from_subject[2:]
                    if target_host_for_ssl.endswith(cn_base) and target_host_for_ssl.count('.') == cn_base.count('.') + 1:
                        domain_matches_cert = True
                elif cn_from_subject == target_host_for_ssl: domain_matches_cert = True
            if not domain_matches_cert:
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "SSL/TLS Issue", "description": "SSL/TLS certificate common name or SANs do not match the target hostname.", "severity": "Medium", "evidence_summary": f"Hostname: {target_host_for_ssl}, CN: {cn_from_subject}, SANs: {sans}"},
                            log_message=f"SSL cert domain mismatch for {target_host_for_ssl}", severity_for_log="MEDIUM")

            weak_sig_algos = ["sha1WithRSAEncryption", "md5WithRSAEncryption", "SHA-1", "md2WithRSAEncryption"] # Added MD2
            if any(weak_algo.lower() in ssl_info.get("signature_algorithm", "").lower() for weak_algo in weak_sig_algos):
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "SSL/TLS Issue", "description": f"SSL/TLS certificate uses a weak signature algorithm: {ssl_info.get('signature_algorithm')}.", "severity": "Medium", "evidence_summary": f"Signature Algorithm: {ssl_info.get('signature_algorithm')}"},
                            log_message=f"Weak SSL cert signature algorithm: {ssl_info.get('signature_algorithm')}", severity_for_log="MEDIUM")

            writer.close()
            await writer.wait_closed()
        except ssl.SSLCertVerificationError as e_ssl_verify:
            # Try to get a more specific error message
            verify_msg = str(e_ssl_verify)
            if "hostname mismatch" in verify_msg.lower():
                verify_msg = "Hostname mismatch"
            elif "self signed certificate" in verify_msg.lower():
                verify_msg = "Self-signed certificate"
            elif "certificate has expired" in verify_msg.lower():
                verify_msg = "Certificate has expired"
            elif "unable to get local issuer certificate" in verify_msg.lower():
                verify_msg = "Unable to get local issuer certificate (chain issue)"
            # Add more common error string checks if needed

            logger.error(f"SSL Certificate Verification Error for {target_host_for_ssl}: {verify_msg}")
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Certificate Verification Failed: {verify_msg}", "details": str(e_ssl_verify)}
            add_finding(self.results["security_posture"], "vulnerability_findings",
                        {"type": "SSL/TLS Issue", "description": f"SSL Certificate Verification Error: {verify_msg}.", "severity": "High", "evidence_summary": str(e_ssl_verify)},
                        log_message=f"SSL cert verification error ({verify_msg}) for {target_host_for_ssl}", severity_for_log="HIGH")
        except (socket.gaierror, ConnectionRefusedError, asyncio.TimeoutError, OSError) as e_ssl_net:
            logger.error(f"Network error during SSL/TLS connection to {target_host_for_ssl}:{target_port_for_ssl}: {type(e_ssl_net).__name__} - {e_ssl_net}")
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Network Error: {type(e_ssl_net).__name__} - {e_ssl_net}"}
        except Exception as e_ssl_generic:
            logger.error(f"Unexpected error during SSL/TLS analysis for {target_host_for_ssl}: {e_ssl_generic}", exc_info=True)
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Unexpected Error: {type(e_ssl_generic).__name__} - {e_ssl_generic}"}

    async def check_http_options_and_auth(self):
        logger.info(f"Checking HTTP OPTIONS and authentication for {self.results['general_info']['final_url']}...")
        response, _ = await self._make_request(self.results["general_info"]["final_url"], method="OPTIONS")
        if response:
            allow_header = response.headers.get("Allow")
            if allow_header:
                allowed_methods = sorted(list(set([method.strip().upper() for method in allow_header.split(',')])))
                self.results["http_details"]["allowed_methods"] = allowed_methods
                logger.info(f"Allowed HTTP methods via OPTIONS: {allowed_methods}")
                risky_methods_enabled = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}.intersection(allowed_methods)
                for risky_method in risky_methods_enabled:
                    severity = "Medium" if risky_method in ['PUT', 'DELETE', 'PATCH'] else "Low"
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Security Misconfiguration", "description": f"Potentially risky HTTP method '{risky_method}' is enabled according to OPTIONS response.",
                                 "severity": severity, "recommendation": f"Review if '{risky_method}' method is necessary for application functionality. Disable if not required."},
                                log_message=f"Risky HTTP method '{risky_method}' enabled (OPTIONS)", severity_for_log=severity.upper())
            else:
                logger.info("No 'Allow' header in OPTIONS response. Methods could not be determined this way.")

            www_auth_header = response.headers.get("WWW-Authenticate")
            if not www_auth_header and self._main_page_response_cache: # Check main page response if not on OPTIONS
                www_auth_header = self._main_page_response_cache[0].headers.get("WWW-Authenticate")
            if www_auth_header:
                auth_type = www_auth_header.split(' ')[0]
                self.results["security_posture"]["http_auth_type"] = auth_type
                logger.info(f"HTTP Authentication detected: {auth_type}")
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Authentication Mechanism", "description": f"HTTP {auth_type} authentication in use.",
                             "severity": "Info", "evidence_summary": f"WWW-Authenticate: {www_auth_header}"},
                            log_message=f"HTTP {auth_type} auth found", severity_for_log="INFO")
        else:
            logger.warning("Failed to get OPTIONS response.")

    async def scan_for_open_ports(self):
        if not self.config.get("enable_nmap_scan", True) or not NMAP_AVAILABLE:
            # Message already logged in run_full_scan or init
            return

        logger.info("Scanning for common open ports using Nmap...")
        if not self.results["general_info"]["ip_addresses"]:
            logger.warning("Skipping port scan: No IP address resolved for the target.")
            return

        target_ip_to_scan = next((ip_info["ip"] for ip_info in self.results["general_info"]["ip_addresses"] if ip_info.get("version") == 4), None)
        if not target_ip_to_scan and self.results["general_info"]["ip_addresses"]:
            target_ip_to_scan = self.results["general_info"]["ip_addresses"][0]["ip"] # Fallback to first IP
        if not target_ip_to_scan:
            logger.error("Could not determine a valid IP for Nmap scan from resolved IPs.")
            return

        ports_to_scan_str = self.config.get('common_ports_to_scan', "80,443")
        logger.info(f"Targeting IP {target_ip_to_scan} for Nmap scan (ports: {ports_to_scan_str}). This may take some time...")

        try:
            nm_scanner = nmap.PortScanner()
            nmap_args = f"-sV -T4 --open -Pn -p {ports_to_scan_str}" # -Pn to skip host discovery (ping)
            scan_results = await asyncio.get_event_loop().run_in_executor(None, nm_scanner.scan, target_ip_to_scan, None, nmap_args)

            if target_ip_to_scan in scan_results.get('scan', {}):
                host_scan_data = scan_results['scan'][target_ip_to_scan]
                if 'tcp' in host_scan_data:
                    for port_num_str, port_data in host_scan_data['tcp'].items():
                        if port_data['state'] == 'open':
                            port_info = {
                                "port": int(port_num_str), "protocol": "tcp", "state": port_data['state'],
                                "service_name": port_data.get('name', 'unknown'), "product": port_data.get('product', ''),
                                "version": port_data.get('version', ''), "extrainfo": port_data.get('extrainfo', ''),
                                "cpe": port_data.get('cpe', '')
                            }
                            self.results["security_posture"]["open_ports"].append(port_info)
                            log_msg = f"Open port: {port_info['port']}/tcp - {port_info['service_name']} {port_info['product']} {port_info['version']}"
                            logger.info(log_msg)
                            if port_info['cpe']:
                                add_finding(self.results["technology_fingerprint"], "software_versions_found_by_nmap",
                                            {"port": port_info['port'], "cpe": port_info['cpe'], "product": port_info['product'], "version": port_info['version']},
                                            log_message=f"Nmap found CPE: {port_info['cpe']} on port {port_info['port']}", severity_for_log="INFO")
                logger.info(f"Nmap scan completed for {target_ip_to_scan}.")
            else:
                logger.warning(f"No Nmap scan results for IP {target_ip_to_scan}. Host might be down, filtering, or Nmap issue.")
                if 'nmap' in scan_results and 'scanstats' in scan_results['nmap']:
                    logger.debug(f"Nmap scan stats: {scan_results['nmap']['scanstats']}")
                    if scan_results['nmap']['scanstats'].get('downhosts') == "1": # Nmap reported host as down
                        logger.warning(f"Nmap reported host {target_ip_to_scan} as down.")
        except nmap.nmap.PortScannerError as e_nmap_exec: # type: ignore
            logger.error(f"Nmap execution error: {e_nmap_exec}. Ensure Nmap executable is installed and in system PATH.")
            self.results["security_posture"]["open_ports"].append({"error": "Nmap executable not found or execution failed."})
        except KeyError as e_nmap_key: # Error parsing Nmap results
            logger.error(f"Error parsing Nmap results (KeyError: {e_nmap_key}). Nmap output structure might have changed.", exc_info=False)
            self.results["security_posture"]["open_ports"].append({"error": f"Nmap result parsing error: {e_nmap_key}"})
        except Exception as e_nmap_generic:
            logger.error(f"An unexpected error occurred during Nmap port scan: {e_nmap_generic}", exc_info=True)
            self.results["security_posture"]["open_ports"].append({"error": f"Unexpected Nmap error: {type(e_nmap_generic).__name__}"})

    async def scan_for_exposed_paths_and_files(self):
        logger.info("Scanning for common exposed sensitive paths and files...")
        if not self.results["general_info"]["final_url"]:
            logger.error("Cannot scan for paths: Final URL not determined.")
            return

        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        path_scan_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"
        paths_to_check_with_categories = []
        for category, path_list in self.config["sensitive_paths_categories"].items():
            if category == "security_txt_paths_list": continue # Handled separately
            for path_item in path_list:
                paths_to_check_with_categories.append({"path": path_item, "category_hint": category})
        logger.debug(f"Will check {len(paths_to_check_with_categories)} common paths/files relative to {path_scan_base_url}")

        async def check_single_path(path_info: dict):
            path_suffix = path_info["path"]
            category_hint = path_info["category_hint"]
            is_likely_file = "." in path_suffix.split('/')[-1] or any(ft in category_hint for ft in ["_files", "_archives", "_exposed"])
            target_check_url = urljoin(path_scan_base_url, path_suffix.lstrip('/'))

            # Use HEAD request first for efficiency, then GET if HEAD fails or is ambiguous
            response, content_bytes = await self._make_request(target_check_url, method="HEAD", allow_redirects=False, max_retries=0)
            if response is None: # HEAD failed completely (network error, timeout)
                response, content_bytes = await self._make_request(target_check_url, method="GET", allow_redirects=False, max_retries=0)
            elif response.status in [405, 501, 403]: # Method Not Allowed, Not Implemented for HEAD, or Forbidden (could be GETtable)
                logger.debug(f"HEAD request to {target_check_url} returned {response.status}. Retrying with GET.")
                response_get, content_bytes_get = await self._make_request(target_check_url, method="GET", allow_redirects=False, max_retries=0)
                if response_get: # If GET succeeds, use its response
                    response = response_get
                    content_bytes = content_bytes_get
                # If GET also fails or returns same 403/405/501, original response is kept.

            if response:
                status = response.status
                content_length = len(content_bytes) if content_bytes is not None else int(response.headers.get("Content-Length", 0))
                finding_details_for_storage = {
                    "path": path_suffix, "url_checked": target_check_url, "status_code": status,
                    "category_hint": category_hint, "content_length": content_length,
                    "content_type": response.headers.get("Content-Type", "N/A")
                }

                if status == 200:
                    self.results["security_posture"]["exposed_sensitive_files"].append(finding_details_for_storage)
                    sev = "High" if category_hint in ["config_files", "backup_archives", "version_control_exposed"] else "Medium"
                    desc = f"Potentially sensitive {'file' if is_likely_file else 'path'} '{path_suffix}' found and accessible (HTTP 200)."

                    if not is_likely_file and "text/html" in finding_details_for_storage["content_type"].lower() and content_bytes:
                        page_text_for_listing = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                        dir_listing_signatures = ['Index of /', '<h1>Index of', '<title>Index of', 'Parent Directory', 'listing directory'] # Added one
                        if any(s.lower() in page_text_for_listing.lower() for s in dir_listing_signatures):
                            if target_check_url not in self.results["security_posture"]["directory_listings_found"]:
                                self.results["security_posture"]["directory_listings_found"].append(target_check_url)
                            desc += " (Directory listing detected)"
                            sev = "Medium"
                            add_finding(self.results["security_posture"], "vulnerability_findings",
                                        {"type": "Information Disclosure", "description": f"Directory listing enabled at: {target_check_url}",
                                         "severity": "Medium", "evidence_summary": f"URL: {target_check_url} (Directory Listing Signatures Found)"},
                                        log_message=f"Directory listing at {target_check_url}", severity_for_log="MEDIUM")
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Information Disclosure", "description": desc, "severity": sev,
                                 "evidence_summary": f"URL: {target_check_url}, Status: {status}, Length: {content_length}",
                                 "details": {"category": category_hint, "content_type": finding_details_for_storage["content_type"]}},
                                log_message=f"Exposed path: {target_check_url} (Status {status})", severity_for_log=sev.upper())
                elif status == 403: # Forbidden
                    if not is_likely_file: # More interesting for directories
                        self.results["security_posture"]["exposed_sensitive_files"].append(finding_details_for_storage)
                        logger.info(f"Path {target_check_url} exists but is Forbidden (403). Could be a directory without listing.")
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Information Disclosure (Potential)",
                                     "description": f"Path '{path_suffix}' exists but is Forbidden (403). May indicate a directory without listing or an unreadable file.",
                                     "severity": "Low", "evidence_summary": f"URL: {target_check_url}, Status: 403"},
                                    log_message=f"Forbidden path (potential dir/file): {target_check_url}", severity_for_log="LOW")
        path_scan_tasks = [check_single_path(p_info) for p_info in paths_to_check_with_categories]
        if path_scan_tasks: await self._execute_task_group(path_scan_tasks, "Sensitive Path Scan")
        logger.info("Scan for common exposed paths and files complete.")

    async def check_for_version_control_exposure(self):
        logger.info("Checking for version control system exposure...")
        vc_paths_from_config = self.config["sensitive_paths_categories"].get("version_control_exposed", [])
        found_artifact_overall = False
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        vc_scan_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"

        for path_suffix in vc_paths_from_config:
            vc_type = "Unknown"
            if ".git" in path_suffix.lower(): vc_type = "Git"
            elif ".svn" in path_suffix.lower(): vc_type = "SVN"
            elif ".hg" in path_suffix.lower(): vc_type = "Mercurial"
            elif ".bzr" in path_suffix.lower(): vc_type = "Bazaar"

            vc_url = urljoin(vc_scan_base_url, path_suffix.lstrip('/'))
            response, content_bytes = await self._make_request(vc_url, allow_redirects=False)

            if response and response.status == 200 and content_bytes:
                logger.warning(f"Potential {vc_type} artifact exposed at: {vc_url} (Status: 200)")
                details_key_base = f"exposed_{vc_type.lower()}"
                if f"{details_key_base}_details" not in self.results["security_posture"]:
                    self.results["security_posture"][f"{details_key_base}_details"] = []

                exposed_artifact_info = {
                    "exposed_path": vc_url, "status": "Accessible (200)",
                    "content_preview": content_bytes[:250].decode(response.charset or 'utf-8', errors='replace'), # Increased preview
                    "content_length": len(content_bytes)
                }
                self.results["security_posture"][f"{details_key_base}_details"].append(exposed_artifact_info)

                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Version Control Exposure", "description": f"Exposed {vc_type} artifact: {path_suffix}",
                             "severity": "High", "evidence_summary": f"URL: {vc_url} is accessible (HTTP 200)."},
                            log_message=f"Exposed {vc_type} artifact: {vc_url}", severity_for_log="HIGH")
                found_artifact_overall = True
                if self.results["technology_fingerprint"]["version_control_type"] is None:
                    self.results["technology_fingerprint"]["version_control_type"] = vc_type

                # Enhanced Git analysis if GitPython is available and .git/config is found
                if vc_type == "Git" and GITPYTHON_AVAILABLE and path_suffix.endswith(".git/config"):
                    try:
                        from io import StringIO
                        config_content_io = StringIO(content_bytes.decode(response.charset or 'utf-8', errors='replace'))
                        git_config = git.GitConfigParser(file_obj=config_content_io, read_only=True) # type: ignore
                        remotes = {}
                        for section in git_config.sections():
                            if section.startswith('remote "') and section.endswith('"'):
                                remote_name = section.split('"')[1]
                                remotes[remote_name] = {
                                    'url': git_config.get(section, 'url', fallback=None),
                                    'fetch': git_config.get(section, 'fetch', fallback=None)
                                }
                        if remotes:
                            exposed_artifact_info["parsed_git_config_remotes"] = remotes # Add to the specific artifact info
                            if 'origin' in remotes and remotes['origin'].get('url'):
                                origin_url = remotes['origin']['url']
                                logger.info(f"Parsed remote 'origin' URL from exposed .git/config: {origin_url}")
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Information Disclosure", "description": f"Git remote repository URL potentially exposed in .git/config: {origin_url}",
                                             "severity": "Medium", "evidence_summary": f"Exposed .git/config at {vc_url} contains remote URL."},
                                            log_message=f"Git remote URL found in exposed .git/config: {origin_url}", severity_for_log="MEDIUM")
                    except Exception as e_git_parse:
                        logger.error(f"Error parsing exposed .git/config with GitPython: {e_git_parse}")
                        exposed_artifact_info["gitpython_analysis_error"] = str(e_git_parse)
                elif vc_type == "Git" and (path_suffix.endswith((".git/config",".git/HEAD", ".git/logs/HEAD"))): # Common sensitive git files
                     exposed_artifact_info["analysis_note"] = "Consider tools like git-dumper for full repo reconstruction if .git/ is listable or key files are exposed."
        if not found_artifact_overall:
            logger.info("No obvious version control artifacts found exposed via common paths.")
        logger.info("Version control system exposure check complete.")

    async def scan_page_for_malware_signatures(self, content: str | None, source_url: str, content_type: str = "HTML"):
        if not content:
            logger.debug(f"Skipping malware signature scan for {source_url}: No content provided.")
            return

        logger.info(f"Scanning content from {source_url} ({content_type}) for malware/suspicious signatures...")
        found_signatures_for_content = []
        signatures_to_check = []
        if content_type.upper() == "HTML" or content_type.upper() == "JAVASCRIPT":
            signatures_to_check.extend(self.config["malware_js_signatures"])
        # PHP signatures are in config but not used here as we don't fetch PHP source code via HTTP.

        for sig_pattern in signatures_to_check:
            try:
                matches = list(re.finditer(sig_pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches:
                    for match in matches:
                        snippet = match.group(0)
                        if len(snippet) > 100: snippet = snippet[:97] + "..."
                        sig_info = {
                            "type": "JavaScript" if content_type.upper() in ["HTML", "JAVASCRIPT"] else content_type,
                            "signature_pattern": sig_pattern, "matched_snippet": snippet, "source_url": source_url
                        }
                        # Avoid duplicate entries for same pattern on same URL
                        is_dup_sig = any(fs.get("signature_pattern") == sig_pattern and fs.get("source_url") == source_url for fs in self.results["security_posture"]["malware_code_signatures"])
                        if not is_dup_sig:
                            self.results["security_posture"]["malware_code_signatures"].append(sig_info)
                            add_finding(self.results["security_posture"], "vulnerability_findings",
                                        {"type": "Suspicious Code", "description": f"Potential malicious/suspicious {sig_info['type']} signature detected in content from {source_url}.",
                                         "severity": "High", "evidence_summary": f"Pattern: {sig_pattern}, Snippet: {snippet}"},
                                        log_message=f"Malware/suspicious signature ({sig_pattern}) in {source_url}", severity_for_log="HIGH")
                        found_signatures_for_content.append(sig_info) # Local list for this content
            except re.error as re_err_malware:
                logger.error(f"Regex error with malware signature '{sig_pattern}' for {source_url}: {re_err_malware}")
        if not found_signatures_for_content:
            logger.info(f"No common malware/suspicious signatures found in content from {source_url}.")

    async def analyze_linked_javascript_files(self):
        if not self.config.get("enable_js_file_analysis", True):
            logger.info("JavaScript file analysis disabled by configuration.")
            return

        logger.info("Analyzing linked JavaScript files for secrets, malware signatures, and interesting patterns...")
        js_files_to_analyze = self.results["content_analysis"]["javascript_files"].get("files", [])
        if not js_files_to_analyze:
            logger.info("No linked JavaScript files found to analyze.")
            return

        max_js_size = self.config.get("js_analysis_max_file_size_kb", 512) * 1024

        async def analyze_single_js(js_url: str):
            if js_url in self._fetched_js_urls: return # Avoid re-processing
            self._fetched_js_urls.add(js_url)

            logger.debug(f"Fetching JS file for analysis: {js_url}")
            js_timeout = aiohttp.ClientTimeout(total=self.config.get("request_timeout_seconds", 20))
            response, content_bytes = await self._make_request(js_url, timeout=js_timeout)

            if response and response.status == 200 and content_bytes:
                if len(content_bytes) > max_js_size:
                    logger.warning(f"JS file {js_url} is too large ({len(content_bytes)} bytes), skipping full analysis. Max size: {max_js_size} bytes.")
                    self.results["content_analysis"]["javascript_files"]["analysis_summary"].append({"url": js_url, "status": "Skipped (Too Large)", "size": len(content_bytes)})
                    return
                try:
                    js_content = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                    self.results["content_analysis"]["javascript_files"]["analysis_summary"].append({"url": js_url, "status": "Analyzed", "size": len(content_bytes)})

                    # 1. Scan for malware signatures in JS content
                    await self.scan_page_for_malware_signatures(js_content, js_url, content_type="JavaScript")

                    # 2. Scan for API keys/secrets in JS content
                    found_keys_in_js = []
                    for key_name, pattern in self.config["api_key_patterns"].items():
                        try:
                            for match in re.finditer(pattern, js_content):
                                matched_value = match.group(0)
                                # Skip example/placeholder keys
                                if "example" in matched_value.lower() or "placeholder" in matched_value.lower() or "test" in matched_value.lower() or "xxxx" in matched_value.lower():
                                    logger.debug(f"Skipping likely placeholder key match for {key_name} in JS {js_url}: {matched_value[:30]}...")
                                    continue

                                context_start = max(0, match.start() - 50)
                                context_end = min(len(js_content), match.end() + 50)
                                context_snippet = js_content[context_start:context_end].replace("\n", " ")
                                api_key_info = {"key_name": key_name, "matched_value": matched_value, "source_js_url": js_url, "context_snippet": context_snippet}

                                # Add to main suspected_api_keys list if not already there from this JS file
                                is_dup_key_js = any(k.get("matched_value") == matched_value and k.get("source_js_url") == js_url for k in self.results["content_analysis"]["suspected_api_keys"])
                                if not is_dup_key_js:
                                    self.results["content_analysis"]["suspected_api_keys"].append(api_key_info)
                                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                                {"type": "Sensitive Data Exposure", "description": f"Potential API key '{key_name}' found in JavaScript file: {js_url}.",
                                                 "severity": "High", "evidence_summary": f"Key: {matched_value[:20]}... in {os.path.basename(js_url)}", "details": api_key_info},
                                                log_message=f"Potential API key '{key_name}' in JS: {js_url}", severity_for_log="HIGH")
                                found_keys_in_js.append(api_key_info)
                        except re.error as ree_js_api:
                            logger.error(f"Regex error for API key pattern '{key_name}' in JS {js_url}: {ree_js_api}")
                    if found_keys_in_js: logger.warning(f"Found {len(found_keys_in_js)} potential API keys/secrets in {js_url}.")

                    # 3. Look for interesting patterns (endpoints, cloud resources, dev comments etc.)
                    interesting_finds_in_js = []
                    for find_type, ep_pattern in self.config.get("js_interesting_patterns", {}).items():
                        try:
                            for match in re.finditer(ep_pattern, js_content, re.IGNORECASE): # Some patterns might be case-sensitive, adjust if needed
                                found_item = match.group(1) if match.groups() else match.group(0)
                                if len(found_item) > 250: found_item = found_item[:247] + "..."
                                find_info = {"type": find_type, "pattern": ep_pattern, "match": found_item, "source_js_url": js_url}
                                # Avoid too many similar findings from the same file/pattern
                                if not any(f.get("match") == found_item and f.get("source_js_url") == js_url and f.get("pattern") == ep_pattern for f in interesting_finds_in_js):
                                    interesting_finds_in_js.append(find_info)
                                    logger.info(f"JSense ({find_type}) in {js_url}: {found_item[:100]}")
                                    # Use find_info for current item
                                    add_finding(self.results["security_posture"], "potential_api_endpoints", # Store these separately or as Info vulns
                                                {"type": f"JS Discovery ({find_type})", "endpoint_or_info": find_info["match"],
                                                 "source_url": find_info["source_js_url"], "pattern_matched": find_info["pattern"], "severity": "Info"}, # Default to Info
                                                log_message=f"JS Discovery ({find_type}) in {find_info['source_js_url']}: {find_info['match'][:60]}...", severity_for_log="INFO")
                        except re.error as ree_js_ep:
                            logger.error(f"Regex error for JS interesting pattern '{find_type}' in {js_url}: {ree_js_ep}")
                    if interesting_finds_in_js:
                        # Find the correct analysis_summary entry to update (the one just added)
                        for summary_item in reversed(self.results["content_analysis"]["javascript_files"]["analysis_summary"]):
                            if summary_item.get("url") == js_url and summary_item.get("status") == "Analyzed":
                                summary_item["interesting_finds"] = interesting_finds_in_js
                                break
                except UnicodeDecodeError:
                    logger.warning(f"Could not decode JS file {js_url} (tried {response.charset or 'utf-8'} and latin-1).")
                    self.results["content_analysis"]["javascript_files"]["analysis_summary"].append({"url": js_url, "status": "Decoding Error", "size": len(content_bytes)})
                except Exception as e_js_analyze:
                    logger.error(f"Error analyzing JS file {js_url}: {e_js_analyze}")
                    self.results["content_analysis"]["javascript_files"]["analysis_summary"].append({"url": js_url, "status": f"Analysis Error: {type(e_js_analyze).__name__}", "size": len(content_bytes)})
            else:
                status_code = response.status if response else "N/A"
                logger.warning(f"Could not fetch JS file {js_url} for analysis (Status: {status_code}).")
                self.results["content_analysis"]["javascript_files"]["analysis_summary"].append({"url": js_url, "status": f"Fetch Failed (Status: {status_code})"})
        js_analysis_tasks = [analyze_single_js(js_url) for js_url in js_files_to_analyze]
        if js_analysis_tasks: await self._execute_task_group(js_analysis_tasks, "JavaScript File Analysis")
        logger.info("JavaScript file analysis complete.")

    async def conduct_basic_vulnerability_checks(self):
        logger.info("Conducting basic automated vulnerability checks...")
        sec_posture = self.results["security_posture"]

        if self.results["technology_fingerprint"]["software_versions_found"]:
            for software, version in self.results["technology_fingerprint"]["software_versions_found"].items():
                if version == "Unknown" or not version: continue
                search_urls = generate_vuln_search_url(software, version)
                log_message = f"Software '{software}' version '{version}' detected. Check for CVEs (see details)."
                add_finding(sec_posture, "vulnerability_findings",
                            {"type": "Outdated Software (Manual Check Recommended)", "description": log_message, "severity": "Info", "evidence_summary": f"{software}: {version}",
                             "recommendation": f"Verify if {software} {version} has known vulnerabilities using the provided search links and update if necessary.", "details": {"search_links": search_urls}},
                            log_message=f"Software '{software} v{version}' detected. Recommend CVE check.", severity_for_log="INFO")

        if self._main_page_html_cache:
            debug_patterns = [
                r"(?i)debug\s*=\s*(true|1)", r"(?i)display_errors\s*=\s*on", r"(?i)xdebug_error", r"Traceback \(most recent call last\)",
                r"<b>Warning</b>\s*:", r"<b>Notice</b>\s*:", r"<b>Parse error</b>\s*:", r"<b>Fatal error</b>\s*:", r"PHP Stack trace:",
                r"Microsoft .NET Framework Version:", r"<!--\s*EnableExceptionHandling\s*=\s*false\s*-->", r"Stack Trace:", r"error reporting",
                r"Exception Details:", r"detailed error messages", r"Application Error", r" diagnostics" # Added some
            ]
            html_content_lower = self._main_page_html_cache.lower()
            for pattern_str in debug_patterns:
                try:
                    if re.search(pattern_str, html_content_lower):
                        add_finding(sec_posture, "vulnerability_findings",
                                    {"type": "Information Disclosure", "description": "Potential debug mode or verbose error display indicators found in page source.",
                                     "severity": "Medium", "evidence_summary": f"Matched debug-related pattern: '{pattern_str}' in HTML."},
                                    log_message="Potential debug mode indicators in HTML source.", severity_for_log="MEDIUM")
                        break # Found one, no need to check others for this category on main page
                except re.error as re_err_debug:
                    logger.error(f"Regex error with debug pattern '{pattern_str}': {re_err_debug}")

        if self.scheme == "https" and self._main_page_soup_cache:
            mixed_content_links = []
            tags_to_check_mixed_content = {'img': 'src', 'script': 'src', 'link': 'href', 'iframe': 'src', 'audio': 'src', 'video': 'src', 'source': 'src', 'object': 'data', 'embed': 'src', 'form': 'action'}
            for tag_name, attr_name in tags_to_check_mixed_content.items():
                for tag_instance in self._main_page_soup_cache.find_all(tag_name, **{attr_name: True}):
                    resource_url_attr_val = tag_instance.get(attr_name)
                    if isinstance(resource_url_attr_val, str) and resource_url_attr_val.startswith("http://"):
                        mixed_content_links.append({"tag": tag_name, "resource_url": resource_url_attr_val})
            if mixed_content_links:
                unique_mixed_urls = sorted(list(set(mcl["resource_url"] for mcl in mixed_content_links)))
                add_finding(sec_posture, "vulnerability_findings",
                            {"type": "Security Misconfiguration", "description": "Mixed Content: HTTP resources loaded on HTTPS page.", "severity": "Medium",
                             "evidence_summary": f"Found {len(unique_mixed_urls)} unique HTTP resources. Example: {unique_mixed_urls[0]}", "details": {"mixed_content_resources": mixed_content_links[:10]}}, # Sample of 10
                            log_message=f"Mixed content found: {len(unique_mixed_urls)} HTTP resources.", severity_for_log="MEDIUM")

        if self._main_page_response_cache:
            headers = self._main_page_response_cache[0].headers
            proxy_headers = ["X-Forwarded-For", "X-Real-IP", "Forwarded", "Via", "X-Forwarded-Host", "X-Client-IP"] # Added more
            found_proxy_headers = [h for h in proxy_headers if h in headers]
            if found_proxy_headers:
                add_finding(sec_posture, "vulnerability_findings",
                            {"type": "Information Disclosure (Potential)", "description": f"Proxy-related headers detected: {', '.join(found_proxy_headers)}. Ensure they are handled securely if used for trust decisions.",
                             "severity": "Info", "evidence_summary": f"Headers: {', '.join(found_proxy_headers)} present."},
                            log_message=f"Proxy headers found: {', '.join(found_proxy_headers)}", severity_for_log="INFO")

        final_url_parsed_for_redirect = urlparse(self.results["general_info"]["final_url"])
        if final_url_parsed_for_redirect.query:
            try: # Guard against malformed query strings
                query_params = dict(qc.split("=", 1) for qc in final_url_parsed_for_redirect.query.split("&") if "=" in qc) # Use split("=", 1) to handle empty values
                redirect_params = ["redirect", "url", "next", "goto", "return", "continue", "dest", "target", "rurl", "callback"] # Added more
                for rp in redirect_params:
                    if rp in query_params and (query_params[rp].startswith("http:") or query_params[rp].startswith("https://") or query_params[rp].startswith("/") or query_params[rp].startswith(".")):
                        # A more advanced check would involve testing if the domain in query_params[rp] is different from target domain
                        target_domain_in_param = urlparse(query_params[rp]).netloc
                        if target_domain_in_param and target_domain_in_param != self.domain and not target_domain_in_param.endswith("." + self.domain): # Check if external domain
                             add_finding(sec_posture, "vulnerability_findings",
                                        {"type": "Open Redirect (Potential - Parameter Found)",
                                        "description": f"A common redirect parameter ('{rp}') with an external URL value ('{query_params[rp]}') was found in the final URL: {self.results['general_info']['final_url']}. Manual testing required.",
                                        "severity": "Low", "evidence_summary": f"Parameter '{rp}={query_params[rp]}' in final URL. Requires manual verification."},
                                        log_message=f"Potential open redirect parameter '{rp}' to external domain in final URL.", severity_for_log="LOW")
                             break # Found one, no need to report more for this simple check.
            except ValueError as e_query_parse: # Catch if qc.split('=') fails on malformed query
                logger.warning(f"Could not parse query string for open redirect check: {final_url_parsed_for_redirect.query} - Error: {e_query_parse}")


        logger.info("Basic automated vulnerability checks complete.")

    async def fetch_and_analyze_security_txt(self):
        logger.info("Fetching and analyzing security.txt...")
        found_security_txt_info = None
        security_txt_paths = self.config["sensitive_paths_categories"].get("security_txt_paths_list", [])
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        security_txt_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"

        for path in security_txt_paths:
            sec_txt_url = urljoin(security_txt_base_url, path.lstrip('/'))
            response, content_bytes = await self._make_request(sec_txt_url)
            if response and response.status == 200 and content_bytes:
                try:
                    sec_txt_content = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                    parsed_fields = {}
                    required_fields_rfc9116 = ["contact", "expires"]
                    is_valid_rfc9116_syntax = True
                    field_issues = []

                    for line_num, line_content in enumerate(sec_txt_content.splitlines()):
                        line_str = line_content.strip()
                        if line_str.startswith("#") or not line_str: continue
                        if ":" not in line_str:
                            logger.warning(f"Malformed line in security.txt at {sec_txt_url} (line {line_num + 1}): '{line_str}' (Missing colon).")
                            is_valid_rfc9116_syntax = False; field_issues.append(f"Line {line_num + 1}: Malformed (no colon separator)"); continue
                        key, value = line_str.split(":", 1)
                        key = key.strip().lower(); value = value.strip()
                        if not key: # Key cannot be empty
                            logger.warning(f"Malformed line in security.txt at {sec_txt_url} (line {line_num + 1}): '{line_str}' (Empty key).")
                            is_valid_rfc9116_syntax = False; field_issues.append(f"Line {line_num + 1}: Empty key"); continue
                        if key in parsed_fields: # Duplicate field
                            if not isinstance(parsed_fields[key], list): parsed_fields[key] = [parsed_fields[key]]
                            parsed_fields[key].append(value)
                        else: parsed_fields[key] = value

                    expires_val = parsed_fields.get("expires")
                    if expires_val and isinstance(expires_val, str): # Only check if string (not list from duplicates)
                        try:
                            # RFC 9116: YYYY-MM-DDThh:mm:ssZ (or with offset)
                            # datetime.fromisoformat handles this well.
                            # Attempt to make it more compliant if common mistakes are made
                            expires_val_iso = expires_val
                            if ' ' in expires_val and 'T' not in expires_val: # Replace space with T if used as date/time sep
                                expires_val_iso = expires_val.replace(' ', 'T', 1)

                            # If no TZ info, append Z for UTC assumption for fromisoformat.
                            if not expires_val_iso.endswith("Z") and '+' not in expires_val_iso and '-' not in expires_val_iso[10:]:
                                if 'T' in expires_val_iso and len(expires_val_iso.split('T')[1]) == 8: # HH:MM:SS without Z
                                     expires_val_iso += "Z"

                            expiry_dt = datetime.fromisoformat(expires_val_iso)
                            if expiry_dt.tzinfo is None: # If still no timezone after attempted fixes, assume UTC
                                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)

                            if expiry_dt < datetime.now(timezone.utc):
                                field_issues.append(f"Expires field value ('{expires_val}') is in the past.")
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Security Policy", "description": "security.txt 'Expires' field indicates the policy is outdated/expired.",
                                             "severity": "Low", "evidence_summary": f"Expires: {expires_val}"},
                                            log_message="security.txt is expired.", severity_for_log="LOW")
                        except ValueError:
                            logger.warning(f"Invalid 'Expires' format in security.txt: {expires_val}. Expected ISO 8601 (e.g., YYYY-MM-DDTHH:MM:SSZ).")
                            is_valid_rfc9116_syntax = False; field_issues.append(f"Expires field ('{expires_val}') has invalid format.")
                    elif not expires_val: # Missing expires
                        is_valid_rfc9116_syntax = False; field_issues.append("Required field 'Expires' is missing.")

                    missing_required = [rf for rf in required_fields_rfc9116 if rf not in parsed_fields]
                    if missing_required:
                        is_valid_rfc9116_syntax = False
                        for mr_field in missing_required: field_issues.append(f"Required field '{mr_field}' is missing.")
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Policy", "description": f"security.txt missing required fields: {', '.join(missing_required)}.",
                                     "severity": "Low", "evidence_summary": f"URL: {sec_txt_url}, Missing: {', '.join(missing_required)}"},
                                    log_message=f"security.txt missing required: {', '.join(missing_required)}", severity_for_log="LOW")

                    found_security_txt_info = {"url": sec_txt_url, "content": sec_txt_content, "parsed_fields": parsed_fields, "rfc9116_compliant_syntax_basic": is_valid_rfc9116_syntax, "syntax_issues": field_issues if field_issues else "None found"}
                    logger.info(f"Found security.txt at: {sec_txt_url}. Basic RFC9116 syntax compliance: {is_valid_rfc9116_syntax}")
                    break # Found one, stop checking other paths
                except Exception as e_sectxt_parse:
                    logger.error(f"Error parsing security.txt content from {sec_txt_url}: {e_sectxt_parse}")
                    found_security_txt_info = {"url": sec_txt_url, "error": f"Parsing failed: {e_sectxt_parse}"}
                    break # Stop on error
        self.results["security_posture"]["security_txt_contents"] = found_security_txt_info if found_security_txt_info else "Not found"
        if not found_security_txt_info: logger.info("security.txt not found at common locations.")

    async def enumerate_and_verify_subdomains(self):
        logger.info(f"Starting subdomain enumeration for {self.domain}...")
        discovered_subs_info_map = {} # Use a map to store unique subdomains with their best status

        async def check_sub(sub_prefix: str, source: str):
            subdomain_to_test = f"{sub_prefix}.{self.domain}".lower()
            if not sub_prefix or subdomain_to_test == self.domain : return # Skip empty or base domain itself

            # Basic wildcard DNS mitigation for bruteforce
            # A more advanced check would compare response content/size of a non-existent random sub with the tested sub.
            if self.results["dns_information"].get("wildcard_dns_detected") and source == "Bruteforce":
                 # Could potentially add a check here to see if the IP resolved matches a known wildcard IP,
                 # or if the response is identical to a known "wildcard response".
                 # For now, this just logs a warning when wildcard is detected.
                 # The main effect is that more subdomains might appear "active".
                 pass


            schemes_to_try = ["https", "http"]
            best_status_for_sub = None; best_url_for_sub = None

            for s_scheme in schemes_to_try:
                test_url = f"{s_scheme}://{subdomain_to_test}"
                try:
                    # Use HEAD first for speed, timeout quickly
                    response_head, _ = await self._make_request(test_url, method="HEAD", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=7), max_retries=0) # Slightly increased timeout

                    current_status = None; current_url = test_url
                    if response_head and response_head.status < 400: # 2xx or 3xx from HEAD
                        current_status = response_head.status; current_url = str(response_head.url)
                    elif not response_head or response_head.status in [405, 501, 403] or response_head.status >= 500: # HEAD failed or not allowed/forbidden/server_error
                        # Retry with GET if HEAD failed or was uninformative
                        response_get, _ = await self._make_request(test_url, method="GET", allow_redirects=True, timeout=aiohttp.ClientTimeout(total=12), max_retries=0) # Slightly increased GET timeout
                        if response_get and response_get.status < 400:
                            current_status = response_get.status; current_url = str(response_get.url)

                    if current_status:
                        logger.info(f"Subdomain confirmed: {test_url} -> {current_url} (Status: {current_status}, Source: {source})")
                        # Update if this is a better status (e.g., HTTPS preferred over HTTP, or 200 over 3xx)
                        if subdomain_to_test not in discovered_subs_info_map or \
                           (s_scheme == "https" and urlparse(discovered_subs_info_map[subdomain_to_test]["url"]).scheme == "http") or \
                           (current_status == 200 and discovered_subs_info_map[subdomain_to_test]["status"] != 200):
                            discovered_subs_info_map[subdomain_to_test] = {"subdomain": subdomain_to_test, "status": current_status, "url": current_url, "source": source}
                        return # Found a working scheme, no need to check others for this sub
                except (asyncio.TimeoutError, aiohttp.ClientError) as e_net:
                    logger.debug(f"Network error checking subdomain {test_url}: {type(e_net).__name__}")
                except Exception as e_sub_check: # Catch all other exceptions during sub check
                    logger.debug(f"Other error checking subdomain {test_url}: {type(e_sub_check).__name__} - {e_sub_check}")


        subdomain_bruteforce_tasks = []
        if self.config.get("enable_subdomain_bruteforce", True) and self.config.get("common_subdomains"):
            logger.info(f"Starting subdomain bruteforce with {len(self.config['common_subdomains'])} common names...")
            for sub_prefix in set(self.config["common_subdomains"]): # Use set to avoid duplicates in list
                if sub_prefix: subdomain_bruteforce_tasks.append(check_sub(sub_prefix, "Bruteforce"))
        if subdomain_bruteforce_tasks: await self._execute_task_group(subdomain_bruteforce_tasks, "Subdomain Bruteforce")

        crtsh_subdomains = set()
        if self.config.get("enable_crtsh_subdomain_search", True) and REQUESTS_AVAILABLE:
            logger.info(f"Querying crt.sh for subdomains of {self.domain}...")
            try:
                crtsh_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response_crtsh = await asyncio.get_event_loop().run_in_executor(None, lambda: requests.get(crtsh_url, timeout=self.config.get("crtsh_timeout_seconds", 15)))
                response_crtsh.raise_for_status()
                crtsh_data = response_crtsh.json()
                for entry in crtsh_data:
                    name_value = entry.get("name_value", "")
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name.endswith(f".{self.domain}") and not name.startswith("*.") and name != self.domain: # Exclude base domain
                                sub_prefix = name[:-len(f".{self.domain}") - 1]
                                if sub_prefix: crtsh_subdomains.add(sub_prefix)
                logger.info(f"Found {len(crtsh_subdomains)} unique potential subdomains from crt.sh.")
            except requests.exceptions.RequestException as e_crtsh_req: logger.error(f"crt.sh request failed: {e_crtsh_req}")
            except json.JSONDecodeError as e_crtsh_json: logger.error(f"Failed to decode JSON response from crt.sh: {e_crtsh_json}")
            except Exception as e_crtsh_generic: logger.error(f"An unexpected error occurred during crt.sh lookup: {e_crtsh_generic}")

            if crtsh_subdomains:
                logger.info(f"Verifying {len(crtsh_subdomains)} subdomains found via crt.sh...")
                crtsh_verification_tasks = [check_sub(sub_prefix, "crt.sh") for sub_prefix in crtsh_subdomains if sub_prefix]
                if crtsh_verification_tasks: await self._execute_task_group(crtsh_verification_tasks, "crt.sh Subdomain Verification")

        self.results["subdomain_discovery"]["discovered_subdomains"] = sorted(list(discovered_subs_info_map.values()), key=lambda x: x["subdomain"])
        logger.info(f"Subdomain enumeration complete. Found {len(self.results['subdomain_discovery']['discovered_subdomains'])} active subdomains.")

    async def fetch_wayback_urls(self):
        if not self.config.get("enable_wayback_machine_scan", True) or not REQUESTS_AVAILABLE:
            return
        logger.info(f"Fetching archived URLs for *.{self.domain} from Wayback Machine...")
        try:
            wayback_cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit={self.config.get('wayback_machine_limit', 20)}"
            response_wayback = await asyncio.get_event_loop().run_in_executor(None, lambda: requests.get(wayback_cdx_url, timeout=25)) # Increased timeout
            response_wayback.raise_for_status()
            archived_urls_data = response_wayback.json()
            if archived_urls_data and isinstance(archived_urls_data, list):
                if archived_urls_data[0] == ["original"]: archived_urls_data = archived_urls_data[1:] # Skip header
                fetched_urls = [item[0] for item in archived_urls_data if item] # item[0] is the original URL
                self.results["content_analysis"]["archived_urls"] = fetched_urls
                logger.info(f"Found {len(fetched_urls)} unique archived URLs from Wayback Machine for *.{self.domain}.")
                for url in fetched_urls[:5]: logger.debug(f"Archived URL example: {url}")

                # Add a finding if interesting files/paths are seen in wayback results
                interesting_extensions = ['.bak', '.sql', '.zip', '.tar.gz', '.config', '.env', '.log', '.yml', '.yaml', '.mdb', '.ini', '.conf', '.pem', '.key']
                interesting_keywords_in_path = ['admin', 'backup', 'config', 'secret', 'dump', 'debug', 'setup', 'install', 'private', 'credentials', 'api_key', 'token', 'password', 'pwd']
                for url_str in fetched_urls:
                    parsed_url = urlparse(url_str)
                    path_lower = parsed_url.path.lower()
                    query_lower = parsed_url.query.lower() # Check query params too
                    if any(path_lower.endswith(ext) for ext in interesting_extensions) or \
                       any(keyword in path_lower for keyword in interesting_keywords_in_path) or \
                       any(keyword in query_lower for keyword in interesting_keywords_in_path): # Check query params
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Information Disclosure (Historical)", "description": f"Potentially sensitive URL '{url_str}' found in Wayback Machine archive.",
                                     "severity": "Low", "evidence_summary": f"Archived URL: {url_str}"},
                                    log_message=f"Interesting archived URL: {url_str}", severity_for_log="LOW")
            else: logger.info(f"No archived URLs found or unexpected format from Wayback Machine for *.{self.domain}.")
        except requests.exceptions.RequestException as e_wayback_req: logger.error(f"Wayback Machine request failed: {e_wayback_req}")
        except json.JSONDecodeError as e_wayback_json: logger.error(f"Failed to decode JSON response from Wayback Machine: {e_wayback_json}")
        except Exception as e_wayback_generic: logger.error(f"An unexpected error occurred during Wayback Machine lookup: {e_wayback_generic}")

    async def discover_api_endpoints(self):
        logger.info("Discovering potential API endpoints...")
        sec_posture_api = self.results["security_posture"].setdefault("potential_api_endpoints", [])
        # Expanded common API paths
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
            "/swagger.json", "/openapi.json", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
            "/swagger/v1/swagger.json", "/api-docs", "/swagger-resources", "/apis", "/_api" # Added some more
        ]
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        api_scan_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"

        async def check_api_path(path):
            api_url = urljoin(api_scan_base_url, path.lstrip('/'))
            response, content_bytes = await self._make_request(api_url, method="GET", allow_redirects=True) # Allow redirects for API docs
            if response and response.status == 200 and content_bytes:
                is_doc_file = any(doc_file in path.lower() for doc_file in ["swagger.json", "openapi.json", "api-docs"])
                content_type = response.headers.get("Content-Type", "").lower()
                api_endpoint_info: dict[str, any] = {"url": api_url, "status": response.status, "type": "Unknown", "discovered_paths": []}
                log_msg_sev = "INFO"

                if is_doc_file or "application/json" in content_type or "application/openapi+json" in content_type or "application/swagger+json" in content_type:
                    api_endpoint_info["type"] = "API Documentation/Specification"
                    log_msg_sev = "MEDIUM" # Higher importance for spec files
                    logger.warning(f"Found potential API documentation/specification: {api_url}")
                    if content_bytes and ("json" in content_type or is_doc_file):
                        try:
                            api_doc_json = json.loads(content_bytes.decode(response.charset or 'utf-8', errors='replace'))
                            doc_title = api_doc_json.get("info", {}).get("title", "N/A")
                            doc_version = api_doc_json.get("info", {}).get("version", "N/A")
                            paths_data = api_doc_json.get("paths", {})
                            paths_count = len(paths_data)
                            api_endpoint_info["details"] = f"Title: {doc_title}, Version: {doc_version}, Paths defined: {paths_count}"
                            if paths_count > 0:
                                logger.info(f"Parsed API spec from {api_url}: {paths_count} paths defined.")
                                for api_path_key in paths_data.keys(): # Store defined paths
                                    api_endpoint_info["discovered_paths"].append(api_path_key)
                        except json.JSONDecodeError: api_endpoint_info["details"] = "Content is JSON-like but failed to parse as API spec."
                        except Exception as e_parse_api_doc: api_endpoint_info["details"] = f"Error parsing API spec: {e_parse_api_doc}"
                elif "text/html" in content_type and ("swagger-ui" in path.lower() or (content_bytes and b"swagger-ui" in content_bytes.lower())):
                    api_endpoint_info["type"] = "Swagger UI"
                    log_msg_sev = "MEDIUM"; logger.warning(f"Found Swagger UI page: {api_url}")
                elif path == "/graphql" and content_bytes and (b"errors" in content_bytes.lower() and b"locations" in content_bytes.lower() or b"data" in content_bytes.lower()): # GraphQL specific response
                    api_endpoint_info["type"] = "GraphQL Endpoint (Responded)"
                    log_msg_sev = "MEDIUM"; logger.warning(f"GraphQL endpoint at {api_url} seems active.")
                else:
                    api_endpoint_info["type"] = "Path Responded (Generic)"; logger.info(f"Path {api_url} responded with 200.")

                # Add to results if not duplicate URL
                if not any(item.get("url") == api_url for item in sec_posture_api):
                    sec_posture_api.append(api_endpoint_info)
                    add_finding(self.results["security_posture"], "vulnerability_findings", # Also add to main vuln list
                                {"type": "API Endpoint Exposed", "description": f"{api_endpoint_info['type']} found at {api_url}.",
                                 "severity": log_msg_sev, "evidence_summary": f"URL: {api_url} (HTTP 200)", "details": api_endpoint_info.get("details", "N/A"), "paths_in_spec": api_endpoint_info.get("discovered_paths")},
                                log_message=f"{api_endpoint_info['type']} at {api_url}", severity_for_log=log_msg_sev)
        api_path_tasks = [check_api_path(p) for p in common_api_paths]
        await self._execute_task_group(api_path_tasks, "Common API Path Scan")
        logger.info("API endpoint discovery phase complete.")

    async def analyze_common_error_pages(self):
        if not self.config.get("enable_error_page_analysis", True):
            logger.info("Error page analysis disabled.")
            return
        logger.info("Analyzing common error pages for technology leakage...")
        error_page_results = self.results["technology_fingerprint"].setdefault("error_page_fingerprints", [])
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        error_page_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"
        non_existent_path = f"/KAIROSTest_{int(datetime.now().timestamp())}_{os.urandom(4).hex()}.html" # Unique path
        error_test_url = urljoin(error_page_base_url, non_existent_path)
        response, content_bytes = await self._make_request(error_test_url, allow_redirects=False)

        if response and content_bytes:
            status = response.status
            try: error_page_html = content_bytes.decode(response.charset or 'utf-8', errors='replace')
            except Exception: error_page_html = "" # Cant analyze if cant decode

            error_signatures = {
                "Apache": [r"Apache.*Server at", r"<address>Apache/</address>", r"mod_wsgi", r"mod_perl", r"mod_ssl"],
                "IIS": [r"Microsoft-IIS", r"ASP.NET is configured to show verbose error messages", r"HTTP Error \d{3}\.\d+ - Not Found", r"detailedError"], # Updated IIS
                "Nginx": [r"nginx</center>", r"<h1>\d{3} Not Found</h1>\s*<hr>\s*<center>nginx"], # Updated Nginx
                "LiteSpeed": [r"LiteSpeed Web Server", r"Proudly Served by LiteSpeed Web Server"],
                "Cloudflare": [r"Attention Required! \| Cloudflare", r"error code: 10\d{2}", r"cf-ray", r"Cloudflare Ray ID:"], # Added more CF
                "Akamai": [r"AkamaiGHost", r"Access Denied.*Akamai", r"You don't have permission to access .* on this server\.\s*<p>Reference #"], # Added Akamai ref
                "AWS (S3/CloudFront)": [r"<Error><Code>NoSuchKey</Code>", r"Generated by cloudfront", r"X-Cache: Error from cloudfront", r"x-amz-error"], # Added x-amz-error
                "Google Cloud": [r"Error: Not Found\s*The requested URL /[^\s]+ was not found on this server.", r"Google Frontend", r"This site can’t be reached"], # Common GFE / browser error
                "Tomcat": [r"Apache Tomcat", r"HTTP Status \d{3} – (Not Found|Error)", r"JBOSS", r"Apache Coyote"], # Added Coyote
                "Jetty": [r"Powered by Jetty", r"org\.eclipse\.jetty"],
                "Oracle Application Server": [r"Oracle Application Server", r"Oracle HTTP Server", r"Oracle-Application-Server"], # Added header
                "Resin": [r"Resin Home Page", r"Caucho Technology"],
                "OpenResty": [r"openresty</center>"],
                "Spring Boot": [r"Whitelabel Error Page", r"\"timestamp\":", r"\"status\": \d{3},", r"\"error\":", r"\"message\":"],
                "Ruby on Rails": [r"Ruby on Rails", r"Action Controller: Exception caught", r"Application Trace", r"Framework Trace"],
                "Django": [r"Page not found \(404\)", r"Request Method:", r"Django Version:", r"Exception Type:", r"You're seeing this error because you have <code>DEBUG = True</code>"]
            }
            found_error_tech = set()
            for tech, patterns in error_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, error_page_html, re.IGNORECASE):
                        if tech not in found_error_tech:
                            result_entry = {"status_triggered_with": status, "url_checked": error_test_url, "identified_technology": tech, "matched_pattern": pattern}
                            error_page_results.append(result_entry)
                            found_error_tech.add(tech)
                            logger.info(f"Technology '{tech}' fingerprinted from error page content (Pattern: {pattern})")
                            # Add to main tech fingerprint if not already there prominently
                            if tech not in self.results["technology_fingerprint"]["server_software"] and \
                               tech not in self.results["technology_fingerprint"]["cdn_providers"] and \
                               tech not in self.results["technology_fingerprint"]["frameworks_libraries"]:
                                # Categorize where to put it
                                if tech in ["Apache", "IIS", "Nginx", "LiteSpeed", "OpenResty"]: # Web Servers
                                    self.results["technology_fingerprint"]["server_software"].append(f"{tech} (from error page)")
                                elif tech in ["Cloudflare", "Akamai", "AWS (S3/CloudFront)", "Google Cloud"]: # CDNs
                                     self.results["technology_fingerprint"]["cdn_providers"].append(f"{tech} (from error page)")
                                else: # Frameworks like Spring, Rails, Django
                                     self.results["technology_fingerprint"]["frameworks_libraries"].append(f"{tech} (from error page)")
                        break # Found this tech, move to next tech
            if not found_error_tech: logger.info(f"No specific technology signatures found on the error page from {error_test_url} (Status: {status}).")
            if 400 <= status < 600: error_page_results.append({"status_triggered_with": status, "url_checked": error_test_url, "content_snippet_on_error": error_page_html[:500]}) # First 500 chars
        else:
            logger.warning(f"Could not fetch error page from {error_test_url} to analyze.")
            error_page_results.append({"status_triggered_with": "Fetch Failed", "url_checked": error_test_url})

    async def fuzz_common_paths(self):
        if not self.config.get("enable_directory_file_fuzzing", False):
            return
        logger.warning("EXPERIMENTAL: Directory/File Fuzzing enabled. This is an active scanning technique.")
        fuzz_wordlist_path = self.config.get("fuzzing_wordlist_file", "common_paths_fuzz.txt")
        if not os.path.exists(fuzz_wordlist_path):
            logger.error(f"Fuzzing wordlist {fuzz_wordlist_path} not found. Skipping fuzzing.")
            try: # Create a placeholder file
                with open(fuzz_wordlist_path, 'w', encoding='utf-8') as f_fuzz_placeholder:
                    f_fuzz_placeholder.write("# Example paths for KAIROS fuzzing (one per line):\nadmin_panel\nconfig.bak\ndebug.php\n.env\n")
                logger.info(f"Created a placeholder fuzzing wordlist: {fuzz_wordlist_path}. Please populate it.")
            except: pass # Ignore if cannot create
            return
        with open(fuzz_wordlist_path, 'r', encoding='utf-8') as f_fuzz:
            fuzz_paths_base = [line.strip() for line in f_fuzz if line.strip() and not line.startswith('#')]
        if not fuzz_paths_base:
            logger.warning("Fuzzing wordlist is empty. Skipping fuzzing.")
            return

        fuzz_paths_to_check = set(fuzz_paths_base) # Start with base paths
        apply_extensions = self.config.get("fuzzing_apply_common_extensions", [])
        if apply_extensions:
            for base_path in fuzz_paths_base:
                if '.' not in base_path.split('/')[-1]: # If it looks like a dir or filename without extension
                    for ext in apply_extensions:
                        fuzz_paths_to_check.add(f"{base_path}{ext}")

        logger.info(f"Starting path fuzzing with {len(fuzz_paths_to_check)} entries (including extensions if any) from {fuzz_wordlist_path}...")
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        fuzz_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"
        fuzzed_findings = self.results["security_posture"].setdefault("fuzzed_paths_found", [])

        # Get content of a known non-existent page to compare against (if possible)
        baseline_404_content: bytes | None = None
        baseline_404_url = urljoin(fuzz_base_url, f"/kairos-fuzz-baseline-{os.urandom(6).hex()}.nonexistent")
        resp_404, content_404 = await self._make_request(baseline_404_url, method="GET", allow_redirects=False, max_retries=0)
        if resp_404 and content_404 and resp_404.status == 404:
            baseline_404_content = content_404
            logger.debug(f"Obtained baseline 404 page content (length: {len(baseline_404_content)}) for fuzzing comparison.")


        async def check_fuzz_path(raw_fuzz_path: str):
            fuzz_path_to_test = raw_fuzz_path.lstrip('/')
            fuzz_url = urljoin(fuzz_base_url, fuzz_path_to_test)
            response, content_bytes = await self._make_request(fuzz_url, method="GET", allow_redirects=False, max_retries=0)

            if response and response.status != 404: # Any response other than 404 is interesting
                content_length = len(content_bytes) if content_bytes else int(response.headers.get("Content-Length", 0))

                # Skip if it's a common redirect to homepage or has same content as baseline 404 (custom 404s returning 200)
                main_page_len = len(self._main_page_html_cache) if self._main_page_html_cache else -1
                if response.status in [301, 302, 307] and content_length == main_page_len:
                    logger.debug(f"Fuzzed path {fuzz_url} (Status {response.status}) redirects, content length similar to main page. Likely not a unique find.")
                    return
                if response.status == 200 and baseline_404_content and content_bytes == baseline_404_content:
                    logger.debug(f"Fuzzed path {fuzz_url} (Status 200) has same content as baseline 404. Likely a custom 200 'Not Found' page.")
                    return


                finding = {"path": fuzz_path_to_test, "url": fuzz_url, "status": response.status, "content_length": content_length, "content_type": response.headers.get("Content-Type")}
                fuzzed_findings.append(finding)
                severity = "Low"
                if response.status == 200: severity = "Medium"
                if response.status == 403: severity = "Low" # Exists but forbidden
                if response.status == 500: severity = "Medium" # Internal server error might leak info
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Fuzzed Path Discovery", "description": f"Path '{fuzz_path_to_test}' discovered via fuzzing with status {response.status}.",
                             "severity": severity, "evidence_summary": f"URL: {fuzz_url}, Status: {response.status}, Length: {content_length}"},
                            log_message=f"Fuzzed path found: {fuzz_url} (Status {response.status})", severity_for_log=severity.upper())
        fuzz_tasks = [check_fuzz_path(fp) for fp in fuzz_paths_to_check]
        if fuzz_tasks: await self._execute_task_group(fuzz_tasks, "Path Fuzzing")
        logger.info("Path fuzzing complete.")

    async def run_cms_specific_scans_if_detected(self):
        cms_name = self.results["technology_fingerprint"].get("cms_identified")
        if not cms_name:
            logger.info("No specific CMS identified, skipping CMS-specific scans.")
            return
        logger.info(f"CMS '{cms_name}' identified. Running specific checks...")
        cms_checks_config = self.config["cms_specific_checks"].get(cms_name)
        if not cms_checks_config:
            logger.info(f"No specific check configuration found for CMS: {cms_name}")
            return

        self.results["cms_specific_findings"].setdefault(cms_name, {"checked_paths_status": [], "found_signatures_in_html": [], "version_info": {"detected_version": None, "source": "None"}, "vulnerabilities": [], "interesting_observations": []})
        cms_results = self.results["cms_specific_findings"][cms_name]
        parsed_final_url = urlparse(self.results["general_info"]["final_url"])
        cms_scan_base_url = f"{parsed_final_url.scheme}://{parsed_final_url.netloc}"

        async def check_cms_path(path_suffix: str):
            full_path_url = urljoin(cms_scan_base_url, path_suffix.lstrip('/'))
            response, content_bytes = await self._make_request(full_path_url, allow_redirects=False)
            status_val = "Fetch Failed"; content_len = 0
            if response: status_val = response.status; content_len = len(content_bytes) if content_bytes else int(response.headers.get("Content-Length", 0))
            cms_results["checked_paths_status"].append({"path": path_suffix, "url": full_path_url, "status": status_val, "length": content_len})

            if response and status_val == 200:
                logger.warning(f"CMS ({cms_name}) specific path found: {full_path_url} (Status 200)")
                cms_results["interesting_observations"].append({"type": "Path Accessible", "path": path_suffix, "url": full_path_url})
                if cms_name == "WordPress" and "install.php" in path_suffix.lower() and content_bytes and (b"WordPress setup configuration file" in content_bytes or b"wp-admin/install.php" in content_bytes):
                    add_finding(cms_results, "vulnerabilities", # Add to CMS specific vulns
                                {"type": "CMS Misconfiguration", "description": f"WordPress installation script ({path_suffix}) accessible at {full_path_url}.",
                                 "severity": "High", "recommendation": "Delete install.php or restrict access after WordPress installation."},
                                log_message=f"WordPress install.php accessible: {full_path_url}", severity_for_log="HIGH")
        cms_path_tasks = []
        if "paths" in cms_checks_config:
            for path in cms_checks_config["paths"]: cms_path_tasks.append(check_cms_path(path))
        if cms_path_tasks: await self._execute_task_group(cms_path_tasks, f"{cms_name} Path Checks")

        if "signatures_in_html" in cms_checks_config and self._main_page_html_cache:
            for sig_pattern in cms_checks_config["signatures_in_html"]:
                if re.search(sig_pattern, self._main_page_html_cache, re.IGNORECASE):
                    if sig_pattern not in cms_results["found_signatures_in_html"]: cms_results["found_signatures_in_html"].append(sig_pattern)

        wapp_version = self.results["technology_fingerprint"]["software_versions_found"].get(cms_name)
        if wapp_version: cms_results["version_info"] = {"detected_version": wapp_version, "source": "Wappalyzer"}
        if (not cms_results["version_info"]["detected_version"] or cms_results["version_info"]["source"] == "None") and "version_pattern" in cms_checks_config and self._main_page_html_cache:
            version_patterns = cms_checks_config["version_pattern"]
            if not isinstance(version_patterns, list): version_patterns = [version_patterns] # Ensure list
            for vp_regex in version_patterns:
                try:
                    match = re.search(vp_regex, self._main_page_html_cache, re.IGNORECASE | re.MULTILINE)
                    if match and len(match.groups()) > 0:
                        version = match.group(1).strip(" .-") # Clean up version string
                        if version:
                            cms_results["version_info"] = {"detected_version": version, "source": f"HTML/JS Pattern: {vp_regex}"}
                            self.results["technology_fingerprint"]["software_versions_found"][cms_name] = version # Update global
                            logger.info(f"CMS ({cms_name}) version '{version}' detected via pattern: {vp_regex}")
                            search_urls = generate_vuln_search_url(cms_name, version)
                            add_finding(self.results["security_posture"], "vulnerability_findings", # Also to main vuln list
                                        {"type": "Information Disclosure", "description": f"{cms_name} version {version} detected. Check for CVEs (see details).",
                                         "severity": "Info", "evidence_summary": f"{cms_name} {version} (Pattern: {vp_regex})", "details": {"search_links": search_urls}},
                                        log_message=f"{cms_name} version {version} found. Recommend CVE check.", severity_for_log="INFO")
                            break # Found version, stop pattern matching
                except re.error as re_err_cms_ver: logger.error(f"Regex error with CMS version pattern '{vp_regex}' for {cms_name}: {re_err_cms_ver}")

        if cms_checks_config.get("vulnerable_plugins_themes_check"):
            # This remains a conceptual check. Real implementation needs a dedicated vulnerability DB.
            # Adding a more informative message.
            dedicated_tools = {
                "WordPress": "WPScan",
                "Joomla": "JoomScan",
                "Drupal": "Droopescan",
            }
            tool_recommendation = f"Consider using dedicated tools like {dedicated_tools.get(cms_name, '(e.g., WPScan, JoomScan)')} for detailed plugin/theme vulnerability analysis."
            cms_results["interesting_observations"].append({
                "type": "Further Analysis Recommended",
                "description": f"Vulnerability scanning for {cms_name} plugins/themes is beyond KAIROS's current scope due to the need for extensive, up-to-date vulnerability databases. {tool_recommendation}"
            })
            logger.info(f"For {cms_name} plugin/theme vulnerabilities, manual checks and dedicated tools are highly recommended.")


        logger.info(f"CMS-specific checks for {cms_name} complete.")

    def _format_html_value(self, value, depth=0):
        if value is None: return "<em>N/A</em>"
        if isinstance(value, bool): return "<strong>Yes</strong>" if value else "No"

        if isinstance(value, list):
            if not value: return "<em>None found.</em>"
            # Compact list for simple items
            if all(isinstance(i, (str, int, float)) for i in value) and len(value) < 10 and sum(len(str(i)) for i in value) < 200:
                return ", ".join(html.escape(str(i)) for i in value)
            # List of findings (dictionaries with 'severity')
            if value and isinstance(value[0], dict) and 'severity' in value[0] and 'description' in value[0]:
                items_html = ""
                for item_dict in value:
                    sev = item_dict.get('severity', 'UNKNOWN').upper()
                    desc = html.escape(item_dict.get('description', 'N/A'))
                    item_type = html.escape(item_dict.get('type', 'Finding'))
                    evidence = self._format_html_value(item_dict.get('evidence_summary', item_dict.get('evidence')), depth + 1) if 'evidence_summary' in item_dict or 'evidence' in item_dict else ""
                    recomm = html.escape(item_dict.get('recommendation', ''))
                    details_val = item_dict.get('details')
                    paths_in_spec = item_dict.get('paths_in_spec') # For API specs

                    items_html += f"<li><span class='severity-{sev}'>[{sev}]</span> <strong>{item_type}:</strong> {desc}"
                    if evidence: items_html += f"<br><small><em>Evidence:</em> {evidence}</small>"
                    if recomm: items_html += f"<br><small><em>Recommendation:</em> {recomm}</small>"
                    if isinstance(details_val, dict): items_html += "<br><small><em>Details:</em></small>" + self._format_html_value(details_val, depth + 1)
                    elif details_val: items_html += f"<br><small><em>Details:</em> {html.escape(str(details_val))}</small>" # If details is not a dict but simple string
                    if paths_in_spec and isinstance(paths_in_spec, list):
                        items_html += "<br><small><em>API Paths in Spec:</em></small>"
                        items_html += "<ul>" + "".join(f"<li><pre style='display:inline; padding:2px 4px;'>{html.escape(p)}</pre></li>" for p in paths_in_spec[:10]) + "</ul>" # Display first 10
                        if len(paths_in_spec) > 10: items_html += f"<small>... and {len(paths_in_spec) - 10} more.</small>"

                    items_html += "</li>"
                return f"<ul>{items_html}</ul>"
            else: # Generic list
                return "<ul>" + "".join(f"<li>{self._format_html_value(i, depth + 1)}</li>" for i in value) + "</ul>"

        if isinstance(value, dict):
            if not value: return "<em>N/A</em>"
            # Special handling for CVE search links
            if all(k in value and isinstance(value[k], str) and value[k].startswith("http") for k in ["vulners", "cve_mitre", "nist_nvd"]):
                links_html = [f"<a href='{html.escape(value[key])}' target='_blank'>Search {key.replace('_',' ').title()}</a>" for key in ["vulners", "cve_mitre", "nist_nvd"] if value.get(key)]
                return " | ".join(links_html)

            table_class = "nested-table" if depth > 0 else ""
            table = f"<table class='{table_class}'><tbody>"
            for k, v_val in value.items():
                k_title = html.escape(str(k).replace('_', ' ').title())
                table += f"<tr><th>{k_title}</th><td>{self._format_html_value(v_val, depth + 1)}</td></tr>"
            table += "</tbody></table>"; return table

        # Default for simple strings, numbers
        escaped_str_value = html.escape(str(value))
        # Make URLs clickable
        if isinstance(value, str) and (value.startswith("http:") or value.startswith("https://")):
            return f"<a href='{escaped_str_value}' target='_blank'>{escaped_str_value}</a>"
        # Wrap long strings or strings with newlines (like code snippets, WHOIS data) in <pre>
        if isinstance(value, str) and ("\n" in value or len(value) > 100):
            return f"<pre>{escaped_str_value}</pre>"
        return escaped_str_value

    def generate_html_report(self) -> str:
        meta = self.results["scan_metadata"]
        scan_duration_str = "N/A"
        if meta.get('start_time') and meta.get('end_time'):
            try:
                start_dt = datetime.fromisoformat(str(meta['start_time']).replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(str(meta['end_time']).replace("Z", "+00:00"))
                duration_seconds = (end_dt - start_dt).total_seconds()
                hours, remainder = divmod(duration_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                scan_duration_str = ""
                if hours > 0: scan_duration_str += f"{int(hours)}h "
                if minutes > 0: scan_duration_str += f"{int(minutes)}m "
                scan_duration_str += f"{seconds:.2f}s"
                if not scan_duration_str.strip(): scan_duration_str = f"{duration_seconds:.2f} seconds"
            except Exception: pass

        report_html = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>KAIROS Report: {html.escape(meta['target_input'])}</title><style>
            body {{ font-family: 'Roboto', Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f6f9; color: #333; line-height: 1.7; }}
            .container {{ max-width: 1280px; margin: 25px auto; background-color: #ffffff; padding: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.12); border-radius: 10px; }}
            h1 {{ color: #1a237e; text-align: center; border-bottom: 4px solid #303f9f; padding-bottom: 18px; margin-bottom:30px; font-size: 2.4em; font-weight: 500; }}
            h1 .kairos-k {{ color: #e53935; }} /* Red for K */
            h2 {{ color: #283593; border-bottom: 2px solid #e8eaf6; padding-bottom: 10px; margin-top: 40px; font-size: 1.8em; cursor: pointer; position: relative; font-weight: 500; }}
            h2::after {{ content: ' ▼'; font-size: 0.7em; position: absolute; right: 12px; top: 50%; transform: translateY(-50%); transition: transform 0.2s ease-in-out; color: #5c6bc0; }}
            h2.collapsed::after {{ transform: translateY(-50%) rotate(-90deg); }}
            .section-content {{ display: block; padding-left: 20px; border-left: 4px solid #c5cae9; margin-top:12px; background-color: #f8f9fa; padding:15px; border-radius:0 5px 5px 0; }}
            .section-content.collapsed {{ display: none; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; table-layout: fixed; }}
            th, td {{ padding: 14px 18px; border: 1px solid #e0e0e0; text-align: left; vertical-align: top; word-wrap: break-word; }}
            th {{ background-color: #f1f3f5; font-weight: 600; color: #37474f; }}
            .nested-table {{ margin-top:8px; margin-bottom:8px; border: 1px dashed #ced4da; }}
            .nested-table th {{ background-color: #e9ecef; font-size:0.9em; padding:10px 12px; }}
            .nested-table td {{ font-size:0.9em; padding:10px 12px; }}
            ul {{ padding-left: 28px; margin-top:8px; margin-bottom:12px; list-style-type: square; }}
            li {{ margin-bottom: 7px; }}
            pre {{ background-color: #e8eaf6; padding: 14px; border-radius: 6px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.95em; border: 1px solid #c5cae9; max-height: 350px; overflow-y: auto; color: #1a237e; }}
            a {{ color: #2962ff; text-decoration: none; font-weight: 500; }}
            a:hover {{ text-decoration: underline; color: #1c54b2; }}
            .severity-CRITICAL {{ color: #b71c1c; font-weight: bold; }} .severity-HIGH {{ color: #e53935; font-weight: bold; }}
            .severity-MEDIUM {{ color: #fb8c00; }} .severity-LOW {{ color: #1e88e5; }} .severity-INFO {{ color: #43a047; }}
            .scan-summary-box {{ border: 2px solid #303f9f; padding: 25px; margin-bottom:35px; border-radius: 10px; background-color: #e8eaf6; }}
            .scan-summary-box h3 {{ margin-top:0; color: #1a237e; font-size:1.5em; border-bottom:2px solid #9fa8da; padding-bottom:10px; cursor: pointer; }}
            .scan-summary-box h3::after {{ content: ' ▼'; font-size: 0.7em; position: relative; left: 10px; transition: transform 0.2s ease-in-out; color: #5c6bc0;}}
            .scan-summary-box h3.collapsed::after {{ transform: rotate(-90deg); }}
            .scan-summary-box table.collapsed {{ display:none; }} /* This selector might not be used if content inside h3 is toggled, but good to have */
            .toc {{ margin-bottom: 35px; border: 1px solid #ced4da; padding: 20px; background-color: #f8f9fa; border-radius: 8px; }}
            .toc h3 {{ margin-top:0; color: #37474f; font-weight:500; }}
            .toc ul {{ list-style-type: none; padding-left: 0; columns: 2; -webkit-columns: 2; -moz-columns: 2; }}
            .toc li a {{ display: block; padding: 4px 0; }}
            .footer {{ text-align: center; margin-top: 35px; padding-top: 18px; border-top: 1px solid #e0e0e0; font-size: 0.95em; color: #546e7a; }}
        </style><script>
            function toggleSection(headerElement) {{
                headerElement.classList.toggle('collapsed');
                const content = headerElement.nextElementSibling;
                // Check if next element is section-content or a table directly under scan-summary-box h3
                if (content && (content.classList.contains('section-content') || (headerElement.parentElement.classList.contains('scan-summary-box') && content.tagName === 'TABLE'))) {{
                    content.classList.toggle('collapsed');
                }}
            }}
            document.addEventListener('DOMContentLoaded', () => {{
                document.querySelectorAll('h2, .scan-summary-box h3').forEach(header => {{
                    header.classList.add('collapsed'); // Start collapsed
                    const content = header.nextElementSibling;
                    if (content && (content.classList.contains('section-content') || (header.parentElement.classList.contains('scan-summary-box') && content.tagName === 'TABLE'))) {{
                         content.classList.add('collapsed');
                    }}
                    header.onclick = () => toggleSection(header);
                }});
                // Auto-open specific sections
                const summaryBoxH3 = document.querySelector('.scan-summary-box h3');
                if (summaryBoxH3) {{
                    toggleSection(summaryBoxH3); // Open scan summary by default
                }}
                const criticalHighHeader = document.getElementById('vuln_summary_critical_high');
                if(criticalHighHeader) {{
                    toggleSection(criticalHighHeader); // Open critical/high findings if present
                }}

                // Populate TOC
                const tocList = document.getElementById('toc-list');
                let tocHtml = '';
                const summaryBox = document.querySelector('.scan-summary-box');
                if (summaryBox && summaryBox.id) {{
                    tocHtml += `<li><a href="#${{summaryBox.id}}">Scan Summary</a></li>`;
                }}
                if(document.getElementById('vuln_summary_critical_high')) tocHtml += '<li><a href="#vuln_summary_critical_high">Critical/High Findings</a></li>';
                document.querySelectorAll('h2').forEach(h => {{
                    if(h.id && h.textContent) {{
                        let titleText = h.textContent.split('(')[0].trim(); // Get title without count
                        tocHtml += `<li><a href="#${{h.id}}">${{titleText}}</a></li>`;
                    }}
                }});
                if (tocList) tocList.innerHTML = tocHtml;
            }});
        </script></head><body><div class="container">
        <h1><span class="kairos-k">K</span>AIROS Reconnaissance Report</h1>
        <div class="scan-summary-box" id="scan_summary_box_main_content">
            <h3>Scan Summary</h3>
            <table><tbody>
                <tr><th>Target Input</th><td>{html.escape(meta['target_input'])}</td></tr>
                <tr><th>Normalized Target</th><td>{self._format_html_value(meta['target_normalized'])}</td></tr>
                <tr><th>Effective Domain</th><td>{self._format_html_value(meta.get('effective_domain', 'N/A'))}</td></tr>
                <tr><th>Scan Started (UTC)</th><td>{html.escape(str(meta.get('start_time', 'N/A')))}</td></tr>
                <tr><th>Scan Ended (UTC)</th><td>{html.escape(str(meta.get('end_time', 'N/A')))}</td></tr>
                <tr><th>Scan Duration</th><td>{html.escape(scan_duration_str)}</td></tr>
                <tr><th>Scanner Version</th><td>{html.escape(meta['scanner_version'])}</td></tr>
            </tbody></table>
        </div><div class="toc"><h3>Table of Contents</h3><ul id="toc-list"></ul></div>
        """
        vuln_findings = self.results["security_posture"].get("vulnerability_findings", [])
        critical_high_vulns = [v for v in vuln_findings if isinstance(v, dict) and v.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
        if critical_high_vulns:
            report_html += f"<h2 id='vuln_summary_critical_high'>Critical/High Severity Findings ({len(critical_high_vulns)})</h2><div class='section-content'>{self._format_html_value(critical_high_vulns)}</div>"

        sections_order_map = {
            "general_info": "General Information", "http_details": "HTTP Details", "dns_information": "DNS Information",
            "technology_fingerprint": "Technology Fingerprint", "content_analysis": "Content Analysis",
            "security_posture": "Security Posture Overview", "subdomain_discovery": "Subdomain Discovery",
            "cms_specific_findings": "CMS Specific Findings"
        }

        for key, title in sections_order_map.items():
            data_to_render = self.results.get(key)
            section_id = key.lower().replace(' ', '_')

            if key == "security_posture" and data_to_render:
                num_findings = len(data_to_render.get('vulnerability_findings',[]))
                report_html += f"<h2 id='{section_id}'>{title} ({num_findings} total findings recorded)</h2><div class='section-content'>"
                temp_sec_posture = {k: v for k, v in data_to_render.items() if k != "vulnerability_findings"}
                if temp_sec_posture: report_html += self._format_html_value(temp_sec_posture)
                all_vulns = data_to_render.get("vulnerability_findings", [])
                if all_vulns:
                    report_html += "<h3>All Identified Findings & Observations</h3>"
                    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
                    sorted_vulns = sorted(all_vulns, key=lambda x: severity_order.get(x.get("severity", "UNKNOWN").upper(), 5))
                    report_html += self._format_html_value(sorted_vulns)
                else: report_html += "<p><em>No specific vulnerability findings noted in this section beyond Critical/High summary.</em></p>"
                report_html += "</div>"; continue

            # Skip empty sections unless it's CMS findings which might have content even if base key is initially empty dict
            is_cms_section_and_data_exists = (key == "cms_specific_findings" and isinstance(data_to_render, dict) and any(data_to_render.values()))
            if not data_to_render and not is_cms_section_and_data_exists :
                if key not in ["cms_specific_findings"]: continue # Avoid empty h2 for non-CMS sections that are truly empty

            # Add count to title if data is a list or a dict with 'vulnerability_findings' or 'discovered_subdomains'
            count_suffix = ""
            if isinstance(data_to_render, list):
                count_suffix = f" ({len(data_to_render)})"
            elif isinstance(data_to_render, dict):
                if 'vulnerability_findings' in data_to_render and isinstance(data_to_render['vulnerability_findings'], list):
                    count_suffix = f" ({len(data_to_render['vulnerability_findings'])} findings)"
                elif 'discovered_subdomains' in data_to_render and isinstance(data_to_render['discovered_subdomains'], list):
                    count_suffix = f" ({len(data_to_render['discovered_subdomains'])} discovered)"
                elif key == "cms_specific_findings" and data_to_render: # For CMS, check specific sub-keys
                    total_cms_items = 0
                    for cms, cms_data in data_to_render.items():
                        if isinstance(cms_data, dict):
                            total_cms_items += len(cms_data.get('vulnerabilities', []))
                            total_cms_items += len(cms_data.get('interesting_observations', []))
                    if total_cms_items > 0: count_suffix = f" ({total_cms_items} items)"


            report_html += f"<h2 id='{section_id}'>{title}{count_suffix}</h2><div class='section-content'>"
            if not data_to_render and not is_cms_section_and_data_exists:
                report_html += "<p><em>No data available for this section.</em></p>"
            elif key == "cms_specific_findings" and not is_cms_section_and_data_exists:
                 report_html += "<p><em>No CMS specific findings or CMS not identified.</em></p>"
            else: report_html += self._format_html_value(data_to_render)
            report_html += "</div>"

        report_html += f"""
            <div class="footer">
                <p>KAIROS v{html.escape(meta['scanner_version'])} - Report Generated: {html.escape(datetime.now(timezone.utc).isoformat(timespec='seconds'))} UTC</p>
                <p><em>Disclaimer: This report is for ETHICAL and EDUCATIONAL purposes only. Use responsibly and with explicit permission.</em></p>
            </div></div></body></html>"""
        return report_html

    def generate_text_report(self) -> str:
        report = []
        meta = self.results["scan_metadata"]
        report.append(f"===== KAIROS Report for: {meta['target_input']} =====")
        report.append(f"Normalized Target: {meta['target_normalized']}")
        report.append(f"Effective Domain: {meta.get('effective_domain', 'N/A')}")
        report.append(f"Scan Started (UTC): {meta.get('start_time', 'N/A')}")
        report.append(f"Scan Ended (UTC): {meta.get('end_time', 'N/A')}")
        if meta.get('start_time') and meta.get('end_time'):
            try:
                start_dt = datetime.fromisoformat(str(meta['start_time']).replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(str(meta['end_time']).replace("Z", "+00:00"))
                duration_seconds = (end_dt - start_dt).total_seconds()
                hours, remainder = divmod(duration_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                duration_str_text = ""
                if hours > 0: duration_str_text += f"{int(hours)}h "
                if minutes > 0: duration_str_text += f"{int(minutes)}m "
                duration_str_text += f"{seconds:.2f}s"
                if not duration_str_text.strip(): duration_str_text = f"{duration_seconds:.2f} seconds"
                report.append(f"Scan Duration: {duration_str_text}")
            except Exception as e_duration:
                logger.debug(f"Error calculating scan duration for text report: {e_duration}")
        report.append(f"Scanner Version: {meta['scanner_version']}\n")

        # Critical/High Severity Summary First
        vuln_findings = self.results["security_posture"].get("vulnerability_findings", [])
        critical_high_vulns = [v for v in vuln_findings if
                               isinstance(v, dict) and v.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
        if critical_high_vulns:
            report.append("\n--- Critical/High Severity Findings Summary ---")
            for vuln in critical_high_vulns:
                report.append(
                    f"  - [{vuln['severity'].upper()}] {vuln.get('type', 'N/A')}: {html.unescape(vuln.get('description', 'N/A'))}")  # Unescape for text
                if 'evidence_summary' in vuln: report.append(
                    f"    Evidence: {html.unescape(str(vuln['evidence_summary']))}")
                if 'recommendation' in vuln: report.append(
                    f"    Recommendation: {html.unescape(vuln['recommendation'])}")
            report.append("\n")

        report.append(format_report_section("General Information", self.results["general_info"]))
        report.append(format_report_section("HTTP Details", self.results["http_details"]))
        report.append(format_report_section("DNS Information", self.results["dns_information"]))
        report.append(format_report_section("Technology Fingerprint", self.results["technology_fingerprint"]))
        report.append(format_report_section("Content Analysis", self.results["content_analysis"]))
        report.append(
            format_report_section("Security Posture",
                                  self.results["security_posture"]))  # Will include all findings
        report.append(format_report_section("Subdomain Discovery", self.results["subdomain_discovery"]))
        if self.results["cms_specific_findings"] and any(self.results["cms_specific_findings"].values()): # Check if there's actual CMS data
            report.append(format_report_section("CMS Specific Findings", self.results["cms_specific_findings"]))

        report.append("\n===== End of KAIROS Report =====")
        return "\n".join(report)

    def save_reports(self, directory: str, formats: list[str] | str = "all"):
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Created report directory: {directory}")
            except OSError as e_mkdir:
                logger.error(
                    f"Could not create report directory {directory}: {e_mkdir}. Saving to current directory.")
                directory = "."  # Fallback to current directory

        safe_filename_domain = re.sub(r'[^\w\-_\.]', '_', self.domain or "unknown_target")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_filename = os.path.join(directory, f"kairos_scan_{safe_filename_domain}_{timestamp}")  # Updated prefix

        if isinstance(formats, str): formats = [formats]
        if "all" in formats: formats = ["json", "txt", "html"]

        if "json" in formats:
            json_filepath = f"{base_filename}.json"
            try:
                with open(json_filepath, 'w', encoding='utf-8') as f_json:
                    # Custom encoder for datetime and other non-serializable objects if any
                    class CustomEncoder(json.JSONEncoder):
                        def default(self, obj):
                            if isinstance(obj, (datetime,)): return obj.isoformat()
                            if isinstance(obj, set): return list(obj)
                            # For any other non-serializable type, convert to string as a fallback
                            try:
                                return json.JSONEncoder.default(self, obj)
                            except TypeError:
                                return str(obj)

                    json.dump(self.results, f_json, indent=2, ensure_ascii=False, cls=CustomEncoder)
                logger.info(f"JSON report saved to: {json_filepath}")
            except Exception as e_json_save:
                logger.error(f"Failed to save JSON report to {json_filepath}: {e_json_save}")

        if "txt" in formats:
            txt_filepath = f"{base_filename}.txt"
            try:
                report_content = self.generate_text_report()
                with open(txt_filepath, 'w', encoding='utf-8') as f_txt:
                    f_txt.write(report_content)
                logger.info(f"Text report saved to: {txt_filepath}")
            except Exception as e_txt_save:
                logger.error(f"Failed to save text report to {txt_filepath}: {e_txt_save}")

        if "html" in formats:
            html_filepath = f"{base_filename}.html"
            try:
                report_html_content = self.generate_html_report()
                with open(html_filepath, 'w', encoding='utf-8') as f_html:
                    f_html.write(report_html_content)
                logger.info(f"HTML report saved to: {html_filepath}")
            except Exception as e_html_save:
                logger.error(f"Failed to save HTML report to {html_filepath}: {e_html_save}", exc_info=True)

# --- Command Line Interface ---
async def main_cli():
    # Load configuration first
    load_config()  # Populates global CONFIG

    # KAIROS ASCII Art
    bright_blue = "\033[1;94m"  # Brighter Blue for KAIROS
    bold_red = "\033[1;91m"  # For the K
    reset_color = "\033[0m"
    if platform.system() == "Windows" and not os.getenv('WT_SESSION'):
        bright_blue = bold_red = reset_color = ""  # No colors for basic Windows cmd

    print(bright_blue)  # KAIROS ASCII Art
    print(r"""
    ╦╔═╗ █████╗ ██╗██████╗  ██████╗ ███████╗
    ║║ ╦╗██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
    ╚╩═╝╝███████║██║██████╔╝██║   ██║███████╗
        ██╔══██║██║██╔══██╗██║   ██║╚════██║
        ██║  ██║██║██████╔╝╚██████╔╝███████║
        ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
    """)
    print(reset_color)
    print(f"================================================================================================")
    print(
        f" {bold_red}KAIROS{reset_color} - The Zenith of Intelligent Site Reconnaissance (v{CONFIG.get('scanner_version', 'N/A')})")
    print(f" Developed by Karim Karam (with AI collaboration) for ETHICAL & EDUCATIONAL purposes. ")
    print(f"================================================================================================\n")

    target_url_input = ""
    while not target_url_input:
        target_url_input = input("Enter the full target URL (e.g., https://example.com or example.com): ").strip()
        parsed_cli_url = urlparse(target_url_input)

        if not parsed_cli_url.scheme:
            # Check if it looks like a domain name without a scheme
            # A simple check: if there's no path or the first part of path has a dot (like domain.com/path)
            path_segment = parsed_cli_url.path.split('/')[0] if parsed_cli_url.path else ""
            if not path_segment or "." not in path_segment :
                if not parsed_cli_url.netloc: # if netloc is also empty, it's likely not a domain
                    logger.error("Invalid input. Please provide a valid URL or domain name (e.g., example.com, http://test.com).")
                    target_url_input = ""  # Reset to loop again
                    continue

            temp_target_https = f"https://{target_url_input}"
            logger.info(f"No scheme provided. Probing HTTPS first for: {temp_target_https}")
            try:
                # Quick HEAD request to check HTTPS viability (without SSL verification for this probe)
                # Use a new session for this quick probe
                temp_ssl_context = ssl.create_default_context()
                temp_ssl_context.check_hostname = False
                temp_ssl_context.verify_mode = ssl.CERT_NONE
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=temp_ssl_context)) as temp_session:
                    async with temp_session.head(temp_target_https, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp_check:
                        if resp_check.status < 500:  # Any non-server error response means HTTPS is likely viable
                            target_url_input = temp_target_https
                            logger.info(
                                f"HTTPS probe successful (Status {resp_check.status}). Using: {target_url_input}")
                        else:
                            target_url_input = f"http://{target_url_input}"  # Fallback to HTTP
                            logger.info(
                                f"HTTPS probe returned {resp_check.status}. Assuming HTTP. Using: {target_url_input}")
            except Exception as e_probe:
                target_url_input = f"http://{target_url_input}"  # Fallback to HTTP on any error
                logger.warning(f"HTTPS probe failed ({type(e_probe).__name__}: {e_probe}). Assuming HTTP. Using: {target_url_input}")

        # Re-parse after potential scheme addition to ensure netloc is present
        parsed_cli_url = urlparse(target_url_input)
        path_segment_recheck = parsed_cli_url.path.split('/')[0] if parsed_cli_url.path else ""
        if not (parsed_cli_url.netloc or (path_segment_recheck and "." in path_segment_recheck)):  # Ensure domain-like structure
            logger.error("Invalid URL. Could not determine a valid domain/host. Please try again.")
            target_url_input = ""  # Reset to loop again

    try:
        output_dir_domain_part = urlparse(target_url_input).netloc.replace(':', '_').replace('.', '_')
        if not output_dir_domain_part: # Handle cases like "example.com/path" where netloc might be empty if not parsed as full URL initially
            output_dir_domain_part = urlparse(f"http://{target_url_input}").netloc.replace(':', '_').replace('.', '_')

    except Exception:
        output_dir_domain_part = "kairos_scan"  # Fallback
    output_dir_default_suggestion = f"./kairos_reports_{output_dir_domain_part}"

    output_dir = input(
        f"Enter directory to save reports (default: {output_dir_default_suggestion}): ").strip() or output_dir_default_suggestion
    report_formats_input = input(
        "Report formats (comma-separated: json,txt,html,all - default: all): ").strip().lower() or "all"
    formats_to_save = [fmt.strip() for fmt in report_formats_input.split(',')]
    if "all" in formats_to_save: formats_to_save = ["json", "txt", "html"]

    log_level_input = input("Log level (DEBUG, INFO, WARNING, ERROR - default: INFO): ").strip().upper()
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    if log_level_input and log_level_input in valid_log_levels:
        logger.setLevel(getattr(logging, log_level_input))
        console_handler.setLevel(getattr(logging, log_level_input))
        logger.info(f"Log level set to {log_level_input}.")
    elif not log_level_input: # User pressed Enter for default
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
        logger.info("Log level set to INFO (default).")
    else:
        logger.warning(f"Invalid log level '{log_level_input}'. Defaulting to INFO.")
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)

    scanner = SiteScanner(target_url_input)  # Initialize the scanner
    async with scanner:  # Use async context manager
        await scanner.run_full_scan()

    scanner.save_reports(output_dir, formats=formats_to_save)
    print("\n================================================================================================")
    logger.info("KAIROS has completed its mission. Stay curious, stay ethical.")
    print("================================================================================================")


if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        logger.info("\nScan aborted by user. Exiting KAIROS.")
    except ValueError as ve_main:  # Catch config errors or invalid URL from SiteScanner init
        logger.critical(f"Initialization Error: {ve_main}")
    except Exception as e_main:
        logger.critical(f"A critical unhandled error occurred in KAIROS's main execution: {e_main}", exc_info=True)