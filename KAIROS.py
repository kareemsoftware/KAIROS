# -*- coding: utf-8 -*-
# ██╗  ██╗ █████╗ ██╗██████╗  ██████╗ ███████╗
# ██║ ██╔╝██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
# █████╔╝ ███████║██║██████╔╝██║   ██║███████╗
# ██╔═██╗ ██╔══██║██║██╔══██╗██║   ██║╚════██║
# ██║  ██╗██║  ██║██║██████╔╝╚██████╔╝███████║
# ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
#
# KAIROS - The Zenith of Intelligent Site Reconnaissance
# Version: 4.0.2 "Quantum Oracle - Configuration Awareness & Robust API Handling"
# (KAI-Enhanced - Advanced Heuristics, Augmented Intelligence, Deeper JS/API Analysis, Adaptive Threat Insights,
#  External API Integrations Activated & Expanded, Enhanced Correlation Logic, Active OpenAI & DeepSeek Analysis,
#  Refined Reporting, Comprehensive Task Completion, Improved API Key Handling)
#
# Conceived & Crafted by: Karim Karam (Cyber-Alchemist)
#                     In Collaboration with: K.A.I. (Karm Artificial Intelligence)
#
# Enhanced and Completed by: AI based on user's request for comprehensive development.
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
#   It leverages advanced heuristics, data correlation, and external API integrations (including LLMs)
#   to provide deeper, actionable insights.
#
# Mission Statement:
#   "Unveiling Digital Universes, One Correlated Quantum Bit at a Time - Now with Symbiotic AI, Active API-Driven Insights, Nexus-Level Correlative Power, and AI-Powered Summarization & Analysis."
#
# Ethical Imperative:
#   This instrument is forged for KNOWLEDGE, DEFENSE, and ETHICAL EXPLORATION.
#   Its profound power demands unwavering responsibility. Utilization must ALWAYS be
#   with EXPLICIT, VERIFIABLE PERMISSION from the target system's rightful owners.
#   Misuse is a desecration of trust and the core ethos of this project.
#
# --- [ Quantum Oracle v4.0.2 - Fixes & Enhancements by AI based on user feedback ] ---
#
#   [*] VERSION BUMP & PHILOSOPHY: KAIROS v4.0.2
#       - All previous fixes and features from v4.0.1 are retained and stabilized.
#       - [FIXED & ENHANCED] External API Key Handling:
#           - `_fetch_virustotal_report`: Now correctly checks for API key presence *before* attempting to make a call. Logging messages improved to be more specific.
#           - `_fetch_nvd_cves`: Similar check for NVD API key.
#           - `_query_llm_provider`: Enhanced checks for API key and model configuration before attempting API calls.
#           - Startup messages now more clearly indicate if API keys are missing or if corresponding integrations are disabled, reducing redundant warnings during the scan.
#       - [IMPROVED] LLM Analysis Task (`run_llm_analysis_tasks`):
#           - More explicit logging if LLM analysis is skipped due to configuration (key missing or feature disabled), rather than just "disabled".
#           - Ensures that if a preferred LLM provider fails (e.g., due to transient error after key check), the system attempts the next provider in the preference list for each task.
#       - [IMPROVED] Configuration Loading (`load_config`):
#           - At startup, if an API key is found (either in config or ENV VAR) but the corresponding `enable_external_api_integrations` flag for that service is `False`, KAIROS will now automatically set it to `True` and log this action. This makes it easier for users to enable integrations by just providing the key.
#           - If a key is *not* found, the corresponding `enable_external_api_integrations` flag will be set to `False` to prevent attempts to use the API, and a warning will be logged.
#       - [REFINED] Logging: Reduced redundant "API key not provided" warnings during the scan phase by handling these checks more proactively at startup or within the API call functions.
#       - [STABILITY] Minor robustness improvements in various helper functions.
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
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus
from datetime import datetime, timezone, timedelta
import html  # For escaping HTML content in reports
import gzip  # For gzipped sitemaps
import random
import string
import hashlib  # For content hashing
from collections import Counter
import io  # For GitPython config parsing
import time  # For rate limiting NVD & VT API calls

# External Libraries (ensure these are installed: pip install ...)
import aiohttp
from bs4 import BeautifulSoup, Comment as BsComment
import dns.resolver  # type: ignore

try:
    from yarl import URL as YARL_URL

    YARL_AVAILABLE = True
except ImportError:
    YARL_AVAILABLE = False
    print(
        "[WARN] 'yarl' library not found. Cookie filtering might be less robust or encounter issues. Install with: pip install yarl")

try:
    import requests

    if hasattr(requests, 'get') and callable(requests.get):
        REQUESTS_AVAILABLE = True
    else:
        REQUESTS_AVAILABLE = False
        print(
            "[WARN] 'requests' library is imported but 'requests.get' is not callable. The library might be corrupted. Some features will be skipped. Try reinstalling: pip uninstall requests -y; pip install requests")

except ImportError:
    REQUESTS_AVAILABLE = False
    print(
        "[WARN] 'requests' library not found. Some features like crt.sh, Wayback Machine, NVD, and VirusTotal will be skipped. Install with: pip install requests")

try:
    import requests_cache

    REQUESTS_CACHE_AVAILABLE = True
    requests_cache.install_cache('kairos_api_cache', backend='sqlite',
                                 expire_after=timedelta(hours=2))  # Increased cache to 2 hours
    print("[INFO] 'requests-cache' library found. External API calls will be cached.")
except ImportError:
    REQUESTS_CACHE_AVAILABLE = False
    print(
        "[INFO] 'requests-cache' library not found. External API calls will not be cached. Install with: pip install requests-cache")

try:
    import nmap  # type: ignore

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[WARN] python-nmap library not found. Port scanning will be skipped. Install with: pip install python-nmap")

from tqdm.asyncio import tqdm as async_tqdm

try:
    import whois  # type: ignore

    if not hasattr(whois, 'whois'):
        print(
            "[WARN] Potentially incorrect 'whois' library detected or it's corrupted. WHOIS lookups might fail or be limited. Ensure 'python-whois' is installed: pip uninstall whois -y; pip install python-whois")
        WHOIS_CORRECT_LIB = False
    else:
        WHOIS_CORRECT_LIB = True
except ImportError:
    print(
        "[WARN] python-whois library not found. WHOIS lookups will be skipped. Install with: pip install python-whois")
    WHOIS_CORRECT_LIB = False

from Wappalyzer import Wappalyzer, WebPage  # type: ignore

try:
    import git  # type: ignore

    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False
    print(
        "[INFO] GitPython library not found. Advanced .git analysis will be skipped. Install with: pip install GitPython")

try:
    from esprima import parseScript, error_handler, nodes as esprima_nodes

    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False
    esprima_nodes = None  # type: ignore
    print(
        "[INFO] 'esprima-python' library not found. Advanced JavaScript AST analysis will be skipped. Install with: pip install esprima-python")

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError

    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print(
        "[INFO] 'ipwhois' library not found. IP Address ASN/Organization lookup will be skipped. Install with: pip install ipwhois")

try:
    import yaml

    PYYAML_AVAILABLE = True
except ImportError:
    PYYAML_AVAILABLE = False
    print(
        "[INFO] 'PyYAML' library not found. YAML API specification parsing will be skipped. Install with: pip install PyYAML")

try:
    import openai

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("[INFO] 'openai' library not found. OpenAI-based analysis will be skipped. Install with: pip install openai")

# DeepSeek uses OpenAI compatible client, so check openai for its client
DEEPSEEK_CLIENT_AVAILABLE = OPENAI_AVAILABLE

CONFIG_FILE_NAME = "config_kairos.json"
DEFAULT_CONFIG = {
    "scanner_version": "4.0.2 Quantum Oracle - Configuration Awareness & Robust API Handling",
    "default_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 KAIROS/4.0.2",
    "request_timeout_seconds": 30,
    "max_concurrent_requests": 25,
    "dns_timeout_seconds": 8,
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
        "graphql", "ads", "app-ads", "assets-origin", "origin", "webservice", "ws",
        "grafana", "prometheus", "kibana", "elasticsearch", "jenkins", "gitlab", "docker", "portainer",
        "dev-api", "staging-api", "prod-api", "api-v1", "api-v2", "api-v3", "test-api", "internal-api"
    ],
    "sensitive_paths_categories": {
        "config_files": [
            ".env", ".env.local", ".env.development", ".env.staging", ".env.production", "config.php", "wp-config.php",
            "settings.php", "web.config", "database.yml", "configuration.php", "appsettings.json", "Procfile",
            "localsettings.php", "application.ini", "settings.ini", "config.json", "secrets.json", "credentials.json",
            "params.php", ".htpasswd", ".htaccess", "docker-compose.yml", "nginx.conf", "httpd.conf", "apache2.conf",
            "config/config.ini", "config/database.php", "app/config/parameters.yml", "app/config/local.php",
            "config/secrets.yml", "conf/server.xml", "server.xml", "context.xml", "security.xml", "credentials.xml",
            "connectionstrings.config", "config/settings_local.py", "credentials", "settings.py", "local_settings.py",
            ".npmrc", ".yarnrc", ".git-credentials", "id_rsa", "id_dsa", "key.pem", "cert.pem", "application.yml",
            "bootstrap.yml"
        ],
        "backup_archives": [
            "backup.sql", "backup.zip", "dump.sql", "site.tar.gz", "backup.tar.gz", "database.sql.gz",
            "db.zip", "_backup.zip", "data.rar", "website_backup.7z", "backup.bak", "site.bak", "db.bak",
            "backup.sql.zip", "db_backup.sql", "backup.tgz", "data.sql", "full_backup.zip", "site_archive.zip",
            "backup.mdb", "database.mdb", "data.tar.bz2", "backup.dump", "website.sql", "www.zip", "site.zip"
        ],
        "log_files": [
            "access.log", "error.log", "debug.log", "app.log", "server.log", "audit.log", "catalina.out",
            "system.log", "security.log", "php_errors.log", "laravel.log", "sql.log", "queries.log",
            "trace.axd", "production.log", "development.log", "nohup.out", "gunicorn.log", "uwsgi.log",
            "npm-debug.log", "yarn-error.log", "pm2.log", "celery.log", "sql_error_log"
        ],
        "exposed_services_info": [
            "phpinfo.php", "info.php", "test.php", "status.php", "server-status", "server-info", "status",
            "/jolokia/list", "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/metrics",
            "/actuator/httptrace", "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",
            "/actuator/beans", "/actuator/configprops", "/actuator/mappings", "/prometheus", "/metrics",
            "/api/swagger.json", "/swagger-ui.html", "swagger.json", "openapi.json", "api-docs", "openapi.yaml",
            "swagger.yaml",
            "license.php", "readme.html", "RELEASE_NOTES.txt", "CHANGELOG.md", "INSTALL.md", "UPGRADE.txt",
            "/api/v2/api-docs", "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs", "/_profiler/phpinfo",
            "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "Gemfile",
            "Gemfile.lock", "requirements.txt", "Pipfile", "Pipfile.lock", "build.gradle", "pom.xml", "ads.txt",
            "app-ads.txt",
            ".well-known/node", ".well-known/host-meta", ".well-known/host-meta.json", "crossdomain.xml",
            "clientaccesspolicy.xml", "/status/all", "/healthz", "/livez", "/readyz", "version.txt", "build-info.txt"
        ],
        "version_control_exposed": [
            ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index", ".git/FETCH_HEAD", ".git/refs/heads/master",
            ".git/refs/heads/main", ".git/ORIG_HEAD", ".git/COMMIT_EDITMSG", ".git/description", ".git/hooks/",
            ".git/info/exclude", ".git/packed-refs", ".git/logs/",
            ".svn/entries", ".svn/wc.db", ".svn/pristine/", ".svn/all-wcprops", ".svn/wcprops/", ".svn/format",
            ".hg/hgrc", ".hg/store/00manifest.i", ".hg/bookmarks", ".hg/branchmap.cache", ".hg/dirstate",
            ".bzr/README", ".bzr/checkout.conf", ".bzr/branch/", ".bzr/branch-format"
        ],
        "common_admin_interfaces": [
            "admin/", "administrator/", "login/", "wp-admin/", "admin.php", "admin/login.php",
            "phpmyadmin/", "pma/", "cpanel/", "webadmin/", "admin_area/", "controlpanel/", "manage/",
            "user/login", "admin/dashboard", "backend/", "secure_admin/", "admincp/", "webpanel/",
            "django-admin/", "rails/info/properties", "admin123/", "secret-admin/", "admin.html", "login.html",
            "admin/index.php", "admin/home.php", "backend/login", "admin/auth", "/manage/login", "webfig/",
            "admin/login", "user/signin", "auth/login", "console/", "system/"
        ],
        "sensitive_directories": [
            "includes/", "uploads/", "files/", "backup/", "temp/", "tmp/", "private/", "secret/", "admin_files/",
            "config/", "cgi-bin/", "data/", "db/", "protected/", "logs/", "temp_files/", "bak/",
            "vendor/", "node_modules/", "storage/logs", "app/etc", "sites/default/files", "sites/default/private",
            "WEB-INF/", "WEB-INF/web.xml", "WEB-INF/classes/", "assets/private", ".ssh/", ".aws/", ".config/",
            "etc/", "conf/", "settings/", "var/log/", "app/logs/", "storage/app", "storage/framework/sessions",
            "wp-content/debug.log", "app_data/", "backups/"
        ],
        "security_txt_paths_list": ["/.well-known/security.txt", "/security.txt"]
    },
    "malware_js_signatures": [
        r"eval\s*\(", r"document\.write\s*\(.*%3Cscript", r"unescape\s*\(", r"decodeURIComponent\s*\(",
        r"String\.fromCharCode\s*\(", r"(?i)iframe.*src\s*=\s*['\"](?:javascript:|data:text/html|http[s]?://[^/]*evil)",
        r"crypto-js\.js", r"miner\.js", r"coinhive\.min\.js", r"webminerpool\.js", r"jsecoin\.com",
        r"\.innerHTML\s*=\s*.*<script>", r"appendChild\s*\(.*createElement\('script'\)",
        r"ws:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
        r"load\s*\(\s*['\"].*evil", r"atob\s*\(", r"\b(cryptonight|stratum|webassembly_miner)\b",
        r"window\.top\.location\.href\s*=\s*['\"]http", r"xmr\.สมุนไพร"
    ],
    "api_key_patterns": {
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Google OAuth ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "Firebase API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Access Key (Heuristic)": r"(?i)(aws|amazon)?.{0,20}(\"|')?[A-Za-z0-9/+=]{40}(\"|')?",
        "GitHub Token (Modern)": r"gh[pousr]_[0-9a-zA-Z]{36,76}",
        "GitHub Token (Classic)": r"github_pat_[0-9a-zA-Z_]{82}",
        "GitLab Personal Access Token": r"glpat-[0-9a-zA-Z\-\_]{20}",
        "Slack Token (Legacy)": r"xox[pbar]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-fA-F0-9]{32}",
        "Slack Webhook": r"https?://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "Stripe API Key": r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,99}",
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
        "DeepSeek API Key": r"sk-[a-f0-9]{32}",
        "Generic JWT": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "SSH Private Key (PEM)": r"-----BEGIN ((RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----",
        "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "Generic Secret/Password in URL": r"(password|passwd|secret|token|auth_token|api_key|session_key)=[\w\%\-\.~!$&'()*+,;=:@/?#\[\]]+",
        "Basic Auth in URL": r"https?://[^:]+:[^@]+@",
        "JDBC Connection String (Heuristic)": r"jdbc:(mysql|postgresql|oracle|sqlserver|mariadb|h2)://[^\s'\"`]+",
        "Bearer Token (Heuristic)": r"(?i)Bearer\s+[A-Za-z0-9\-\._~+\/]+=*"
    },
    "js_interesting_patterns": {
        "Cloud Storage URL (S3)": r"['\"](s3://[a-zA-Z0-9.-]+/[^'\"\s]+|https?://[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9.-]*\.amazonaws\.com/[^'\"\s]*)['\"]",
        "Cloud Storage URL (GCS)": r"['\"](gs://[a-zA-Z0-9.-]+/[^'\"\s]+|https?://storage\.googleapis\.com/[a-zA-Z0-9.-]+/[^'\"\s]*)['\"]",
        "Cloud Storage URL (Azure Blob)": r"['\"](https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net/[^'\"\s]+)['\"]",
        "Internal IP Address": r"['\"](10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.)[0-9]{1,3}|localhost|127.0.0.1)['\"]",
        "Developer Comment (TODO/FIXME)": r"//\s*(TODO|FIXME|HACK|XXX|NOTE|OPTIMIZE|BUG|REVIEW|WARNING|DANGER|LEAK|VULN|SECURITY|PASSWORD|KEY|SECRET|TOKEN):?\s*(.+)",
        "Potential Endpoint Path": r"['\"](\/(api(?:/v[0-9]+)?|rest|service|graphql|ws|rpc|jsonrpc|soap)(?:/[^'\"\s?#]+)|/_next/data/[^'\"\s?#]+|/\.netlify/functions/[^'\"\s?#]+|/firebaseapp\.com/__/auth/handler|/__launchdarkly|/clientstream|/eventsource|/sockjs-node|/socket.io)['\"]",
        "WebSocket URL": r"['\"](wss?://\S+?)['\"]",
        "Firebase Database URL": r"['\"](https?://[a-zA-Z0-9_-]+\.firebaseio\.com)['\"]",
        "DOM XSS Sink (innerHTML - Regex)": r"\.innerHTML\s*=[^=;]+",
        "DOM XSS Sink (outerHTML - Regex)": r"\.outerHTML\s*=[^=;]+",
        "DOM XSS Sink (document.write - Regex)": r"document\.write[ln]?\s*\(",
        "DOM XSS Sink (eval - Regex)": r"\beval\s*\(",
        "Data Source (location.* - Regex)": r"location\.(href|hash|search|pathname|assign|replace)\b",
        "Data Source (document.URL/URI.* - Regex)": r"document\.(URL|documentURI|URLUnencoded|baseURI)\b",
        "Data Source (document.referrer - Regex)": r"document\.referrer\b",
        "Data Source (window.name - Regex)": r"window\.name\b",
        "Data Source (document.cookie - Regex)": r"document\.cookie\b",
        "PostMessage Usage (Regex)": r"\.postMessage\s*\(",
        "Potentially Sensitive Function (localStorage/sessionStorage - Regex)": r"(localStorage|sessionStorage)\.(setItem|getItem|removeItem|clear)\s*\("
    },
    "js_ast_analysis_config": {
        "enabled": True,
        "max_file_size_kb_for_ast": 1024,
        "dangerous_function_calls": ["eval", "Function", "setTimeout", "setInterval"],
        "dom_xss_sinks": {
            "innerHTML": {"object_match": None, "property_match": "innerHTML", "type": "Assignment"},
            "outerHTML": {"object_match": None, "property_match": "outerHTML", "type": "Assignment"},
            "document.write": {"object_match": "document", "property_match": "write", "type": "Call"},
            "document.writeln": {"object_match": "document", "property_match": "writeln", "type": "Call"},
            "setAttribute": {"object_match": None, "property_match": "setAttribute", "type": "Call",
                             "arg_index_is_sink": 1,
                             "first_arg_name_match_regex": ["src", "href", "data", "style", "on.*", "formaction",
                                                            "xlink:href", "innerHTML", "codebase", "action",
                                                            "background", "cite", "classid", "form", "icon", "manifest",
                                                            "poster", "profile", "srcset"]},
            "jQuery.html": {"object_match": "$", "property_match": "html", "type": "Call"},  # Assuming $ is jQuery
            "jQuery.append": {"object_match": "$", "property_match": "append", "type": "Call"},
            "jQuery.prepend": {"object_match": "$", "property_match": "prepend", "type": "Call"},
            "jQuery.after": {"object_match": "$", "property_match": "after", "type": "Call"},
            "jQuery.before": {"object_match": "$", "property_match": "before", "type": "Call"},
            "Element.insertAdjacentHTML": {"object_match": None, "property_match": "insertAdjacentHTML", "type": "Call"}
        },
        "sensitive_storage_keys_ast": ["token", "jwt", "secret", "key", "auth", "pass", "cred", "session", "api_key",
                                       "private_key", "access_token", "refresh_token", "user_id", "client_secret",
                                       "bearer"],
        "potential_source_identifiers_ast": {
            # Values are boolean (true if source) or a dict for more complex (e.g. jQuery val)
            "location.href": True, "location.hash": True, "location.search": True, "location.pathname": True,
            "document.URL": True, "document.documentURI": True, "document.referrer": True,
            "window.name": True, "document.cookie": True,
            "message": True, "event.data": True,  # Common in event handlers
            "this.href": True, "this.src": True,  # Common in event handlers on elements
            "getParameterByName": True,  # Common custom function name
            "URLSearchParams.get": True,  # Specific method
            "jQuery.val": {"object_match": "$", "property_match": "val", "type": "Call"},
            # Example for specific jQuery method
            "formInput.value": True,  # Generic for input elements
        }
    },
    "dns_records_to_query": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "DNSKEY", "SPF", "DMARC",
                             "PTR", "HINFO", "RP", "URI", "TLSA", "DS", "NAPTR"],
    "wildcard_dns_config": {
        "num_probes": 3,
        "http_probe_timeout_seconds": 10,
        "content_similarity_threshold_bytes": 350,
        "compare_http_response_similarity": True,
        "title_similarity_threshold_ratio": 0.65
    },
    "common_ports_to_scan": "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1080,1433,1521,1723,2049,3306,3389,5432,5900,6379,8000,8008,8080,8443,8888,9000,9090,9200,9300,11211,27017,27018,50000,50070,6443,2375,2376,10250,10255,3000,5000,8009,8180,6000,6001,7001,7002,7070,7071,25565",
    "cms_specific_checks": {
        "WordPress": {
            "paths": ["/wp-login.php", "/xmlrpc.php", "/wp-json/", "/wp-content/debug.log", "/wp-cron.php",
                      "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old", "/wp-admin/install.php",
                      "/readme.html", "/license.txt",
                      "/wp-content/uploads/", "/wp-admin/setup-config.php", "/wp-admin/upgrade.php",
                      "/wp-json/wp/v2/users"],
            "signatures_in_html": [r"wp-content/themes", r"wp-includes", r"Yoast SEO", r"Rank Math", r"Elementor",
                                   r"WooCommerce", r"wp-block-library-css"],
            "version_pattern": [
                r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9\.]+)",
                r"<meta name=\"generator\" content=\"WordPress ([0-9\.]+)\"",
                r"wp-includes/css/dist/block-library/style.min.css\?ver=([0-9\.]+)",
                r"/wp-includes/js/tinymce/tinymce.min.js\?ver=([0-9\.]+)"
            ],
            "vulnerable_plugins_themes_check": True,
            "dedicated_tool_recommendation": "WPScan (wpscan.org), Nuclei with WordPress templates"
        },
        "Joomla": {
            "paths": ["/administrator/", "/configuration.php-dist", "/README.txt", "/LICENSE.txt",
                      "/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml",
                      "/configuration.php.bak", "/web.config.txt"],
            "signatures_in_html": [r"com_content", r"Joomla! - Open Source Content Management", r"media/jui/js",
                                   r"templates/system/css/system.css"],
            "version_pattern": [
                r"<meta name=\"generator\" content=\"Joomla! ([0-9\.]+) Platform\"",
                r"/media/cms/js/core\.js\?([a-f0-9]+)",  # Version can be a hash sometimes
                r"Joomla! (\d+\.\d+\.\d+) - Open Source Content Management",
                r"<meta name=\"generator\" content=\"Joomla! - Open Source Content Management - Version ([0-9\.]+) \">"
            ],
            "vulnerable_plugins_themes_check": True,
            "dedicated_tool_recommendation": "JoomScan (OWASP JoomScan), Nuclei with Joomla templates"
        },
        "Drupal": {
            "paths": ["/user/login", "/CHANGELOG.txt", "/sites/default/settings.php", "/core/INSTALL.txt",
                      "/update.php", "/MAINTAINERS.txt", "/web.config", "/core/misc/drupal.js"],
            "signatures_in_html": [r"Drupal\.settings", r"sites/default/files", r"X-Generator: Drupal",
                                   r"misc/drupal.js", r"core/assets/vendor"],
            "version_pattern": [
                r"<meta name=\"Generator\" content=\"Drupal ([0-9\.]+)",
                r"Drupal ([0-9\.]+) \(http",
                r"core/misc/drupal\.js\?v=([0-9\.]+)",
                r"core/modules/system/system\.info\.yml"  # Check for version in this file if accessible
            ],
            "vulnerable_plugins_themes_check": True,
            "dedicated_tool_recommendation": "Droopescan, Nuclei with Drupal templates"
        },
        "Magento": {
            "paths": ["/downloader/", "/errors/report.php", "/RELEASE_NOTES.txt", "/app/etc/local.xml",
                      "/magento_version", "/health_check.php", "/static/deployed_version.txt"],
            "signatures_in_html": [r"skin/frontend/", r"Magento", r"static/version", r"requirejs/mage",
                                   r"pub/static/frontend"],
            "version_pattern": [
                r"Magento_Theme/js/responsive\.js\?version=([0-9\.]+)",
                r"<meta name=\"format-detection\" content=\"telephone=no\">\s*<script type=\"text/x-magento-init\">",
                # Presence indicates Magento
                r"MAGENTO_VERSION = '([0-9\.]+)'",  # Found in some JS
                r"Magento CLI version ([0-9\.]+)"  # From exposed files
            ],
            "vulnerable_plugins_themes_check": True,
            "dedicated_tool_recommendation": "MagentoScan (magescan.com), Nuclei with Magento templates."
        },
        "Shopify": {  # Shopify versions are not typically exposed directly
            "paths": ["/admin", "/cart.js", "/password", "/collections.json", "/services/javascripts/currencies.js",
                      "/robots.txt", "/sitemap.xml", "/apps/", "/themes/"],
            "signatures_in_html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"ShopifyAnalytics", r"shopify-cloud",
                                   r"window.Shopify ="],
            "version_pattern": [],  # Shopify is SaaS, version is managed by Shopify
            "vulnerable_plugins_themes_check": True,  # Refers to Apps
            "dedicated_tool_recommendation": "Manual review of Shopify Apps and their known vulnerabilities. Check Shopify App Store reviews, developer reputation, and public vulnerability databases for installed apps."
        }
    },
    "security_headers_info": {
        "Strict-Transport-Security": "Instructs browsers to only connect via HTTPS. Check for 'max-age' (min 1 year recommended), 'includeSubDomains', and 'preload' for maximum effectiveness.",
        "Content-Security-Policy": "Controls resources the browser is allowed to load, mitigating XSS and data injection. Presence is key; policy strictness varies. Avoid 'unsafe-inline', 'unsafe-eval', and overly broad wildcards like '*'. Key directives: 'default-src', 'script-src', 'style-src', 'object-src', 'base-uri', 'frame-ancestors', 'form-action', 'report-uri'/'report-to'.",
        "Content-Security-Policy-Report-Only": "Allows experimenting with CSP. Issues are reported but not blocked. Useful for policy development before enforcement.",
        "X-Frame-Options": "Prevents clickjacking. Should be 'DENY' or 'SAMEORIGIN'. 'ALLOW-FROM uri' is deprecated. CSP 'frame-ancestors' directive is the modern, more flexible replacement.",
        "X-Content-Type-Options": "Prevents MIME-sniffing attacks. Should always be 'nosniff'.",
        "Referrer-Policy": "Controls how much referrer information is sent with requests. 'no-referrer', 'strict-origin-when-cross-origin', or 'same-origin' are good privacy-enhancing choices.",
        "Permissions-Policy": "Controls browser features available to the page (e.g., camera, microphone, geolocation). Presence and restrictive policies enhance security and user privacy. Replaces Feature-Policy.",
        "X-XSS-Protection": "Deprecated by modern browsers in favor of CSP. '1; mode=block' was its strongest setting. If present, ensure it's not '0' (disabled), though removal is generally preferred now.",
        "Set-Cookie": "Analyze for 'HttpOnly' (prevents JS access), 'Secure' (HTTPS only), 'SameSite' attributes (Strict or Lax for CSRF protection). Check 'Domain' and 'Path' for scope. 'Max-Age' or 'Expires' should manage cookie lifetime appropriately. Consider cookie prefixes like '__Secure-' and '__Host-'.",
        "Cross-Origin-Opener-Policy": "Protects against cross-origin attacks (e.g., XS-Leaks) by controlling how a document can interact with its opener's browsing context. 'same-origin' is a common strong value. 'same-origin-allow-popups' also exists.",
        "Cross-Origin-Embedder-Policy": "Controls embedding of cross-origin resources. 'require-corp' enables Cross-Origin Isolation, enhancing security by preventing certain cross-origin interactions. 'unsafe-none' is the default (permissive).",
        "Cross-Origin-Resource-Policy": "Controls how cross-origin resources can be requested from a given domain. 'same-origin' or 'same-site' are common to prevent data leakage. 'cross-origin' is permissive."
    },
    "wayback_machine_config": {
        "limit": 100,
        "fetch_current_status_for_interesting": True,
        "interesting_extensions": [
            ".bak", ".sql", ".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".csv",
            ".config", ".conf", ".cfg", ".ini", ".yml", ".yaml", ".json", ".xml", ".properties",
            ".env", ".pem", ".key", ".p12", ".pfx", ".p7b", ".cer", ".crt", ".der", ".asc",
            ".log", ".mdb", ".sqlite", ".db", ".txt", ".md", ".ini", ".inf",
            ".swp", ".swo", ".DS_Store", ".DS_STORE",
            ".old", ".orig", ".tmp", ".temp", ".bkp", ".save", ".bk", ".backup",
            ".psd", ".ai", ".indd", ".sketch",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
            ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".rb", ".py", ".java", ".class",
            ".sh", ".bash", ".ps1", ".bat",
            ".bak-", ".sql.gz", ".zip", ".tar", ".gz", ".old", ".backup", ".jar", ".war", ".ear", ".dll", ".exe"
        ],
        "interesting_keywords_in_path_or_query": [
            "admin", "login", "user", "account", "password", "passwd", "pwd", "credential", "secret", "token",
            "apikey", "api_key", "auth", "session", "jwt", "bearer", "sso", "oauth", "saml", "openid",
            "backup", "dump", "export", "import", "migrate", "archive", "sql", "database", "db_dump",
            "config", "setting", "parameter", "env", "environment", "local_settings",
            "debug", "trace", "log", "phpinfo", "server-status", "status", "info", "health", "metrics",
            "setup", "install", "test", "dev", "staging", "internal", "private", "confidential", "corp",
            "cgi-bin", "shell", "cmd", "exec", "console", "terminal",
            "upload", "download", "file", "include", "path", "dir", "browse", "directory", "ls", "tree",
            "payment", "checkout", "cart", "creditcard", "cvv", "billing", "invoice", "receipt", "order",
            "swagger", "openapi", "graphql", "graphiql", "playground", "api-docs", "wsdls",
            "jolokia", "actuator", "jmx-console",
            "jenkins", "jira", "confluence", "gitlab", "github", "bitbucket", "svn", "git", ".git",
            "id_rsa", "id_dsa", ".ssh", ".aws", ".gitconfig", "wp-config", "web.config", "local.xml",
            "user_id", "customer_id", "order_id", "ssn", "nid", "passport_id", "dob", "credit_score", "personal_info",
            "debug.log", "error.log", "access.log",
            "phpunit", "phpunit.xml", "docker-compose.yml", "Makefile", "Gemfile", "Procfile", "build.xml",
            "api/v1", "api/v2", "api/v3", "/_next/data/", "/.netlify/functions/",
            "elb-status", "remote_config", "security.txt", ".well-known",
            "crossdomain.xml", "clientaccesspolicy.xml", "sitemap.xml", "robots.txt",
            "params", "query", "redirect", "url", "next", "file", "filename", "path", "include", "page"
        ]
    },
    "crtsh_timeout_seconds": 35,
    "js_analysis_max_file_size_kb": 1536,
    "waf_signatures_headers": {
        "Cloudflare": ["Server: cloudflare", "CF-RAY:", "__cfduid=", "__cflb=", "cf_ob_info", "cf-challenge",
                       "cf-cache-status:", "expect-ct:", "cf-ipcountry:"],
        "AWS WAF/ALB/CloudFront": ["awselb", "x-amz-waf-", "AWSALB", "x-amz-cf-id", "X-Cache: Error from cloudfront",
                                   "X-Amz-Cf-Pop", "Via:.*cloudfront", "X-Amz-Function-Error"],
        "Akamai": ["X-Akamai-Transformed", "AkamaiGHost", "Akamai-IANONCE", "X-Cache: Akamai", "X-Akamai-Request-ID",
                   "X-CDN-Provider: Akamai"],
        "Sucuri": ["X-Sucuri-ID:", "X-Sucuri-Cache:", "Server: Sucuri", "x-sucuri-block", "X-Sucuri-Error"],
        "Wordfence": ["wfCookie", "wordfence_verifiedHuman", "X-Powered-By: Wordfence", "x-wordfence-", "wfvt_"],
        "Incapsula (Imperva)": ["X-Iinfo", "incap_ses_", "X-CDN: Imperva", "visid_incap_"],
        "F5 BIG-IP": ["TSxxxx", "BIGipServer", "F5 BIGIP", "Last-Modified:.*BIG-IP", "X-WA-Info", "X-PvInfo",
                      "F5_secure"],
        "Barracuda WAF": ["barra_counter_session=", "BNI__BARRACUDA_IPS", "BNI_persistence=", "Barracuda:"],
        "FortiWeb": ["FORTIWAFSID=", "X-Fortiweb-Httpauth-Error", "fortiloadbalancer", "FORTANALYTICSFORTIOS"],
        "Azure Application Gateway/WAF": ["ApplicationGatewayAffinity", "X-Azure-Ref", "X-AppGW-", "X-ASPNET-VERSION",
                                          "x-msedge-ref", "ARRaffinity"],
        "Google Cloud Armor/GFE": ["Via: 1.1 google", "Server: GFE", "Server: gws", "X-Google-"],
        "ModSecurity": ["Mod_Security", "mod_security", "X-Mod-Security-Action", "server:.*mod_security",
                        "Sec- dimiliki", "rules triggered"],
        "Signal Sciences (Fastly)": ["X-SigSci-RequestID", "X-SigSci-Tags", "Server: Signal Sciences Compute",
                                     "X-Protected-By: Signal Sciences"],
        "Wallarm": ["nginx-wallarm", "X-Wallarm-Instance", "X-Wallarm-Node"],
        "Citrix NetScaler/ADC": ["Cneonction: close", "citrixnsanalyticsprofile", "ns_af", "NSC_", "NS_PERS",
                                 "secure_client_session"],
        "Radware AppWall": ["X-SL-CompState", "X-Radware-AppWall-"],
        "DOSarrest": ["X-DISCORD", "Server: DOSarrest"],
        "StackPath (Highwinds/MaxCDN)": ["Server: StackPath_shield", "X-HW", "Server: NetDNA"],
        "Imperva SecureSphere": ["X-Imperva-Reputation", "Imperva_ visitesid"],
        "Sophos UTM/XG": ["Powered by Sophos", "SERVER: ZSK", "X-Sophos-Firewall"],
        "WatchGuard": ["Server: WatchGuard", "X-WatchGuard-"],
        "Palo Alto Networks": ["Server: Palo Alto Networks", "PA-HID", "PA-VID"],
        "NSFocus": ["NSFocus", "NSFocus-WAF"],
        "AliYunDun (Alibaba Cloud WAF)": ["aliyungf_tc", "AliyunDun"],
        "SafeDog (Chuangyu)": ["WAF/2.0", "Safedog"],
        "Wangsu (ChinaNetCenter)": ["X-Cache: Wangsu", "Powered-By-ChinaCache"]
    },
    "enable_nmap_scan": True,
    "enable_whois_lookup": True,
    "enable_subdomain_bruteforce": True,
    "enable_crtsh_subdomain_search": True,
    "enable_wayback_machine_scan": True,
    "enable_js_file_analysis": True,
    "enable_js_ast_analysis": True,
    "enable_error_page_analysis": True,
    "enable_waf_detection": True,
    "enable_ip_asn_lookup": True,
    "fuzzing_wordlist_file": "common_paths_fuzz.txt",
    "fuzzing_apply_common_extensions": [".php", ".html", ".htm", ".txt", ".bak", ".old", ".config", ".json", ".xml",
                                        ".log", ".aspx", ".asp", ".jsp", ".do", ".action", ".env", ".ini", ".yml",
                                        ".yaml", ".cgi", ".pl", ".secret", ".pem", ".key", ".zip", ".tar.gz", ".inc",
                                        ".conf", ".bak-", ".sql", ".md", ".csv", ".properties", ".dist", ".swp",
                                        ".original", ".backup"],
    "enable_directory_file_fuzzing": False,
    "external_api_keys": {
        "nvd_api_key": os.getenv("KAIROS_NVD_API_KEY", ""),
        "virustotal_api_key": os.getenv("KAIROS_VT_API_KEY", ""),
        "openai_api_key": os.getenv("KAIROS_OPENAI_API_KEY", ""),
        "deepseek_api_key": os.getenv("KAIROS_DEEPSEEK_API_KEY", "")
    },
    "enable_external_api_integrations": {
        "nvd": True,
        "virustotal": True,
        "openai_analysis": False,
        "deepseek_analysis": False
    },
    "llm_analysis_preference": ["openai", "deepseek"],
    "llm_analysis_tasks": {
        "explain_finding": {
            "enabled": True,
            "max_tokens": 400,
            "temperature": 0.2,
            "prompt_template": "You are a security analyst. Explain the KAIROS finding: Type: '{finding_type}', Description: '{finding_description}', Target: '{target_url}', Details: '{finding_details}'. Describe its potential security impact concisely and suggest a specific, actionable remediation step. Keep it brief and focused."
        },
        "suggest_remediation": {
            "enabled": False,  # Keep focused on explanation for now
            "max_tokens": 600,
            "temperature": 0.3,
            "prompt_template": "For the KAIROS finding: Type: {finding_type}, Description: {finding_description}, Severity: {severity}, Target: {target_url}, Details: {finding_details}. Provide detailed, step-by-step remediation guidance suitable for a technical audience. Consider common technologies if applicable."
        }
    },
    "nvd_api_config": {
        "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "results_per_page": 50,
        "request_delay_seconds": 6
    },
    "virustotal_api_config": {
        "base_url": "https://www.virustotal.com/api/v3",
        "domain_report_endpoint": "/domains/",
        "ip_report_endpoint": "/ip_addresses/",
        "url_report_endpoint": "/urls/",
        "request_delay_seconds": 15
    },
    "openai_api_config": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-3.5-turbo",
        "max_tokens_summary": 1000,
        "max_tokens_explanation": 500,
        "temperature": 0.3,
        "timeout_seconds": 120,
        "request_delay_seconds": 3
    },
    "deepseek_api_config": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        # Common model, user might need to change if they have access to other DeepSeek models
        "max_tokens_summary": 1000,
        "max_tokens_explanation": 500,
        "temperature": 0.3,
        "timeout_seconds": 120,
        "request_delay_seconds": 3
    }
}

CONFIG = {}

logger = logging.getLogger("KAIROS")
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d (%(funcName)s)] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
if not logger.hasHandlers():
    logger.addHandler(console_handler)


def load_config():
    global CONFIG
    if os.path.exists(CONFIG_FILE_NAME):
        try:
            with open(CONFIG_FILE_NAME, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            CONFIG = DEFAULT_CONFIG.copy()

            def recursive_update(d, u):
                for k_item, v_item in u.items():
                    if isinstance(v_item, dict) and isinstance(d.get(k_item), dict):
                        d[k_item] = recursive_update(d.get(k_item, {}), v_item)
                    else:
                        d[k_item] = v_item
                return d

            CONFIG = recursive_update(CONFIG, user_config)
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

    # Enhanced API key and integration enabling logic
    for api_key_config_name, default_api_key_val in CONFIG["external_api_keys"].items():  # e.g., "nvd_api_key"
        env_var_name = f"KAIROS_{api_key_config_name.upper()}"  # e.g., KAIROS_NVD_API_KEY
        env_val = os.getenv(env_var_name)

        # Prioritize environment variable if set and config file key is empty
        if env_val and not default_api_key_val:
            CONFIG["external_api_keys"][api_key_config_name] = env_val
            logger.info(f"Loaded {api_key_config_name} from environment variable {env_var_name}.")

        # Determine service name (e.g., "nvd", "virustotal", "openai", "deepseek")
        service_name = api_key_config_name.replace('_api_key', '')

        current_api_key_for_service = CONFIG["external_api_keys"].get(api_key_config_name)

        if service_name in CONFIG["enable_external_api_integrations"]:
            if current_api_key_for_service:  # If key is present (from file or ENV)
                if not CONFIG["enable_external_api_integrations"][service_name]:
                    logger.info(f"API key found for {service_name}, automatically enabling this integration.")
                    CONFIG["enable_external_api_integrations"][service_name] = True
                # else: already enabled, key present - good.
            else:  # No key found for this service
                if CONFIG["enable_external_api_integrations"][service_name]:
                    logger.warning(
                        f"{service_name.capitalize()} integration was enabled in config, but no API key ('{api_key_config_name}') was found. Disabling {service_name} integration.")
                    CONFIG["enable_external_api_integrations"][service_name] = False
                # else: already disabled, no key - expected.

    subdomain_file_path = CONFIG.get("common_subdomains_file", "common_subdomains.txt")
    if os.path.exists(subdomain_file_path):
        try:
            with open(subdomain_file_path, 'r', encoding='utf-8') as f_subs:
                loaded_subdomains = [line.strip() for line in f_subs if line.strip() and not line.startswith('#')]
                CONFIG["common_subdomains"] = sorted(list(set(loaded_subdomains)))
            logger.info(f"Loaded {len(CONFIG['common_subdomains'])} unique subdomains from {subdomain_file_path}")
        except Exception as e:
            logger.warning(f"Could not load subdomains from {subdomain_file_path}: {e}. Using default list.")
            CONFIG["common_subdomains"] = CONFIG.get("default_common_subdomains", []).copy()
    else:
        logger.info(f"Subdomain file {subdomain_file_path} not found. Using default list.")
        CONFIG["common_subdomains"] = CONFIG.get("default_common_subdomains", []).copy()

    CONFIG["dns_records_to_query"] = sorted(list(set(CONFIG.get("dns_records_to_query", []))))


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

    if 'severity' not in finding_data: finding_data['severity'] = 'Unknown'
    if 'confidence' not in finding_data: finding_data['confidence'] = 'Medium'

    sig_parts = [
        finding_data.get("type"),
        finding_data.get("description", str(finding_data.get("details", {}))[:100]),
        finding_data.get("target_url"),
    ]
    details_data_sig = finding_data.get("details", {}) if isinstance(finding_data.get("details"), dict) else {}

    if finding_data.get("type") == "Sensitive Data Exposure":
        sig_parts.extend([details_data_sig.get("key_name"), details_data_sig.get("source_js_url"),
                          details_data_sig.get("matched_value_preview"), str(details_data_sig.get("line"))])
    elif finding_data.get("type") in ["API Endpoint Exposed", "API Component Exposed",
                                      "API Security Concern (Specification)"]:  # Added new type
        sig_parts.append(details_data_sig.get("url", finding_data.get("target_url")))
        sig_parts.append(details_data_sig.get("api_type", details_data_sig.get("api_spec_url")))  # For spec url
        if details_data_sig.get("endpoints_without_security"):  # For spec issues
            sig_parts.append(str(details_data_sig.get("endpoints_without_security")[:1]))
    elif finding_data.get("type") == "JS AST Finding":
        sig_parts.extend([details_data_sig.get("js_url"), details_data_sig.get("finding_type"),
                          str(details_data_sig.get("code_snippet", ""))[:50], str(details_data_sig.get("line"))])
    elif finding_data.get("type") == "Fuzzed Path Discovery":
        sig_parts.append(details_data_sig.get("path"))
        sig_parts.append(str(details_data_sig.get("status")))
    elif finding_data.get("type") == "CMS Path Accessible":
        sig_parts.append(finding_data.get("path", details_data_sig.get("path")))
    elif finding_data.get("type") == "Software Version Information":
        sig_parts.extend([details_data_sig.get("software"), details_data_sig.get("version")])
    elif finding_data.get("type") == "AI-Powered Insight & Summary":
        sig_parts.append(str(details_data_sig.get("summary_hash"))[:50])
    elif finding_data.get("type") == "AI-Powered Finding Explanation":
        sig_parts.append(details_data_sig.get("original_finding_type"))
        sig_parts.append(details_data_sig.get("original_finding_target"))
        sig_parts.append(str(details_data_sig.get("ai_explanation"))[:50])
    else:
        sig_parts.append(str(finding_data.get("evidence_summary", details_data_sig.get("evidence", details_data_sig.get(
            "matched_snippet", ""))))[:100])

    new_finding_signature_tuple = tuple(str(p) for p in sig_parts if p is not None)
    is_duplicate = False

    for existing_finding_idx, existing_finding in enumerate(results_dict[category]):
        existing_sig_parts = [
            existing_finding.get("type"),
            existing_finding.get("description", str(existing_finding.get("details", {}))[:100]),
            existing_finding.get("target_url"),
        ]
        existing_details_sig = existing_finding.get("details", {}) if isinstance(existing_finding.get("details"),
                                                                                 dict) else {}

        if existing_finding.get("type") == "Sensitive Data Exposure":
            existing_sig_parts.extend([existing_details_sig.get("key_name"), existing_details_sig.get("source_js_url"),
                                       existing_details_sig.get("matched_value_preview"),
                                       str(existing_details_sig.get("line"))])
        elif existing_finding.get("type") in ["API Endpoint Exposed", "API Component Exposed",
                                              "API Security Concern (Specification)"]:
            existing_sig_parts.append(existing_details_sig.get("url", existing_finding.get("target_url")))
            existing_sig_parts.append(existing_details_sig.get("api_type", existing_details_sig.get("api_spec_url")))
            if existing_details_sig.get("endpoints_without_security"):
                existing_sig_parts.append(str(existing_details_sig.get("endpoints_without_security")[:1]))
        elif existing_finding.get("type") == "JS AST Finding":
            existing_sig_parts.extend([existing_details_sig.get("js_url"), existing_details_sig.get("finding_type"),
                                       str(existing_details_sig.get("code_snippet", ""))[:50],
                                       str(existing_details_sig.get("line"))])
        elif existing_finding.get("type") == "Fuzzed Path Discovery":
            existing_sig_parts.append(existing_details_sig.get("path"))
            existing_sig_parts.append(str(existing_details_sig.get("status")))
        elif existing_finding.get("type") == "CMS Path Accessible":
            existing_sig_parts.append(existing_finding.get("path", existing_details_sig.get("path")))
        elif existing_finding.get("type") == "Software Version Information":
            existing_sig_parts.extend([existing_details_sig.get("software"), existing_details_sig.get("version")])
        elif existing_finding.get("type") == "AI-Powered Insight & Summary":
            existing_sig_parts.append(str(existing_details_sig.get("summary_hash"))[:50])
        elif existing_finding.get("type") == "AI-Powered Finding Explanation":
            existing_sig_parts.append(existing_details_sig.get("original_finding_type"))
            existing_sig_parts.append(existing_details_sig.get("original_finding_target"))
            existing_sig_parts.append(str(existing_details_sig.get("ai_explanation"))[:50])
        else:
            existing_sig_parts.append(str(existing_finding.get("evidence_summary", existing_details_sig.get("evidence",
                                                                                                            existing_details_sig.get(
                                                                                                                "matched_snippet",
                                                                                                                ""))))[
                                      :100])

        existing_finding_signature_tuple_comp = tuple(str(p) for p in existing_sig_parts if p is not None)

        if new_finding_signature_tuple == existing_finding_signature_tuple_comp:
            is_duplicate = True
            current_severity_val = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}
            current_confidence_val = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}  # Confirmed not really used yet

            updated_finding = existing_finding.copy()

            if current_severity_val.get(finding_data['severity'].upper(), -1) > current_severity_val.get(
                    updated_finding['severity'].upper(), -1):
                updated_finding['severity'] = finding_data['severity']
            if current_confidence_val.get(finding_data['confidence'], 0) > current_confidence_val.get(
                    updated_finding.get('confidence', 'Low'), 0):
                updated_finding['confidence'] = finding_data['confidence']

            if isinstance(updated_finding.get('details'), dict) and isinstance(finding_data.get('details'), dict):
                def deep_merge_dicts(base_dict, new_dict_data):
                    for k_merge, v_merge in new_dict_data.items():
                        if k_merge in base_dict and isinstance(base_dict[k_merge], dict) and isinstance(v_merge, dict):
                            deep_merge_dicts(base_dict[k_merge], v_merge)
                        elif k_merge in base_dict and isinstance(base_dict[k_merge], list) and isinstance(v_merge,
                                                                                                          list):
                            base_dict[k_merge] = list(set(base_dict[k_merge] + v_merge))
                        else:
                            base_dict[k_merge] = v_merge
                    return base_dict

                updated_finding['details'] = deep_merge_dicts(updated_finding['details'], finding_data['details'])
            elif 'details' in finding_data:
                updated_finding['details'] = finding_data['details']

            if 'recommendation' in finding_data and finding_data['recommendation'] and \
                    (not updated_finding.get('recommendation') or len(finding_data['recommendation']) > len(
                        updated_finding.get('recommendation', ''))):
                updated_finding['recommendation'] = finding_data['recommendation']

            # If new finding has AI explanation and old one doesn't, or new one is more recent
            if 'ai_explanation' in finding_data and (not updated_finding.get('ai_explanation') or
                                                     (isinstance(finding_data['ai_explanation'], dict) and isinstance(
                                                         updated_finding.get('ai_explanation'), dict) and
                                                      finding_data['ai_explanation'].get('timestamp', '') >
                                                      updated_finding['ai_explanation'].get('timestamp', ''))):
                updated_finding['ai_explanation'] = finding_data['ai_explanation']

            results_dict[category][existing_finding_idx] = updated_finding
            break

    if not is_duplicate:
        results_dict[category].append(finding_data)

    if log_message:
        log_level_attr = getattr(logging, severity_for_log.upper(), logging.INFO)
        # Log if not duplicate, or if it's a correlation/AI summary finding (these are often aggregates)
        if not is_duplicate or category == "correlated_intelligence" or finding_data.get("type", "").startswith(
                "AI-Powered"):
            logger.log(log_level_attr, f"{generate_severity_tag(severity_for_log)} {log_message}")


def format_report_section(title: str, data: dict | list | str | None, indent_level: int = 0) -> str:
    indent = "  " * indent_level
    section_str = f"{indent}--- {title} ---\n"
    if data is None:
        section_str += f"{indent}  N/A\n"
    elif isinstance(data, str):
        section_str += "".join([f"{indent}  {html.unescape(line)}\n" for line in data.strip().splitlines()])
    elif isinstance(data, list):
        if not data:
            section_str += f"{indent}  None found.\n"
        else:
            for item_idx, item in enumerate(data):
                if isinstance(item, dict):
                    section_str += f"{indent}  - "
                    details_list = []
                    summary_keys = ['type', 'description', 'severity', 'confidence', 'path', 'url', 'name', 'subdomain',
                                    'finding_type', 'function_name', 'sink_property', 'key_name', 'endpoint_or_info',
                                    'software', 'version', 'port', 'service', 'cve_id', 'vt_score', 'id',
                                    'title', 'source_llm', 'source', 'original_finding_type']  # Added more keys
                    present_summary_keys = [k_sum for k_sum in summary_keys if
                                            k_sum in item and item[k_sum] is not None]
                    other_keys = [k_item for k_item in item if
                                  k_item not in present_summary_keys and k_item not in ['details', 'recommendation',
                                                                                        'search_links', 'nvd_cves',
                                                                                        'virustotal_report',
                                                                                        'attributes', 'ai_explanation']]

                    for k_item in present_summary_keys + other_keys:
                        v_item = item[k_item]
                        v_str = str(v_item)
                        if k_item == "details" and isinstance(v_item, dict):
                            v_str = "... (see nested details below)" if v_item else "N/A"
                        elif isinstance(v_item, list) and len(v_item) > 3 and not (
                                all(isinstance(x, str) for x in v_item) and sum(len(x) for x in v_item) < 100):
                            v_str = f"List ({len(v_item)} items) - First 3: {', '.join(map(str, v_item[:3]))}..."
                        elif isinstance(v_item, str) and len(v_item) > 150:
                            v_str = v_item[:147] + "..."
                        details_list.append(f"{k_item.replace('_', ' ').title()}: {html.unescape(v_str)}")
                    section_str += ", ".join(details_list) + "\n"

                    if 'details' in item and isinstance(item['details'], dict) and item['details']:
                        if item.get("type", "").startswith("AI-Powered Insight") and 'full_ai_response' in item[
                            'details']:
                            section_str += f"{indent}    Full AI Response:\n"
                            for line in str(item['details']['full_ai_response']).splitlines():
                                section_str += f"{indent}      {html.unescape(line)}\n"
                            if 'prompt_sent_preview' in item['details']:
                                section_str += f"{indent}    AI Prompt Preview:\n"
                                for line in str(item['details']['prompt_sent_preview']).splitlines():
                                    section_str += f"{indent}      {html.unescape(line)}\n"
                        elif item.get("type", "").startswith("AI-Powered Finding Explanation") and 'ai_explanation' in \
                                item['details']:
                            section_str += f"{indent}    AI Explanation:\n"
                            for line in str(item['details']['ai_explanation']).splitlines():
                                section_str += f"{indent}      {html.unescape(line)}\n"
                        else:
                            section_str += format_report_section("Details", item['details'], indent_level + 2)

                    if 'ai_explanation' in item and isinstance(item['ai_explanation'], dict) and item[
                        'ai_explanation'].get('explanation'):
                        section_str += f"{indent}    AI Explanation ({item['ai_explanation'].get('llm_provider', 'LLM')}):\n"
                        for line in str(item['ai_explanation']['explanation']).splitlines():
                            section_str += f"{indent}      {html.unescape(line)}\n"

                    if 'attributes' in item and isinstance(item['attributes'], dict) and item[
                        'attributes'] and item.get('type') == 'domain':
                        section_str += format_report_section("VirusTotal Attributes", item['attributes'],
                                                             indent_level + 2)

                    if 'nvd_cves' in item and item['nvd_cves']:
                        section_str += format_report_section("NVD CVEs", item['nvd_cves'], indent_level + 2)
                    if 'virustotal_report' in item and item['virustotal_report'] and isinstance(
                            item['virustotal_report'], dict):
                        vt_summary = {
                            "id": item['virustotal_report'].get('id'),
                            "type": item['virustotal_report'].get('type'),
                            "last_analysis_stats": item['virustotal_report'].get('attributes', {}).get(
                                'last_analysis_stats')
                        }
                        section_str += format_report_section("VirusTotal Summary", vt_summary, indent_level + 2)
                    if 'search_links' in item and isinstance(item['search_links'], dict) and item['search_links']:
                        section_str += f"{indent}    Search Links:\n"
                        for db_name, link_url in item['search_links'].items():
                            section_str += f"{indent}      {db_name}: {link_url}\n"
                    if 'recommendation' in item and item['recommendation']:
                        section_str += f"{indent}    Recommendation: {html.unescape(str(item['recommendation']))}\n"
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
                        section_str += format_report_section("", value, indent_level + 1)
                        continue
                    else:
                        val_str = (', '.join(map(lambda x_item: html.unescape(str(x_item)), value)))
                    section_str += f"{indent}  {key_title}: {val_str}\n"
                elif isinstance(value, dict):
                    section_str += f"{indent}  {key_title}:\n"
                    section_str += format_report_section("", value, indent_level + 1)
                else:
                    section_str += f"{indent}  {key_title}: {html.unescape(str(value)) if value is not None else 'N/A'}\n"
    return section_str + "\n"


def generate_vuln_search_url(software_name, version=None):
    query_parts = [software_name.strip()]
    if version and str(version).strip() and str(version).strip().lower() not in ["unknown", "n/a"]:
        query_parts.append(str(version).strip())
    query = " ".join(query_parts)
    query_plus = quote_plus(query)
    sw_name_plus = quote_plus(software_name.strip())
    ver_plus = quote_plus(str(version).strip()) if version and str(version).strip().lower() not in ["unknown",
                                                                                                    "n/a"] else ""

    return {
        "Vulners": f"https://vulners.com/search?query={query_plus}",
        "CVE Mitre": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query_plus}",
        "NIST NVD": f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query={query_plus}&search_type=all",
        "Exploit-DB": f"https://www.exploit-db.com/search?q={sw_name_plus}{('+' + ver_plus) if ver_plus else ''}",
        "GitHub Advisories": f"https://github.com/advisories?query={query_plus}",
        "Packet Storm": f"https://packetstormsecurity.com/search/?q={query_plus}"
    }


class SiteScanner:
    def __init__(self, target_url: str, user_config_overrides: dict | None = None):
        self.raw_target_url = target_url
        self.config = CONFIG.copy()
        if user_config_overrides:
            def recursive_update(d, u):
                for k, v in u.items():
                    if isinstance(v, dict) and isinstance(d.get(k), dict):
                        d[k] = recursive_update(d.get(k, {}), v)
                    else:
                        d[k] = v
                return d

            self.config = recursive_update(self.config, user_config_overrides)

        parsed_initial_url = urlparse(target_url)
        self.scheme = parsed_initial_url.scheme.lower() if parsed_initial_url.scheme else ""
        self.domain = parsed_initial_url.netloc.lower().split(':')[0]
        self.port = parsed_initial_url.port

        if not self.scheme:
            logger.warning(f"No scheme provided for {target_url}. Assuming 'http'. Will attempt HTTPS first.")
            self.scheme = "http"

        if not self.domain:
            if parsed_initial_url.path and not parsed_initial_url.netloc:
                path_parts = parsed_initial_url.path.lstrip('/').split('/', 1)
                self.domain = path_parts[0].lower()
                path_remainder = f"/{path_parts[1]}" if len(path_parts) > 1 else ""
                self.target_url = f"{self.scheme}://{self.domain}{path_remainder}"
                logger.info(f"Extracted domain '{self.domain}' from path. Assuming target is {self.target_url}")
            else:
                raise ValueError("Invalid target URL: Could not determine domain.")
        else:
            self.target_url = f"{self.scheme}://{self.domain}"
            if self.port and not (
                    (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)):
                self.target_url += f":{self.port}"
            base_path_for_join = self.target_url
            if parsed_initial_url.path:
                if not base_path_for_join.endswith('/') and not parsed_initial_url.path.startswith('/'):
                    base_path_for_join += "/"
            self.target_url = urljoin(base_path_for_join, parsed_initial_url.path)
            if parsed_initial_url.query: self.target_url += f"?{parsed_initial_url.query}"
            if parsed_initial_url.fragment: self.target_url += f"#{parsed_initial_url.fragment}"

        self.results: dict = {
            "scan_metadata": {"target_input": self.raw_target_url, "target_normalized": self.target_url,
                              "effective_domain": self.domain, "start_time": None, "end_time": None,
                              "scanner_version": self.config["scanner_version"],
                              "llm_preference": self.config.get("llm_analysis_preference", [])},
            "general_info": {"ip_addresses": [], "final_url": self.target_url, "server_location_guess": None,
                             "ip_asn_info": {}, "domain_reputation_vt": None},
            "http_details": {"status_code_final": None, "http_version": None, "headers_final": {},
                             "security_headers_analysis": {}, "cookies_set": [], "allowed_methods": [],
                             "redirect_chain": []},
            "dns_information": {"records": {}, "dnssec_status": "Unknown", "mail_servers_config": {},
                                "whois_data": None,
                                "wildcard_dns_analysis": {"detected": False, "evidence": "Not fully tested or N/A"}},
            "technology_fingerprint": {"server_software": [], "x_powered_by": [], "cms_identified": None,
                                       "frameworks_libraries": [], "analytics_trackers": [], "cdn_providers": [],
                                       "programming_languages_detected": [], "operating_system_guesses": [],
                                       "version_control_type": None, "wappalyzer_findings": [],
                                       "software_versions_found": {}, "error_page_fingerprints": [],
                                       "waf_detected": []},
            "content_analysis": {"robots_txt_content": None, "sitemap_urls_found": [], "page_title": None,
                                 "meta_description": None, "meta_keywords": None, "developer_comments_found": [],
                                 "emails_on_page": [], "phone_numbers_on_page": [], "social_media_links_on_page": [],
                                 "internal_links_count": 0, "external_links_count": 0, "suspected_api_keys": [],
                                 "linked_documents": [], "forms_found_count": 0,
                                 "javascript_files": {"count": 0, "files": [], "analysis_summary": [],
                                                      "ast_findings": []},
                                 "css_files_count": 0,
                                 "archived_urls": {"fetched_count": 0, "sample": [],
                                                   "interesting_historical_paths_status": []},
                                 "ads_txt_content": None, "app_ads_txt_content": None},
            "security_posture": {"open_ports": [], "ssl_tls_config": {}, "vulnerability_findings": [],
                                 "malware_code_signatures": [], "exposed_git_details": None,
                                 "exposed_svn_details": None, "exposed_mercurial_details": None,
                                 "exposed_bazaar_details": None, "exposed_sensitive_files": [],
                                 "directory_listings_found": [], "security_txt_contents": None, "http_auth_type": None,
                                 "potential_api_endpoints": [], "fuzzed_paths_found": [],
                                 "external_api_analysis_summary": {"nvd_checks_performed": 0, "nvd_cves_found_total": 0,
                                                                   "virustotal_checks_performed": 0,
                                                                   "virustotal_detections": 0,
                                                                   "llm_analysis_status": {}}},
            "subdomain_discovery": {"discovered_subdomains": [],
                                    "subdomain_verification_methodology": "Initial HEAD/GET, advanced check if wildcard suspected."},
            "cms_specific_findings": {},
            "correlated_intelligence": []
        }
        self.session: aiohttp.ClientSession | None = None
        self.user_agent = self.config["default_user_agent"]
        self.request_timeout = aiohttp.ClientTimeout(total=self.config["request_timeout_seconds"])
        self.semaphore = asyncio.Semaphore(self.config["max_concurrent_requests"])
        self._main_page_response_cache: tuple[aiohttp.ClientResponse, bytes] | None = None
        self._main_page_html_cache: str | None = None
        self._main_page_soup_cache: BeautifulSoup | None = None
        self._main_page_title_cache: str | None = None
        self._baseline_404_response_cache: tuple[aiohttp.ClientResponse | None, bytes | None, str | None] = (None, None,
                                                                                                             None)
        self._robots_txt_cache: str | None = None
        self._fetched_js_urls: set[str] = set()
        self._sitemap_processing_queue: asyncio.Queue[str] = asyncio.Queue()
        self._processed_sitemap_urls: set[str] = set()
        self._last_nvd_api_call_time = 0
        self._last_vt_api_call_time = 0
        self._last_llm_api_call_time: dict[str, float] = {}
        logger.info(f"KAIROS initialized for target: {self.target_url}")

    async def __aenter__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.config["max_concurrent_requests"] * 2,
                                         limit_per_host=self.config["max_concurrent_requests"], force_close=True,
                                         enable_cleanup_closed=True)
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
                            timeout_override=None, **kwargs) -> tuple[aiohttp.ClientResponse | None, bytes | None]:
        full_url = url
        if not url.startswith(("http://", "https://")):
            base_for_join = self.results["general_info"].get("final_url", self.target_url)
            if not base_for_join.endswith('/') and not url.startswith('/'):
                base_for_join += '/'
            full_url = urljoin(base_for_join, url)

        retries = 0
        current_timeout = timeout_override if timeout_override is not None else self.request_timeout

        while retries <= max_retries:
            async with self.semaphore:
                if not self.session or self.session.closed:
                    logger.error("Session is closed or uninitialized. Cannot make request.")
                    return None, None
                try:
                    logger.debug(f"Requesting ({method}): {full_url} (Attempt: {retries + 1})")
                    async with self.session.request(method, full_url, allow_redirects=allow_redirects,
                                                    timeout=current_timeout, **kwargs) as response:
                        is_main_target_related_request = (
                                    full_url == self.target_url or full_url == self.results["general_info"].get(
                                "final_url"))
                        if is_main_target_related_request and response.history:
                            self.results["http_details"]["redirect_chain"] = [str(r.url) for r in response.history]
                            self.results["http_details"]["redirect_chain"].append(str(response.url))

                        content_bytes = await response.read()
                        return response, content_bytes
                except aiohttp.ClientConnectorCertificateError as e:
                    logger.warning(
                        f"SSL Certificate error for {full_url}: {e.os_error if hasattr(e, 'os_error') else e}")
                    if full_url == self.results["general_info"].get("final_url", self.target_url):
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue",
                                     "description": f"SSL Certificate error: {e.os_error if hasattr(e, 'os_error') else e}",
                                     "target_url": full_url, "severity": "Medium", "confidence": "High",
                                     "evidence_summary": str(e),
                                     "recommendation": "Ensure the SSL certificate is valid, trusted, and correctly configured for the hostname."},
                                    log_message=f"SSL Certificate error at {full_url}", severity_for_log="MEDIUM")
                    return None, None
                except aiohttp.ClientConnectorDNSError as e:
                    logger.warning(
                        f"DNS resolution error for {full_url}: {type(e).__name__} - {e.os_error if hasattr(e, 'os_error') else e}")
                except aiohttp.ClientConnectorError as e:
                    logger.warning(
                        f"Connection error for {full_url}: {type(e).__name__} - {e.os_error if hasattr(e, 'os_error') else e}")
                except aiohttp.ClientResponseError as e:
                    logger.warning(f"HTTP error {e.status} for {full_url}: {e.message}")
                    try:
                        content_bytes_err = await e.response.read() if hasattr(e, 'response') and e.response else b""
                    except Exception:
                        content_bytes_err = b""
                    return e.response if hasattr(e, 'response') else None, content_bytes_err
                except asyncio.TimeoutError:
                    timeout_total_seconds = current_timeout.total if hasattr(current_timeout, 'total') else self.config[
                        "request_timeout_seconds"]
                    logger.warning(f"Timeout during request to {full_url} (Timeout: {timeout_total_seconds}s)")
                except Exception as e:
                    logger.error(f"Unexpected error during request to {full_url}: {type(e).__name__} - {e}",
                                 exc_info=False)

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
            logger.info(f"Initial scheme is HTTP. Probing HTTPS endpoint: {https_target}")
            probe_timeout = aiohttp.ClientTimeout(total=10)
            response_https, content_bytes_https = await self._make_request(https_target, timeout_override=probe_timeout,
                                                                           allow_redirects=True, max_retries=0)

            if response_https and response_https.status < 400 and content_bytes_https is not None:
                logger.info(f"HTTPS probe successful for {str(response_https.url)}. Updating target to use HTTPS.")
                self.target_url = str(response_https.url)
                self.scheme = urlparse(self.target_url).scheme.lower()
                self.port = urlparse(self.target_url).port
                self.results["scan_metadata"]["target_normalized"] = self.target_url
            else:
                status_msg = f" (Status: {response_https.status})" if response_https else " (No response or connection error)"
                logger.info(
                    f"HTTPS probe for {https_target} failed or non-2xx/3xx{status_msg}. Sticking with {initial_target}.")

        response, content_bytes = await self._make_request(self.target_url)

        if not response or content_bytes is None:
            logger.error(f"Failed to fetch main page for {self.target_url}. Critical for many scans.")
            await self.gather_ip_addresses_and_asn()  # Still try to get IP info
            return False

        self._main_page_response_cache = (response, content_bytes)
        self.results["general_info"]["final_url"] = str(response.url)
        self.results["http_details"]["status_code_final"] = response.status
        self.results["http_details"][
            "http_version"] = f"{response.version.major}.{response.version.minor}" if response.version else "Unknown"
        self.results["http_details"]["headers_final"] = dict(response.headers)

        final_domain_parsed = urlparse(str(response.url))
        final_domain_netloc = final_domain_parsed.netloc.lower().split(':')[0]
        if final_domain_netloc and final_domain_netloc != self.domain:
            logger.info(f"Effective domain changed by redirect: {self.domain} -> {final_domain_netloc}")
            self.domain = final_domain_netloc
            self.results["scan_metadata"]["effective_domain"] = self.domain

        self.scheme = final_domain_parsed.scheme.lower()
        self.port = final_domain_parsed.port

        try:
            charset = response.charset if response.charset else 'utf-8'
            self._main_page_html_cache = content_bytes.decode(charset, errors='replace')
        except UnicodeDecodeError:
            logger.warning(
                f"UnicodeDecodeError for main page with charset {response.charset or 'unknown'}. Trying 'latin-1'.")
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
                title_tag = self._main_page_soup_cache.find("title")
                self._main_page_title_cache = title_tag.string.strip() if title_tag and title_tag.string else ""
                logger.info(
                    f"Successfully fetched and parsed main page: {self.results['general_info']['final_url']} (Status: {response.status}, Title: '{self._main_page_title_cache[:50]}...')")
            except Exception as e_soup:
                logger.error(f"BeautifulSoup failed to parse main page HTML: {e_soup}")
                self._main_page_soup_cache = None
                self._main_page_title_cache = None
                return response.status < 400
        else:
            logger.error("Main page HTML content could not be decoded or is empty.")
            self._main_page_soup_cache = None
            self._main_page_title_cache = None
            return response.status < 400

        random_404_path = f"/kairos_test_404_{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}.html_or_nonexistent_resource"
        resp_404, content_404 = await self._make_request(
            urljoin(self.results["general_info"]["final_url"], random_404_path), max_retries=0)
        if resp_404 and content_404:
            try:
                soup_404 = BeautifulSoup(content_404.decode(resp_404.charset or 'utf-8', errors='replace'),
                                         'html.parser')
                title_404_tag = soup_404.find("title")
                title_404_str = title_404_tag.string.strip() if title_404_tag and title_404_tag.string else ""
                self._baseline_404_response_cache = (resp_404, content_404, title_404_str)
                logger.info(f"Fetched baseline 404 (Status: {resp_404.status}, Title: '{title_404_str}')")
            except Exception as e_404_parse:
                logger.warning(f"Could not fully parse baseline 404 page: {e_404_parse}")
                self._baseline_404_response_cache = (resp_404, content_404, "")
        return True

    async def run_full_scan(self):
        logger.info(
            f"Starting KAIROS Quantum Oracle scan for {self.raw_target_url} (Initial Normalized: {self.target_url})...")
        if not await self.fetch_and_cache_main_page():
            logger.critical(f"Aborting full scan: Could not fetch or parse the main target page {self.target_url}.")
            if self.config.get("enable_whois_lookup", True) and WHOIS_CORRECT_LIB:
                await self.gather_whois_information()
            await self.gather_dns_information()
            if self.config.get("enable_nmap_scan", True) and NMAP_AVAILABLE and self.results["general_info"][
                "ip_addresses"]:
                await self.scan_for_open_ports()
            await self.run_external_api_integrations()
            await self.run_llm_analysis_tasks()
            await self.correlate_findings()
            return

        logger.info(
            f"Effective target for scan (after HTTPS probe/redirects): {self.results['general_info']['final_url']}")
        logger.info(f"Effective domain for DNS/Subdomain checks: {self.domain}")

        logger.info("--- Stage: Core Information Gathering ---")
        core_tasks = [
            self.gather_ip_addresses_and_asn(),
            self.gather_dns_information(),
            self.analyze_http_response_details(),
            self.fingerprint_technologies(),
            self.analyze_web_content(),
            self.fetch_and_analyze_robots_txt(),
            self.fetch_ads_txt_files(),
            self.discover_and_fetch_sitemaps(),
            self.perform_ssl_tls_analysis(),
            self.check_http_options_and_auth(),
        ]
        if self.config.get("enable_whois_lookup", True) and WHOIS_CORRECT_LIB:
            core_tasks.append(self.gather_whois_information())
        if self.config.get("enable_wayback_machine_scan", True) and REQUESTS_AVAILABLE:
            core_tasks.append(self.fetch_wayback_urls_and_check_live_status())
        if self.config.get("enable_error_page_analysis", True):
            core_tasks.append(self.analyze_common_error_pages())

        await self._execute_task_group(core_tasks, "Core Info Gathering")
        await self._process_sitemap_queue_iteratively()  # Ensure sitemap queue is processed after initial discovery

        logger.info("--- Stage: Security-Oriented Scans ---")
        security_tasks = [
            self.scan_for_exposed_paths_and_files(),
            self.check_for_version_control_exposure(),
            self.scan_page_for_malware_signatures(self._main_page_html_cache, self.results["general_info"]["final_url"],
                                                  "HTML Content"),
            self.conduct_basic_vulnerability_checks(),
            self.fetch_and_analyze_security_txt(),
            self.discover_api_endpoints()
        ]
        if self.config.get("enable_nmap_scan", True) and NMAP_AVAILABLE:
            security_tasks.append(self.scan_for_open_ports())
        else:
            if not NMAP_AVAILABLE:
                logger.info("Nmap library not available, skipping port scan.")
            else:
                logger.info("Nmap scan disabled in configuration, skipping port scan.")
            self.results["security_posture"]["open_ports"] = [
                {"status": "Skipped - Nmap library not found or scan disabled."}]

        if self.config.get("enable_js_file_analysis", True):
            security_tasks.append(self.analyze_linked_javascript_files())

        if self.config.get("enable_directory_file_fuzzing", False):
            security_tasks.append(self.fuzz_common_paths())

        await self._execute_task_group(security_tasks, "Security Scans")

        logger.info("--- Stage: Enumeration ---")
        enumeration_tasks = [self.enumerate_and_verify_subdomains()]
        await self._execute_task_group(enumeration_tasks, "Enumeration")

        logger.info("--- Stage: External API Integrations (Post-Enumeration) ---")
        await self.run_external_api_integrations()

        logger.info("--- Stage: Contextual & CMS-Specific Scans ---")
        await self.run_cms_specific_scans_if_detected()

        logger.info("--- Stage: AI-Powered Analysis (LLM) ---")
        await self.run_llm_analysis_tasks()  # Unified LLM analysis

        logger.info("--- Stage: Correlating Intelligence ---")
        await self.correlate_findings()

        logger.info(f"KAIROS Quantum Oracle scan completed for {self.results['general_info']['final_url']}.")

    async def _execute_task_group(self, tasks: list, group_name: str):
        logger.info(f"Starting task group: {group_name} ({len(tasks)} tasks)")
        valid_tasks = [task for task in tasks if task is not None]
        if not valid_tasks:
            logger.info(f"No tasks to execute in group: {group_name}")
            return

        try:
            await async_tqdm.gather(
                *valid_tasks,
                desc=group_name,
                unit="task",
                leave=False,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]'
            )
        except Exception as e:
            logger.error(
                f"An unhandled exception occurred in task group '{group_name}'. Error: {type(e).__name__} - {e}",
                exc_info=True)
            self.results[
                f"error_in_group_{group_name.replace(' ', '_').lower()}"] = f"Task group failed: {type(e).__name__} - {e}"

    async def gather_ip_addresses_and_asn(self):
        current_domain_to_resolve = self.results["scan_metadata"].get("effective_domain", self.domain)
        if not current_domain_to_resolve:
            logger.error("Cannot gather IPs/ASN: No valid effective domain identified.")
            self.results["general_info"]["ip_addresses"] = [{"error": "No valid domain for IP resolution."}]
            return

        logger.info(f"Resolving IP addresses and fetching ASN info for {current_domain_to_resolve}...")
        loop = asyncio.get_event_loop()
        found_ips_details = []
        unique_ips_set = set()

        for fam in [socket.AF_INET, socket.AF_INET6]:
            try:
                ainfo = await loop.run_in_executor(None, socket.getaddrinfo, current_domain_to_resolve, None, fam,
                                                   socket.SOCK_STREAM)
                for res in ainfo:
                    ip_addr = res[4][0]
                    if ip_addr not in unique_ips_set:
                        found_ips_details.append(
                            {"ip": ip_addr, "version": (4 if fam == socket.AF_INET else 6), "asn_info": {},
                             "virustotal_report": None})
                        unique_ips_set.add(ip_addr)
                        logger.debug(
                            f"IPv{4 if fam == socket.AF_INET else 6} address found for {current_domain_to_resolve}: {ip_addr}")
            except socket.gaierror:
                logger.warning(
                    f"Could not resolve IPv{4 if fam == socket.AF_INET else 6} address for {current_domain_to_resolve}.")
            except Exception as e_ip_res:
                logger.error(
                    f"Error resolving IPv{4 if fam == socket.AF_INET else 6} for {current_domain_to_resolve}: {e_ip_res}")

        self.results["general_info"]["ip_addresses"] = found_ips_details

        if not found_ips_details:
            logger.error(
                f"Failed to resolve any IP address for {current_domain_to_resolve}. Many checks will be impacted.")
            add_finding(self.results["security_posture"], "vulnerability_findings",
                        {"type": "Configuration Issue", "description": "Domain does not resolve to any IP address.",
                         "target_url": current_domain_to_resolve, "severity": "High", "confidence": "High",
                         "evidence_summary": "DNS resolution failed for A/AAAA records",
                         "recommendation": "Verify DNS records for the domain are correctly configured and propagated."},
                        log_message=f"Domain {current_domain_to_resolve} failed to resolve to any IP.",
                        severity_for_log="HIGH")
            return

        logger.info(f"IP addresses for {current_domain_to_resolve}: {[ip_info['ip'] for ip_info in found_ips_details]}")

        # ASN Lookup & Basic Location Guess
        geo_location_source = "None"
        if self.config.get("enable_ip_asn_lookup", True) and IPWHOIS_AVAILABLE:
            for ip_info_entry in self.results["general_info"]["ip_addresses"]:
                ip_addr_asn = ip_info_entry["ip"]
                if ip_addr_asn in self.results["general_info"]["ip_asn_info"] and \
                        self.results["general_info"]["ip_asn_info"][ip_addr_asn]:
                    ip_info_entry["asn_info"] = self.results["general_info"]["ip_asn_info"][ip_addr_asn]
                    if self.results["general_info"].get("server_location_guess") is None and ip_info_entry[
                        "asn_info"].get("asn_country_code"):
                        self.results["general_info"][
                            "server_location_guess"] = f"Country: {ip_info_entry['asn_info']['asn_country_code']} (from ASN)"
                        geo_location_source = "ASN"
                    continue
                try:
                    logger.debug(f"Fetching ASN for {ip_addr_asn}")
                    obj = IPWhois(ip_addr_asn)
                    results = await asyncio.to_thread(obj.lookup_rdap, allow_permutations=True)

                    asn_data = {
                        "asn": results.get("asn"),
                        "asn_description": results.get("asn_description"),
                        "asn_cidr": results.get("asn_cidr"),
                        "asn_country_code": results.get("asn_country_code"),
                        "entities": results.get("entities"),
                        "network_name": results.get("network", {}).get("name"),
                        "network_handle": results.get("network", {}).get("handle")
                    }
                    ip_info_entry["asn_info"] = asn_data
                    self.results["general_info"]["ip_asn_info"][ip_addr_asn] = asn_data
                    logger.info(f"ASN for {ip_addr_asn}: {asn_data.get('asn')} - {asn_data.get('asn_description')}")

                    if self.results["general_info"].get("server_location_guess") is None and asn_data.get(
                            "asn_country_code"):
                        self.results["general_info"][
                            "server_location_guess"] = f"Country: {asn_data['asn_country_code']} (from ASN)"
                        geo_location_source = "ASN"

                    if asn_data.get('asn_description'):
                        desc_lower = asn_data['asn_description'].lower()
                        provider = None
                        provider_keywords = {"cloudflare": "Cloudflare", "amazon": "AWS", "aws": "AWS",
                                             "google": "Google Cloud", "microsoft": "Microsoft Azure",
                                             "azure": "Microsoft Azure", "akamai": "Akamai", "fastly": "Fastly",
                                             "sucuri": "Sucuri", "ovh": "OVH", "digitalocean": "DigitalOcean",
                                             "linode": "Linode", "hetzner": "Hetzner", "godaddy": "GoDaddy",
                                             "bluehost": "Bluehost", "hostgator": "HostGator",
                                             "siteground": "SiteGround", "oracle": "Oracle Cloud",
                                             "maxcdn": "MaxCDN/StackPath", "stackpath": "StackPath",
                                             "imperva": "Imperva"}
                        for keyword, p_name in provider_keywords.items():
                            if keyword in desc_lower:
                                provider = p_name
                                break
                        if provider and not any(p_item.startswith(provider) for p_item in
                                                self.results["technology_fingerprint"]["cdn_providers"]):
                            self.results["technology_fingerprint"]["cdn_providers"].append(
                                f"{provider} (ASN: {asn_data.get('asn')})")
                            add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                        {"type": "Hosting Provider Identification (ASN)",
                                         "description": f"The IP address {ip_addr_asn} appears to be hosted by {provider} based on ASN information (ASN: {asn_data.get('asn')} - {asn_data.get('asn_description')}).",
                                         "severity": "Info", "confidence": "Medium",
                                         "details": {"ip": ip_addr_asn, "provider": provider, "asn_info": asn_data}},
                                        log_message=f"IP {ip_addr_asn} likely hosted by {provider} (ASN)",
                                        severity_for_log="INFO")
                except IPDefinedError:
                    logger.debug(f"ASN lookup for {ip_addr_asn} skipped (private/reserved IP).")
                    ip_info_entry["asn_info"] = {"status": "Private/Reserved IP"}
                    self.results["general_info"]["ip_asn_info"][ip_addr_asn] = ip_info_entry["asn_info"]
                except Exception as e_asn:
                    logger.warning(f"ASN lookup failed for {ip_addr_asn}: {type(e_asn).__name__} - {e_asn}")
                    ip_info_entry["asn_info"] = {"status": f"Lookup Error: {type(e_asn).__name__}"}
                    self.results["general_info"]["ip_asn_info"][ip_addr_asn] = ip_info_entry["asn_info"]
        elif not IPWHOIS_AVAILABLE:
            logger.info("IP ASN lookup skipped: 'ipwhois' library not available.")

        if self.results["general_info"].get("server_location_guess") is None and \
                self.results["general_info"].get("domain_reputation_vt") and \
                isinstance(self.results["general_info"]["domain_reputation_vt"].get("attributes"), dict) and \
                self.results["general_info"]["domain_reputation_vt"]["attributes"].get("country"):
            self.results["general_info"][
                "server_location_guess"] = f"Country: {self.results['general_info']['domain_reputation_vt']['attributes']['country']} (from VirusTotal Domain Report)"
            geo_location_source = "VirusTotal Domain Report"

        if self.results["general_info"].get("server_location_guess"):
            logger.info(
                f"Server Location Guess: {self.results['general_info']['server_location_guess']} (Source: {geo_location_source})")
        else:
            logger.info("Could not determine server location from available data sources.")

    async def _perform_advanced_wildcard_dns_check(self) -> dict:
        wildcard_analysis = {"detected": False, "evidence": "Initial tests negative or inconclusive.",
                             "probed_subdomains_details": []}
        current_domain_for_wildcard = self.results["scan_metadata"].get("effective_domain", self.domain)
        if not current_domain_for_wildcard:
            wildcard_analysis["evidence"] = "Wildcard check skipped: No valid domain identified."
            return wildcard_analysis

        wildcard_config = self.config.get("wildcard_dns_config", {})
        num_probes = wildcard_config.get("num_probes", 3)

        if num_probes == 0:
            wildcard_analysis["evidence"] = "Wildcard check skipped by config (num_probes=0)."
            return wildcard_analysis

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config["dns_timeout_seconds"]
        resolver.lifetime = self.config["dns_timeout_seconds"] * 2

        resolved_ips_set = set()
        resolved_subdomains_count = 0
        all_probes_resolved_to_same_ip_group = True
        first_probe_ip_set = None

        for i in range(num_probes):
            random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            test_host = f"kairos-wildcard-test-{random_prefix}-{i}.{current_domain_for_wildcard}"
            probe_info = {"subdomain": test_host, "resolved_ips": [], "http_status": None, "content_hash_prefix": None,
                          "resolution_status": "Not Resolved"}
            try:
                current_probe_ips = []
                for r_type in ["A", "AAAA"]:
                    try:
                        answers = await asyncio.to_thread(resolver.resolve, test_host, r_type)
                        current_probe_ips.extend([str(rdata) for rdata in answers])
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                        continue
                    except Exception as e_dns_res_type:
                        logger.debug(f"Minor error resolving {r_type} for {test_host}: {e_dns_res_type}")
                        continue

                if current_probe_ips:
                    resolved_subdomains_count += 1
                    probe_info["resolved_ips"] = current_probe_ips
                    probe_info["resolution_status"] = "Resolved"
                    resolved_ips_set.update(current_probe_ips)

                    current_probe_ip_set = set(current_probe_ips)
                    if first_probe_ip_set is None:
                        first_probe_ip_set = current_probe_ip_set
                    elif current_probe_ip_set != first_probe_ip_set:
                        all_probes_resolved_to_same_ip_group = False
                else:
                    probe_info["resolution_status"] = "NXDOMAIN/NoAnswer"
            except Exception as e_wild_dns:
                probe_info["resolution_status"] = f"Error: {type(e_wild_dns).__name__}"
            wildcard_analysis["probed_subdomains_details"].append(probe_info)

        if resolved_subdomains_count == num_probes and num_probes > 0:
            wildcard_analysis["detected"] = True
            wildcard_analysis[
                "evidence"] = f"All {num_probes} random subdomains (e.g., {wildcard_analysis['probed_subdomains_details'][0]['subdomain']}) resolved."
            if all_probes_resolved_to_same_ip_group and first_probe_ip_set:
                wildcard_analysis[
                    "evidence"] += f" All resolved to the same IP(s): {', '.join(sorted(list(first_probe_ip_set)))}."
            else:
                wildcard_analysis[
                    "evidence"] += f" Resolved to varying IPs or groups of IPs (Total unique IPs from probes: {len(resolved_ips_set)} - e.g., {list(resolved_ips_set)[:5]}...). This is strong wildcard evidence."

            if wildcard_config.get("compare_http_response_similarity", False) and self.session:
                content_hashes = set()
                http_responses_summary = []
                primary_scheme_for_wildcard = urlparse(
                    self.results["general_info"].get("final_url", self.target_url)).scheme
                if primary_scheme_for_wildcard not in ["http", "https"]: primary_scheme_for_wildcard = "http"

                for probe_http_info_item in wildcard_analysis["probed_subdomains_details"]:
                    if probe_http_info_item["resolved_ips"]:
                        test_url_wc = f"{primary_scheme_for_wildcard}://{probe_http_info_item['subdomain']}"
                        try:
                            resp_wc, content_wc = await self._make_request(
                                test_url_wc, method="GET", allow_redirects=False, max_retries=0,
                                timeout_override=aiohttp.ClientTimeout(
                                    total=wildcard_config.get("http_probe_timeout_seconds", 7))
                            )
                            if resp_wc and content_wc:
                                probe_http_info_item["http_status"] = resp_wc.status
                                prefix_len = wildcard_config.get("content_similarity_threshold_bytes", 350)
                                content_hash = hashlib.md5(content_wc[:prefix_len]).hexdigest()
                                probe_http_info_item["content_hash_prefix"] = content_hash
                                content_hashes.add(content_hash)
                                http_responses_summary.append(
                                    f"{test_url_wc}: Status {resp_wc.status}, Hash: {content_hash}")
                        except Exception as e_http_wc:
                            logger.debug(f"HTTP probe for wildcard check on {test_url_wc} failed: {e_http_wc}")
                            probe_http_info_item["http_status"] = f"Error: {type(e_http_wc).__name__}"

                wildcard_analysis["http_responses_summary"] = http_responses_summary
                if len(content_hashes) == 1 and resolved_subdomains_count > 1:
                    wildcard_analysis[
                        "evidence"] += " HTTP/S responses for these resolved probes showed high content similarity (same hash of first N bytes)."
                elif content_hashes and resolved_subdomains_count > 1:
                    wildcard_analysis[
                        "evidence"] += f" HTTP/S responses for these resolved probes showed {len(content_hashes)} distinct content patterns."

        elif resolved_subdomains_count > 0:
            wildcard_analysis[
                "evidence"] = f"{resolved_subdomains_count} out of {num_probes} random subdomains resolved. May indicate partial wildcard or specific configurations. Less likely a full wildcard."
        else:
            wildcard_analysis[
                "evidence"] = f"None of the {num_probes} random subdomains resolved. Wildcard DNS unlikely for *.{current_domain_for_wildcard}."

        if wildcard_analysis["detected"]:
            logger.warning(f"Advanced Wildcard DNS detection: {wildcard_analysis['evidence']}")
        else:
            logger.info(f"Advanced Wildcard DNS check: {wildcard_analysis['evidence']}")
        return wildcard_analysis

    async def gather_dns_information(self):
        current_domain_for_dns = self.results["scan_metadata"].get("effective_domain", self.domain)
        if not current_domain_for_dns:
            logger.error("Cannot gather DNS information: No valid domain identified for the target.")
            self.results["dns_information"]["records"] = {"error": "No valid domain for DNS queries."}
            return

        logger.info(f"Gathering DNS records for {current_domain_for_dns}...")
        self.results["dns_information"]["wildcard_dns_analysis"] = await self._perform_advanced_wildcard_dns_check()

        dns_results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config["dns_timeout_seconds"]
        resolver.lifetime = self.config["dns_timeout_seconds"] * 2

        for record_type in self.config["dns_records_to_query"]:
            try:
                logger.debug(f"Querying DNS {record_type} record for {current_domain_for_dns}")
                if record_type == "PTR":
                    if not self.results["general_info"]["ip_addresses"]:
                        logger.debug(
                            f"Skipping PTR for {current_domain_for_dns} as no primary IPs resolved yet to reverse.")
                        dns_results[record_type] = ["Info: Skipped for primary domain, no IPs resolved yet."]
                        continue
                    ptr_records = []
                    for ip_info in self.results["general_info"]["ip_addresses"]:
                        try:
                            rev_name = dns.reversename.from_address(ip_info["ip"])
                            answers = await asyncio.to_thread(resolver.resolve, rev_name, "PTR")
                            ptr_records.extend([rdata.to_text().strip('"').strip().rstrip('.') for rdata in answers])
                        except dns.resolver.NXDOMAIN:
                            logger.debug(f"No PTR record for IP {ip_info['ip']}.")
                        except dns.exception.Timeout:
                            logger.warning(f"Timeout querying PTR for IP {ip_info['ip']}.")
                        except Exception as e_ptr_ip:
                            logger.warning(f"Error querying PTR for {ip_info['ip']}: {e_ptr_ip}")
                    dns_results[record_type] = sorted(list(set(ptr_records))) if ptr_records else [
                        "No PTR records found for resolved IPs."]
                    continue

                answers = await asyncio.to_thread(resolver.resolve, current_domain_for_dns, record_type)
                processed_answers = []
                for rdata in answers:
                    if record_type == "SOA":
                        processed_answers.append(
                            f"MNAME: {rdata.mname.to_text().rstrip('.')}, RNAME: {rdata.rname.to_text().rstrip('.')}, Serial: {rdata.serial}")
                    elif record_type == "MX":
                        processed_answers.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                    elif record_type == "SRV":
                        processed_answers.append(
                            f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target.to_text().rstrip('.')}")
                    elif record_type in ["NS", "CNAME"]:
                        processed_answers.append(rdata.target.to_text().rstrip('.'))
                    elif record_type == "TXT":
                        processed_answers.append(" ".join(b.decode('utf-8', 'ignore') for b in rdata.strings))
                    else:
                        processed_answers.append(rdata.to_text().strip('"').strip())
                dns_results[record_type] = sorted(list(set(processed_answers)))

            except dns.resolver.NoAnswer:
                dns_results[record_type] = []
            except dns.resolver.NXDOMAIN:
                logger.error(
                    f"DNS resolution failed (NXDOMAIN) for {current_domain_for_dns} while querying {record_type}.")
                dns_results[record_type] = ["Error: NXDOMAIN"]
                if record_type in ["A", "AAAA"] and not self.results["general_info"]["ip_addresses"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "DNS Issue",
                                 "description": f"Domain {current_domain_for_dns} does not exist (NXDOMAIN for {record_type}).",
                                 "target_url": current_domain_for_dns, "severity": "Critical", "confidence": "High",
                                 "evidence_summary": f"{record_type} query failed",
                                 "recommendation": "Ensure the domain name is correct and DNS records are properly configured and propagated."},
                                log_message=f"NXDOMAIN for {current_domain_for_dns} on {record_type}",
                                severity_for_log="CRITICAL")
            except dns.exception.Timeout:
                dns_results[record_type] = ["Error: Timeout"]
                logger.warning(f"DNS query for {record_type} on {current_domain_for_dns} timed out.")
            except dns.rdatatype.UnknownRdatatype:
                logger.debug(f"DNS record type {record_type} is unknown for {current_domain_for_dns}.")
            except dns.resolver.NoNameservers as e_nonameservers:
                logger.error(
                    f"DNS query for {record_type} on {current_domain_for_dns} failed: No authoritative nameservers found or they failed to respond. Error: {e_nonameservers}")
                dns_results[record_type] = [f"Error: NoNameservers - {e_nonameservers}"]
            except Exception as e_dns:
                logger.error(
                    f"Error fetching DNS {record_type} for {current_domain_for_dns}: {type(e_dns).__name__} - {e_dns}")
                dns_results[record_type] = [f"Error: {type(e_dns).__name__}"]
        self.results["dns_information"]["records"] = dns_results

        mail_config = {}
        if "MX" in dns_results and dns_results["MX"] and not any("Error:" in r for r in dns_results["MX"]):
            mail_config["mx_records"] = dns_results["MX"]

        txt_records_from_dns = dns_results.get("TXT", [])
        spf_record_val = None
        if dns_results.get("SPF") and dns_results["SPF"] and not any(
                "Error:" in r for r in dns_results["SPF"]):  # SPF record type
            spf_record_val = " ".join(dns_results["SPF"])
            mail_config["spf_record_source"] = "SPF Record Type"
        if not spf_record_val:  # Fallback to TXT
            spf_from_txt = [txt for txt in txt_records_from_dns if "v=spf1" in txt.lower()]
            if spf_from_txt:
                spf_record_val = spf_from_txt[0]
                mail_config["spf_record_source"] = "TXT Record"

        if spf_record_val:
            mail_config["spf_record_effective"] = spf_record_val
            if "~all" in spf_record_val:
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "SPF Policy Weak (SoftFail)",
                             "description": "SPF record uses '~all' (SoftFail). This advises acceptance but marking of non-compliant mail, less secure than '-all' (Fail).",
                             "severity": "Low", "confidence": "High", "evidence_summary": spf_record_val,
                             "recommendation": "Consider changing '~all' to '-all' in the SPF record for stricter enforcement if all sending sources are listed."},
                            log_message="Weak SPF policy (~all) found", severity_for_log="LOW")
            elif "?all" in spf_record_val:
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "SPF Policy Weak (Neutral)",
                             "description": "SPF record uses '?all' (Neutral). This means no policy assertion. Less secure than '-all' (Fail).",
                             "severity": "Low", "confidence": "High", "evidence_summary": spf_record_val,
                             "recommendation": "Consider changing '?all' to '-all' in the SPF record for stricter enforcement if all sending sources are listed."},
                            log_message="Weak SPF policy (?all) found", severity_for_log="LOW")
            elif "-all" not in spf_record_val:
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "SPF Policy Incomplete/Permissive",
                             "description": "SPF record does not explicitly end with '-all' (Fail) or '~all' (SoftFail). This might lead to default interpretation or is overly permissive if no 'all' mechanism is present.",
                             "severity": "Low", "confidence": "Medium", "evidence_summary": spf_record_val,
                             "recommendation": "Ensure the SPF record ends with an appropriate mechanism like '-all', '~all', or at least '?all' to define the policy for non-matching senders. Prefer '-all' or '~all'."},
                            log_message="SPF policy may be incomplete or too permissive", severity_for_log="LOW")

        dmarc_record_val = None
        try:
            dmarc_answers = await asyncio.to_thread(resolver.resolve, f"_dmarc.{current_domain_for_dns}", "TXT")
            dmarc_from_subdomain = [rdata.to_text().strip('"').strip() for rdata in dmarc_answers if
                                    "v=dmarc1" in rdata.to_text().lower()]
            if dmarc_from_subdomain: dmarc_record_val = dmarc_from_subdomain[0]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e_dmarc:
            logger.warning(f"Error querying DMARC for _dmarc.{current_domain_for_dns}: {e_dmarc}")

        if dmarc_record_val:
            mail_config["dmarc_record_effective"] = dmarc_record_val
            if "p=none" in dmarc_record_val.lower():
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "DMARC Policy Weak (None)",
                             "description": "DMARC policy is 'p=none' (monitor mode). This provides reporting but no enforcement against spoofing.",
                             "severity": "Medium", "confidence": "High", "evidence_summary": dmarc_record_val,
                             "recommendation": "Gradually move DMARC policy to 'p=quarantine' and then 'p=reject' after monitoring reports to enhance email spoofing protection."},
                            log_message="DMARC policy 'p=none' found", severity_for_log="MEDIUM")
            elif "p=quarantine" not in dmarc_record_val.lower() and "p=reject" not in dmarc_record_val.lower():
                add_finding(self.results["dns_information"], "mail_servers_config_issues",
                            {"type": "DMARC Policy Missing Enforcement",
                             "description": "DMARC record found, but no explicit 'p=quarantine' or 'p=reject' policy. Effective policy may be 'none' or default to 'none' if 'p' tag is missing.",
                             "severity": "Medium", "confidence": "High", "evidence_summary": dmarc_record_val,
                             "recommendation": "Ensure DMARC policy 'p' is explicitly set to 'quarantine' or 'reject' for enforcement after a monitoring period with 'p=none'."},
                            log_message="DMARC policy 'p' not explicitly set to quarantine/reject",
                            severity_for_log="MEDIUM")
        else:  # No DMARC record found
            add_finding(self.results["dns_information"], "mail_servers_config_issues",
                        {"type": "DMARC Policy Missing",
                         "description": "No DMARC record found. This makes the domain more susceptible to email spoofing as it doesn't instruct receivers on how to handle unauthenticated mail.",
                         "severity": "Medium", "confidence": "High",
                         "evidence_summary": "DMARC record not found at _dmarc subdomain.",
                         "recommendation": "Implement a DMARC record, starting with 'p=none' and monitoring rua/ruf reports, then progressing to 'p=quarantine' or 'p=reject'."},
                        log_message="DMARC record missing", severity_for_log="MEDIUM")

        dkim_selectors_to_check = ["default._domainkey", "google._domainkey", "selector1._domainkey",
                                   "selector2._domainkey", "k1._domainkey", "dkim._domainkey", "mandrill._domainkey",
                                   "smtp._domainkey", "zoho._domainkey", "pm._domainkey", "mail._domainkey",
                                   "s1._domainkey", "s2._domainkey", "m1._domainkey", "sparkpost._domainkey",
                                   "sendgrid._domainkey", "amazonses._domainkey"]
        dkim_found_records = []
        for selector in dkim_selectors_to_check:
            try:
                answers = await asyncio.to_thread(resolver.resolve, f"{selector}.{current_domain_for_dns}", "TXT")
                for rdata in answers:
                    txt_val = rdata.to_text().strip('"').strip()
                    if "v=dkim1" in txt_val.lower():
                        dkim_found_records.append(f"{selector}: {txt_val[:100]}{'...' if len(txt_val) > 100 else ''}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e_dkim:
                logger.debug(f"Error querying DKIM selector {selector}: {e_dkim}")
        if dkim_found_records:
            mail_config["dkim_records_found_heuristic"] = dkim_found_records
        self.results["dns_information"]["mail_servers_config"] = mail_config

        if "DNSKEY" in dns_results and dns_results["DNSKEY"] and not any("Error:" in r for r in dns_results["DNSKEY"]):
            self.results["dns_information"][
                "dnssec_status"] = "Likely Enabled (DNSKEY records found). Full validation requires a validating resolver."
            if "DS" in dns_results and dns_results["DS"] and not any("Error:" in r for r in dns_results["DS"]):
                self.results["dns_information"]["dnssec_status"] += " DS records also found, strengthening likelihood."
            else:
                self.results["dns_information"][
                    "dnssec_status"] += " No DS records found at this level; check parent zone for delegation."

        else:
            self.results["dns_information"][
                "dnssec_status"] = "Not Enabled or Not Verifiable (No DNSKEY records / Error fetching DNSKEY)."
        logger.info(f"DNS information gathering for {current_domain_for_dns} complete.")

    async def gather_whois_information(self):
        current_domain_for_whois = self.results["scan_metadata"].get("effective_domain", self.domain)
        if not self.config.get("enable_whois_lookup", True) or not WHOIS_CORRECT_LIB:
            self.results["dns_information"]["whois_data"] = {
                "status": "Skipped - WHOIS lookup disabled or 'python-whois' library issue."}
            if not WHOIS_CORRECT_LIB: logger.warning(
                "WHOIS lookup skipped: 'python-whois' library not found or seems corrupted.")
            return

        if not current_domain_for_whois:
            logger.error("Cannot perform WHOIS lookup: No valid domain identified.")
            self.results["dns_information"]["whois_data"] = {"status": "Skipped - No valid domain for WHOIS lookup."}
            return

        logger.info(f"Fetching WHOIS information for {current_domain_for_whois}...")
        try:
            whois_data_obj = await asyncio.to_thread(whois.whois, current_domain_for_whois)

            if whois_data_obj and (
                    getattr(whois_data_obj, 'domain_name', None) or getattr(whois_data_obj, 'DOMAIN_NAME',
                                                                            None) or getattr(whois_data_obj, 'name',
                                                                                             None) or getattr(
                    whois_data_obj, 'text', None)):
                sanitized_whois = {}
                if hasattr(whois_data_obj, '__dict__') and whois_data_obj.__dict__:
                    for key, value in whois_data_obj.__dict__.items():
                        k_lower = key.lower() if isinstance(key, str) else str(key)
                        if isinstance(value, list):
                            sanitized_whois[k_lower] = [item.isoformat() if isinstance(item, datetime) else str(item)
                                                        for item in value]
                        elif isinstance(value, datetime):
                            sanitized_whois[k_lower] = value.isoformat()
                        else:
                            sanitized_whois[k_lower] = str(value) if value is not None else None
                elif hasattr(whois_data_obj,
                             'text') and whois_data_obj.text:  # Fallback for when parsing fails but text is available
                    sanitized_whois['raw_text'] = whois_data_obj.text
                elif isinstance(whois_data_obj, str):  # Some libs might return raw string
                    sanitized_whois['raw_text'] = whois_data_obj
                else:
                    self.results["dns_information"]["whois_data"] = {
                        "status": "No parseable WHOIS data and no raw text found."}
                    logger.warning(f"No parseable WHOIS data returned for {current_domain_for_whois}.")
                    return

                self.results["dns_information"]["whois_data"] = sanitized_whois
                logger.info(f"WHOIS data successfully retrieved for {current_domain_for_whois}.")

                privacy_keywords = ["privacy", "redacted", "whoisguard", "domains by proxy", "contactprivacy",
                                    "private registration", "data protected", "proxy", "shielded", "anonymous",
                                    "identity protected", "not disclosed", "redacted for privacy",
                                    "domain protection services", "registrant contact anonymer",
                                    "whois privacy service"]
                registrant_info_str = "".join([str(sanitized_whois.get(field, "")).lower() for field in
                                               ["registrant_name", "registrant_organization", "registrant_email",
                                                "name", "org", "email", "admin_name", "admin_organization",
                                                "admin_email", "tech_name", "tech_organization", "tech_email",
                                                "raw_text"]])

                if any(keyword in registrant_info_str for keyword in privacy_keywords) or \
                        any(keyword in str(sanitized_whois.get("emails", "")).lower() for keyword in privacy_keywords):
                    self.results["dns_information"]["whois_privacy_enabled"] = True
                    logger.info(f"WHOIS privacy protection appears to be enabled for {current_domain_for_whois}.")
                else:
                    self.results["dns_information"]["whois_privacy_enabled"] = False

            elif whois_data_obj and hasattr(whois_data_obj, 'text') and whois_data_obj.text and (
                    "limit exceeded" in whois_data_obj.text.lower() or "query rate exceeded" in whois_data_obj.text.lower()):
                self.results["dns_information"]["whois_data"] = {"status": "Rate limit exceeded with WHOIS server",
                                                                 "raw_text": whois_data_obj.text}
                logger.warning(f"WHOIS lookup for {current_domain_for_whois} failed due to rate limiting.")
            else:
                self.results["dns_information"]["whois_data"] = {
                    "status": "No data found or unrecognized format from WHOIS server."}
                logger.warning(f"No WHOIS data found or unrecognized format for {current_domain_for_whois}.")

        except whois.parser.PywhoisError as e_whois_parse:
            self.results["dns_information"]["whois_data"] = {"error": f"WHOIS Parsing Error: {e_whois_parse}"}
            logger.error(f"WHOIS parsing error for {current_domain_for_whois}: {e_whois_parse}")
        except AttributeError as ae_whois:  # Catch cases where the whois object might be None or not have expected attrs
            self.results["dns_information"]["whois_data"] = {
                "error": f"WHOIS Library AttributeError or Data Issue: {ae_whois}. Ensure 'python-whois' is correctly installed."}
            logger.error(
                f"WHOIS library attribute error for {current_domain_for_whois}: {ae_whois}. Check 'python-whois' installation.")
        except socket.timeout:
            self.results["dns_information"]["whois_data"] = {"error": "WHOIS lookup timed out."}
            logger.warning(f"WHOIS lookup for {current_domain_for_whois} timed out.")
        except Exception as e_whois_generic:
            self.results["dns_information"]["whois_data"] = {
                "error": f"Unexpected WHOIS Error: {type(e_whois_generic).__name__} - {e_whois_generic}"}
            logger.error(f"Unexpected WHOIS error for {current_domain_for_whois}: {e_whois_generic}", exc_info=True)

    async def analyze_http_response_details(self):
        logger.info("Analyzing HTTP response details (headers, cookies)...")
        if not self._main_page_response_cache:
            logger.warning("Main page response not cached, skipping HTTP details analysis.")
            return

        response, _ = self._main_page_response_cache
        headers = response.headers
        sec_headers_analysis = {}

        for header_name, description in self.config["security_headers_info"].items():
            header_value = None
            actual_value_for_report = None

            if header_name == "Set-Cookie":
                header_value_list = headers.getall(header_name, [])
                if header_value_list:
                    header_value = "; ".join(header_value_list)  # For checking presence
                    actual_value_for_report = header_value_list  # For report
            else:
                header_value = headers.get(header_name)
                actual_value_for_report = header_value

            status = "Present" if header_value is not None else "Missing"
            sec_headers_analysis[header_name] = {"value": actual_value_for_report, "status": status,
                                                 "description": description}
            recommendation = None
            current_confidence = "High"

            if header_value is not None:  # Header is present
                if header_name == "Strict-Transport-Security":
                    if "preload" not in header_value.lower():
                        recommendation = "Consider adding 'preload' to HSTS and submitting to HSTS preload lists for maximum security."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice (HSTS)",
                                     "description": "HSTS header present but 'preload' directive is missing.",
                                     "severity": "Low", "confidence": "High",
                                     "evidence_summary": f"HSTS: {header_value}", "recommendation": recommendation},
                                    log_message="HSTS 'preload' missing", severity_for_log="LOW")
                    if "max-age" in header_value.lower():
                        try:
                            max_age_match = re.search(r"max-age=(\d+)", header_value, re.I)
                            if max_age_match and int(max_age_match.group(1)) < 31536000:  # Less than 1 year
                                recommendation = "Increase HSTS 'max-age' to at least 31536000 seconds (1 year) for stronger protection."
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Security Best Practice (HSTS)",
                                             "description": f"HSTS 'max-age' is {max_age_match.group(1)}, less than recommended 1 year.",
                                             "severity": "Low", "confidence": "High",
                                             "evidence_summary": f"HSTS: {header_value}",
                                             "recommendation": recommendation},
                                            log_message=f"HSTS 'max-age' low ({max_age_match.group(1)})",
                                            severity_for_log="LOW")
                        except ValueError:
                            pass  # Invalid number for max-age

                elif header_name == "X-Frame-Options" and header_value.lower() not in ["deny", "sameorigin"]:
                    recommendation = "Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options. For finer control, use CSP 'frame-ancestors'."
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Security Misconfiguration (Clickjacking)",
                                 "description": f"X-Frame-Options is '{header_value}' which might be permissive or deprecated. Consider CSP 'frame-ancestors'.",
                                 "severity": "Low", "confidence": "High",
                                 "evidence_summary": f"X-Frame-Options: {header_value}",
                                 "recommendation": recommendation},
                                log_message=f"X-Frame-Options potentially weak: {header_value}", severity_for_log="LOW")

                elif header_name == "Content-Security-Policy":
                    csp_val_lower = header_value.lower()
                    # Check 'unsafe-inline' for scripts without nonces/hashes more carefully
                    unsafe_inline_scripts = "'unsafe-inline'" in csp_val_lower and \
                                            ("script-src" in csp_val_lower or (
                                                        "default-src" in csp_val_lower and "script-src" not in csp_val_lower)) and \
                                            not ((
                                                             "nonce-" in csp_val_lower or "sha256-" in csp_val_lower or "sha384-" in csp_val_lower or "sha512-" in csp_val_lower) and "script-src" in csp_val_lower)

                    if unsafe_inline_scripts:
                        recommendation = "Avoid 'unsafe-inline' in CSP script-src. Use nonces, hashes, or host-based whitelisting. If nonces/hashes are used for some scripts, ensure all inline scripts are covered or refactored."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration (CSP)",
                                     "description": "CSP allows 'unsafe-inline' for scripts, increasing XSS risk if not mitigated by nonces/hashes for all inline scripts.",
                                     "severity": "Medium", "confidence": "High",
                                     "evidence_summary": "CSP: ...unsafe-inline...", "recommendation": recommendation},
                                    log_message="CSP 'unsafe-inline' scripts found", severity_for_log="MEDIUM")
                    if "'unsafe-eval'" in csp_val_lower and (
                            "script-src" in csp_val_lower or "default-src" in csp_val_lower):
                        recommendation = "Avoid 'unsafe-eval' in CSP. Refactor code to eliminate dynamic code execution with eval-like functions."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration (CSP)",
                                     "description": "CSP allows 'unsafe-eval', increasing risk from eval-like functions.",
                                     "severity": "Medium", "confidence": "High",
                                     "evidence_summary": "CSP: ...unsafe-eval...", "recommendation": recommendation},
                                    log_message="CSP 'unsafe-eval' scripts found", severity_for_log="MEDIUM")
                    if re.search(r"(\s|;)['\"]?\*(?:['\"]?|:\*)(\s|;|$)",
                                 csp_val_lower) or csp_val_lower.strip() == "'*'":
                        recommendation = "Avoid wildcard '*' sources in CSP where possible. Be specific about allowed origins."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Misconfiguration (CSP)",
                                     "description": "CSP uses wildcard '*' source, which is overly permissive.",
                                     "severity": "Low", "confidence": "Medium", "evidence_summary": "CSP: ...'*'...",
                                     "recommendation": recommendation},
                                    log_message="CSP wildcard '*' source found", severity_for_log="LOW")
                    if "frame-ancestors" not in csp_val_lower:
                        recommendation = "Define 'frame-ancestors' directive in CSP (e.g., 'frame-ancestors 'self'' or 'frame-ancestors 'none'') to protect against clickjacking. This is preferred over X-Frame-Options."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice (CSP)",
                                     "description": "CSP is present but does not define 'frame-ancestors' directive for clickjacking protection.",
                                     "severity": "Low", "confidence": "High",
                                     "evidence_summary": "CSP missing frame-ancestors",
                                     "recommendation": recommendation},
                                    log_message="CSP missing 'frame-ancestors'", severity_for_log="LOW")
                    if "object-src" not in csp_val_lower:
                        recommendation = "Define 'object-src 'none'' in CSP to prevent embedding of potentially malicious Flash/Java/other plugin content, unless explicitly required."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice (CSP)",
                                     "description": "CSP is present but does not define 'object-src' directive. Defaulting can be risky. 'object-src 'none'' is recommended.",
                                     "severity": "Low", "confidence": "Medium",
                                     "evidence_summary": "CSP missing object-src", "recommendation": recommendation},
                                    log_message="CSP missing 'object-src'", severity_for_log="LOW")
                    if "base-uri" not in csp_val_lower:
                        recommendation = "Define 'base-uri 'self'' (or 'none') in CSP to protect against base tag hijacking, which can lead to XSS or resource loading from untrusted origins."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice (CSP)",
                                     "description": "CSP is present but does not define 'base-uri' directive. 'base-uri 'self'' or 'none' is recommended.",
                                     "severity": "Low", "confidence": "Medium",
                                     "evidence_summary": "CSP missing base-uri", "recommendation": recommendation},
                                    log_message="CSP missing 'base-uri'", severity_for_log="LOW")
                    if "report-uri" not in csp_val_lower and "report-to" not in csp_val_lower:
                        recommendation = "Consider adding 'report-uri' (CSP Level 2) or 'report-to' (CSP Level 3) directive to your CSP to monitor policy violations."
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Best Practice (CSP Monitoring)",
                                     "description": "CSP is present but lacks 'report-uri' or 'report-to' directive for violation reporting.",
                                     "severity": "Info", "confidence": "Medium",
                                     "evidence_summary": "CSP missing reporting directive",
                                     "recommendation": recommendation},
                                    log_message="CSP missing reporting directive", severity_for_log="INFO")


            else:  # Header is missing
                severity = "Medium";
                log_sev = "MEDIUM";
                desc_extra = ""
                if header_name == "Strict-Transport-Security":
                    recommendation = "Implement HSTS to enforce HTTPS connections. Start with a low max-age and gradually increase it. Consider preload submission."
                elif header_name == "Content-Security-Policy":
                    recommendation = "Implement CSP to mitigate XSS and other injection attacks. Start with a restrictive policy (e.g., default-src 'self') and incrementally allow required sources."
                elif header_name == "X-Frame-Options":
                    recommendation = "Implement X-Frame-Options (e.g., 'DENY' or 'SAMEORIGIN') or preferably CSP 'frame-ancestors' to prevent clickjacking."
                elif header_name == "X-Content-Type-Options":
                    recommendation = "Set X-Content-Type-Options to 'nosniff' to prevent browsers from MIME-sniffing the content-type."
                elif header_name == "Referrer-Policy":
                    recommendation = "Set a Referrer-Policy (e.g., 'strict-origin-when-cross-origin' or 'no-referrer') to control referrer information leakage."
                elif header_name == "Permissions-Policy":
                    recommendation = "Implement Permissions-Policy (formerly Feature-Policy) to control access to powerful browser features."
                elif header_name == "X-XSS-Protection":
                    severity = "Info";
                    log_sev = "INFO";
                    desc_extra = " This header is deprecated by modern browsers; CSP is the recommended replacement.";
                    recommendation = "Focus on a strong Content-Security-Policy (CSP) for XSS protection. X-XSS-Protection is largely obsolete."
                else:  # For other security headers like COOP, COEP, CORP
                    severity = "Low";
                    log_sev = "LOW";
                    recommendation = f"Consider implementing the '{header_name}' header for enhanced security according to best practices."

                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Security Hardening (Missing Header)",
                             "description": f"Security header '{header_name}' is missing.{desc_extra}",
                             "severity": severity, "confidence": current_confidence, "recommendation": recommendation},
                            log_message=f"Missing security header: {header_name}", severity_for_log=log_sev.upper())

            if recommendation: sec_headers_analysis[header_name]["recommendation"] = recommendation
        self.results["http_details"]["security_headers_analysis"] = sec_headers_analysis

        cookies_data = []
        final_url_str_for_cookie_filter = str(self.results["general_info"]["final_url"])
        cookie_filter_url = YARL_URL(
            final_url_str_for_cookie_filter) if YARL_AVAILABLE else final_url_str_for_cookie_filter

        if self.session and self.session.cookie_jar:
            for cookie_obj in self.session.cookie_jar.filter_cookies(cookie_filter_url):
                if isinstance(cookie_obj, str) or not hasattr(cookie_obj, 'key') or not hasattr(cookie_obj, 'value'):
                    logger.warning(f"Skipping malformed cookie object encountered: {cookie_obj}")
                    continue

                cookie_info = {
                    "name": cookie_obj.key, "value": cookie_obj.value,
                    "domain": cookie_obj.get('domain'), "path": cookie_obj.get('path'),
                    "expires": cookie_obj.get('expires'),
                    "secure": bool(cookie_obj.get('secure')), "httponly": bool(cookie_obj.get('httponly')),
                    "samesite": cookie_obj.get('samesite', None)
                }
                if isinstance(cookie_info["expires"], datetime):  # Format datetime if present
                    cookie_info["expires"] = cookie_info["expires"].strftime("%a, %d-%b-%Y %H:%M:%S GMT")
                cookies_data.append(cookie_info)

                if not cookie_info["httponly"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security (HttpOnly Missing)",
                                 "description": f"Cookie '{cookie_obj.key}' missing 'HttpOnly' attribute, making it accessible to client-side scripts and increasing XSS impact.",
                                 "severity": "Medium", "confidence": "High",
                                 "target_url": final_url_str_for_cookie_filter,
                                 "details": {"cookie_name": cookie_obj.key},
                                 "recommendation": f"Set 'HttpOnly' attribute for cookie '{cookie_obj.key}' if not needed by client-side scripts."},
                                log_message=f"Cookie '{cookie_obj.key}' missing HttpOnly", severity_for_log="MEDIUM")
                if not cookie_info["secure"] and self.scheme == "https":
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security (Secure Missing)",
                                 "description": f"Cookie '{cookie_obj.key}' missing 'Secure' attribute despite being served over HTTPS. It can be transmitted over HTTP if user is tricked to HTTP.",
                                 "severity": "Medium", "confidence": "High",
                                 "target_url": final_url_str_for_cookie_filter,
                                 "details": {"cookie_name": cookie_obj.key},
                                 "recommendation": f"Set 'Secure' attribute for cookie '{cookie_obj.key}' to ensure it's only transmitted over HTTPS."},
                                log_message=f"Cookie '{cookie_obj.key}' missing Secure on HTTPS",
                                severity_for_log="MEDIUM")
                if cookie_info["samesite"] and str(cookie_info["samesite"]).lower() == "none" and not cookie_info[
                    "secure"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security (SameSite=None without Secure)",
                                 "description": f"Cookie '{cookie_obj.key}' has 'SameSite=None' but is not marked 'Secure'. Modern browsers may reject this or treat it as Lax.",
                                 "severity": "Medium", "confidence": "High",
                                 "target_url": final_url_str_for_cookie_filter,
                                 "details": {"cookie_name": cookie_obj.key},
                                 "recommendation": f"If cookie '{cookie_obj.key}' requires 'SameSite=None', it MUST also have 'Secure' attribute."},
                                log_message=f"Cookie '{cookie_obj.key}' SameSite=None without Secure",
                                severity_for_log="MEDIUM")
                if not cookie_info["samesite"]:
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Cookie Security (SameSite Missing)",
                                 "description": f"Cookie '{cookie_obj.key}' missing 'SameSite' attribute. Browsers default to 'Lax', but explicit 'SameSite=Lax' or 'SameSite=Strict' is better for CSRF protection.",
                                 "severity": "Low", "confidence": "High", "target_url": final_url_str_for_cookie_filter,
                                 "details": {"cookie_name": cookie_obj.key},
                                 "recommendation": f"Explicitly set 'SameSite' attribute for cookie '{cookie_obj.key}' (e.g., 'Strict' or 'Lax') to mitigate CSRF risks."},
                                log_message=f"Cookie '{cookie_obj.key}' missing SameSite attribute",
                                severity_for_log="LOW")
        self.results["http_details"]["cookies_set"] = cookies_data

    async def fingerprint_technologies(self):
        logger.info("Fingerprinting technologies (Wappalyzer, Headers, WAFs)...")
        if not self._main_page_response_cache or self._main_page_html_cache is None:
            logger.warning("Main page not available or content is None, technology fingerprinting will be limited.")
            return

        response, _ = self._main_page_response_cache
        headers = response.headers
        tech_results = self.results["technology_fingerprint"]

        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage(url=str(response.url), html=self._main_page_html_cache or "", headers=dict(headers))
            tech_detected_by_wappalyzer = wappalyzer.analyze_with_versions_and_categories(webpage)

            wappalyzer_findings_list = []
            for tech_name, tech_data in tech_detected_by_wappalyzer.items():
                version = tech_data.get("versions", [None])[0] if tech_data.get("versions") else None
                categories = [cat['name'] for cat in tech_data.get('categories', [])]
                confidence = tech_data.get("confidence", 100)  # Wappalyzer confidence for a match
                icon = tech_data.get("icon", "default.svg")

                wappalyzer_findings_list.append(
                    {"name": tech_name, "version": version, "categories": categories, "confidence": confidence,
                     "icon": icon})
                entry_str = tech_name + (f" v{version}" if version else "")

                if "CMS" in categories and not tech_results["cms_identified"]:
                    tech_results["cms_identified"] = tech_name
                elif any(c in categories for c in ["Web servers", "Reverse proxies"]):
                    if entry_str not in tech_results["server_software"]: tech_results["server_software"].append(
                        entry_str)
                elif any(c in categories for c in
                         ["JavaScript frameworks", "UI frameworks", "Web frameworks", "JavaScript graphics",
                          "Mobile frameworks"]):
                    if entry_str not in tech_results["frameworks_libraries"]: tech_results[
                        "frameworks_libraries"].append(entry_str)
                elif any(c in categories for c in
                         ["Analytics", "Tag managers", "Customer success", "Marketing automation", "Advertising"]):
                    if entry_str not in tech_results["analytics_trackers"]: tech_results["analytics_trackers"].append(
                        entry_str)
                elif "CDN" in categories:
                    if entry_str not in tech_results["cdn_providers"]: tech_results["cdn_providers"].append(entry_str)
                elif "Programming languages" in categories:
                    if entry_str not in tech_results["programming_languages_detected"]: tech_results[
                        "programming_languages_detected"].append(entry_str)
                elif "Operating systems" in categories:
                    if entry_str not in tech_results["operating_system_guesses"]: tech_results[
                        "operating_system_guesses"].append(entry_str)
                elif "Web application firewalls" in categories:
                    if not any(w.get("name") == tech_name for w in tech_results["waf_detected"]):
                        tech_results["waf_detected"].append(
                            {"name": tech_name, "version": version, "source": "Wappalyzer", "confidence": confidence})

                if version and tech_name not in tech_results["software_versions_found"]:
                    tech_results["software_versions_found"][tech_name] = version
            tech_results["wappalyzer_findings"] = wappalyzer_findings_list
        except TypeError as e_wapp_type:  # Catch specific Wappalyzer type errors if data is unexpected
            logger.error(
                f"Wappalyzer analysis failed due to a TypeError: {e_wapp_type}. This might be an internal Wappalyzer issue or related to data parsing. KAIROS will continue.",
                exc_info=False)
            tech_results["wappalyzer_findings"] = [{"error": f"Wappalyzer TypeError: {str(e_wapp_type)[:150]}"}]
        except Exception as e_wapp:
            logger.error(f"Wappalyzer analysis failed: {type(e_wapp).__name__} - {e_wapp}", exc_info=False)
            tech_results["wappalyzer_findings"] = [{"error": f"Wappalyzer failed: {str(e_wapp)[:150]}"}]

        if self.config.get("enable_waf_detection", True):
            waf_header_signatures = self.config.get("waf_signatures_headers", {})
            final_url_str_waf = str(response.url)
            cookie_filter_url_waf = YARL_URL(final_url_str_waf) if YARL_AVAILABLE else final_url_str_waf

            valid_cookies_list_waf = []
            if self.session and self.session.cookie_jar:
                for c_obj_waf in self.session.cookie_jar.filter_cookies(cookie_filter_url_waf):
                    if not isinstance(c_obj_waf, str) and hasattr(c_obj_waf, 'key') and hasattr(c_obj_waf, 'value'):
                        valid_cookies_list_waf.append(f"{c_obj_waf.key}={c_obj_waf.value}")
                    else:
                        logger.warning(
                            f"Skipping malformed cookie object in fingerprint_technologies (WAF detection): {c_obj_waf}")
            all_cookies_str = "; ".join(valid_cookies_list_waf)

            detected_waf_names_this_scan = {w['name'] for w in tech_results[
                "waf_detected"]}  # Keep track of WAFs already found (e.g. by Wappalyzer)

            for tech_provider_name, sig_patterns in waf_header_signatures.items():
                if tech_provider_name in detected_waf_names_this_scan: continue  # Don't re-add if Wappalyzer found it
                for pattern_item in sig_patterns:
                    pattern_lower = pattern_item.lower();
                    found_by_header_or_cookie = False;
                    evidence = ""
                    if ":" in pattern_item:  # Header:Value pattern
                        header_key_sig, *header_val_parts = pattern_item.split(":", 1)
                        header_key_sig = header_key_sig.strip()
                        header_val_sig = header_val_parts[0].strip().lower() if header_val_parts and header_val_parts[
                            0].strip() else None
                        actual_header_val = headers.get(header_key_sig)
                        if actual_header_val is not None:
                            if header_val_sig is None:
                                found_by_header_or_cookie = True; evidence = f"Header present: {header_key_sig}"  # Just presence of header
                            elif header_val_sig in actual_header_val.lower():
                                found_by_header_or_cookie = True; evidence = f"Header '{header_key_sig}' contains '{header_val_sig}'"
                    elif pattern_item.endswith("="):  # Cookie name pattern (e.g., "incap_ses_=")
                        cookie_name_sig = pattern_item[:-1].lower()
                        if f"{cookie_name_sig}=" in all_cookies_str.lower(): found_by_header_or_cookie = True; evidence = f"Cookie name pattern: {cookie_name_sig}"
                    else:  # General substring in any header value
                        for h_name, h_val in headers.items():
                            if pattern_lower in h_val.lower(): found_by_header_or_cookie = True; evidence = f"Substring '{pattern_item}' in Header '{h_name}' value"; break

                    if found_by_header_or_cookie:
                        is_waf = any(keyword in tech_provider_name.lower() for keyword in
                                     ["waf", "firewall", "shield", "security", "modsec", "wallarm", "wordfence",
                                      "barracuda", "fortiweb", "incapsula", "imperva", "akamai", "cloudflare"])
                        is_cdn = any(keyword in tech_provider_name.lower() for keyword in
                                     ["cdn", "akamai", "cloudflare", "fastly", "aws", "azure", "google", "stackpath",
                                      "incapsula"])

                        if is_waf and tech_provider_name not in detected_waf_names_this_scan:
                            tech_results["waf_detected"].append(
                                {"name": tech_provider_name, "source": "Header/Cookie Signature", "evidence": evidence,
                                 "confidence": 80})
                            detected_waf_names_this_scan.add(tech_provider_name)
                            logger.info(f"WAF Detected (Manual Signature): {tech_provider_name} (Evidence: {evidence})")
                        elif is_cdn and not any(
                                c_item == tech_provider_name or c_item.startswith(tech_provider_name) for c_item in
                                tech_results["cdn_providers"]):
                            tech_results["cdn_providers"].append(
                                f"{tech_provider_name} (Header/Cookie Signature: {evidence})")
                            logger.info(f"CDN Detected (Manual Signature): {tech_provider_name} (Evidence: {evidence})")
                        break  # Move to next WAF provider signature set

            if tech_results["waf_detected"]:
                waf_names_summary = sorted(list(set(w['name'] for w in tech_results['waf_detected'])))
                add_finding(tech_results, "waf_detection_summary",
                            # Using add_finding to self.results["technology_fingerprint"]
                            {"type": "WAF Presence Detected",
                             "description": f"Web Application Firewall(s) detected: {', '.join(waf_names_summary)}. This may impact scan results or indicate protection levels.",
                             "severity": "Info", "confidence": "Medium",
                             "details": {"detected_wafs": tech_results["waf_detected"]}},
                            log_message=f"WAFs detected: {', '.join(waf_names_summary)}", severity_for_log="INFO")

        server_header = headers.get("Server")
        if server_header:
            normalized_server_header = server_header.strip()
            if normalized_server_header not in tech_results["server_software"]: tech_results["server_software"].append(
                normalized_server_header)
            match = re.search(r"([\w.-]+)(?:[/\s-]([0-9.]+[\w.-]*))?", normalized_server_header)
            if match:
                sw_name, sw_version = match.group(1), match.group(2) if len(match.groups()) > 1 and match.group(
                    2) else "Unknown"
                if sw_name and (sw_name not in tech_results["software_versions_found"] or (
                        tech_results["software_versions_found"].get(sw_name) == "Unknown" and sw_version != "Unknown")):
                    tech_results["software_versions_found"][sw_name] = sw_version

        x_powered_by = headers.get("X-Powered-By")
        if x_powered_by:
            normalized_xpb = x_powered_by.strip()
            if normalized_xpb not in tech_results["x_powered_by"]: tech_results["x_powered_by"].append(normalized_xpb)
            match_xpb = re.search(r"([\w.-]+)(?:[/\s-]([0-9.]+[\w.-]*))?", normalized_xpb)
            if match_xpb:
                lang_name, lang_version = match_xpb.group(1), match_xpb.group(2) if len(
                    match_xpb.groups()) > 1 and match_xpb.group(2) else "Unknown"
                if lang_name and (lang_name not in tech_results["software_versions_found"] or (
                        tech_results["software_versions_found"].get(
                                lang_name) == "Unknown" and lang_version != "Unknown")):
                    tech_results["software_versions_found"][lang_name] = lang_version
                if lang_name and lang_name not in tech_results["programming_languages_detected"]: tech_results[
                    "programming_languages_detected"].append(lang_name)

        if not tech_results["cms_identified"] and self._main_page_soup_cache:
            for cms_name_iter, checks in self.config["cms_specific_checks"].items():
                for sig in checks.get("signatures_in_html", []):
                    if self._main_page_soup_cache.find(string=re.compile(sig, re.IGNORECASE)) or \
                            self._main_page_soup_cache.find(attrs={"src": re.compile(sig, re.IGNORECASE)}) or \
                            self._main_page_soup_cache.find(attrs={"href": re.compile(sig, re.IGNORECASE)}):
                        tech_results["cms_identified"] = cms_name_iter
                        logger.info(f"CMS identified by HTML signature: {cms_name_iter}")
                        break
                if tech_results["cms_identified"]: break

        if tech_results["software_versions_found"]:
            tech_results["software_version_cve_search_links"] = {}
            for sw, ver in tech_results["software_versions_found"].items():
                if ver and ver != "Unknown":
                    tech_results["software_version_cve_search_links"][f"{sw} {ver}"] = generate_vuln_search_url(sw, ver)
        logger.info("Technology fingerprinting complete.")

    async def analyze_web_content(self):
        logger.info("Analyzing web content from main page...")
        if not self._main_page_soup_cache or self._main_page_html_cache is None:
            logger.warning("Main page Soup/HTML not available, web content analysis will be limited.")
            return

        soup = self._main_page_soup_cache
        content_results = self.results["content_analysis"]
        html_content_for_regex = self._main_page_html_cache

        title_tag = soup.find("title")
        if title_tag and title_tag.string: content_results["page_title"] = title_tag.string.strip()
        desc_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if desc_tag and desc_tag.get("content"): content_results["meta_description"] = desc_tag["content"].strip()
        keywords_tag = soup.find("meta", attrs={"name": re.compile(r"keywords", re.I)})
        if keywords_tag and keywords_tag.get("content"): content_results["meta_keywords"] = keywords_tag[
            "content"].strip()

        email_pattern = r"[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        content_results["emails_on_page"] = sorted(list(set(re.findall(email_pattern, html_content_for_regex))))

        phone_pattern = r'(?:\+?\d{1,4}[-.\s]?)?(?:\(?\d{1,5}\)?[-.\s]?)?\d{2,5}[-.\s]?\d{2,5}(?:[-.\s]?\d{1,5})?'
        potential_phones = re.findall(phone_pattern, html_content_for_regex)
        valid_phones = []
        for p_phone in potential_phones:  # Filter out things like IP addresses, version numbers
            digits_only = re.sub(r'\D', '', p_phone)
            if 7 <= len(digits_only) <= 15:  # Common phone number length range
                if not (p_phone.count('.') > 2 and re.match(r'^\d+(\.\d+){2,}$',
                                                            p_phone)):  # Avoid version numbers like 1.2.3.4
                    valid_phones.append(p_phone.strip())
        content_results["phone_numbers_on_page"] = sorted(list(set(valid_phones)))

        social_media_domains = ["twitter.com", "facebook.com", "linkedin.com", "instagram.com", "youtube.com",
                                "github.com", "t.me", "wa.me", "pinterest.com", "tiktok.com", "reddit.com",
                                "medium.com", "discord.gg", "discord.com/invite", "threads.net", "behance.net",
                                "dribbble.com"]
        social_links, internal_links, external_links = set(), set(), set()
        doc_extensions = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.xml', '.json',
                          '.md', '.log', '.cfg', '.ini', '.yaml', '.rtf', '.odt', '.ods', '.odp', '.svg', '.eps',
                          '.sql', '.bak', '.zip', '.tar.gz', '.rar', '.7z', '.ics', '.vcf', '.key', '.pem', '.crt',
                          '.cer', '.jar', '.war')

        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url_for_join = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if not href or href.startswith("#") or href.lower().startswith("javascript:") or href.lower().startswith(
                    "mailto:") or href.lower().startswith("tel:"):
                continue
            full_url = urljoin(base_url_for_join, href)
            try:
                parsed_link = urlparse(full_url)
                if parsed_link.netloc == final_url_parsed.netloc:
                    internal_links.add(full_url)
                else:
                    if parsed_link.netloc:  # Ensure it's a valid external link with a netloc
                        external_links.add(full_url)
                        if any(sm_domain in parsed_link.netloc.lower() for sm_domain in social_media_domains):
                            social_links.add(full_url)
                if any(parsed_link.path.lower().endswith(ext) for ext in doc_extensions):
                    if full_url not in content_results["linked_documents"]: content_results["linked_documents"].append(
                        full_url)
            except ValueError:  # Handle malformed URLs that urlparse might struggle with after urljoin
                logger.debug(f"Malformed URL in <a> tag: {href}, resolved to {full_url}")

        content_results["internal_links_count"] = len(internal_links)
        content_results["external_links_count"] = len(external_links)
        content_results["social_media_links_on_page"] = sorted(list(social_links))

        comments = soup.find_all(string=lambda text: isinstance(text, BsComment))
        dev_comments = []
        for c in comments:
            comment_text = c.strip()
            if len(comment_text) > 10 and not comment_text.lower().startswith(
                    ("<![if", "[if", "status:", "googleoff:", "googleon:")):  # Filter out common non-dev comments
                dev_comments.append(comment_text)
        if dev_comments: content_results["developer_comments_found"] = dev_comments

        content_to_search_keys = html_content_for_regex + "\n".join(dev_comments)  # Search in HTML and comments
        for key_name, pattern in self.config["api_key_patterns"].items():
            try:
                for match in re.finditer(pattern, content_to_search_keys):
                    matched_val = match.group(0)
                    if any(skip_kw in matched_val.lower() for skip_kw in
                           ["example", "placeholder", "test", "xxxx", "your_api_key", "sample", "demo", "token_here",
                            "not_a_real_key", "api-key-goes-here"]): continue
                    context_snippet = content_to_search_keys[max(0, match.start() - 50):min(len(content_to_search_keys),
                                                                                            match.end() + 50)].replace(
                        "\n", " ")
                    api_key_info = {"key_name": key_name, "matched_value_preview": matched_val[:20] + (
                        "..." if len(matched_val) > 20 else ""), "source_context": "HTML/Comment",
                                    "context_snippet": context_snippet}
                    if not any(
                            k_info.get("matched_value_preview") == api_key_info["matched_value_preview"] and k_info.get(
                                    "key_name") == key_name and k_info.get("source_context") == "HTML/Comment" for
                            k_info in content_results["suspected_api_keys"]):
                        content_results["suspected_api_keys"].append(api_key_info)
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Sensitive Data Exposure",
                                     "description": f"Potential API key/secret ('{key_name}') found in page source or HTML comments.",
                                     "severity": "Medium", "confidence": "Medium", "details": api_key_info,
                                     "target_url": self.results["general_info"]["final_url"],
                                     "recommendation": f"Verify if '{key_name}' is a live credential. If so, revoke and investigate. Avoid hardcoding secrets in client-side content."},
                                    log_message=f"Potential API key '{key_name}' found in HTML/comments",
                                    severity_for_log="MEDIUM")
            except re.error as ree_api:
                logger.error(f"Regex error for API key pattern '{key_name}': {ree_api}")

        content_results["forms_found_count"] = len(soup.find_all("form"))
        js_links = set()
        for s_tag in soup.find_all("script", src=True):
            js_src = s_tag.get("src")
            if js_src and not js_src.startswith(("data:", "javascript:")):
                js_links.add(urljoin(base_url_for_join, js_src))
        content_results["javascript_files"]["count"] = len(js_links)
        content_results["javascript_files"]["files"] = sorted(list(js_links))

        css_links = set()
        for l_tag in soup.find_all("link", rel="stylesheet", href=True):
            css_href = l_tag.get("href")
            if css_href and not css_href.startswith("data:"):
                css_links.add(urljoin(base_url_for_join, css_href))
        content_results["css_files_count"] = len(css_links)
        logger.info("Web content analysis complete.")

    async def fetch_ads_txt_files(self):
        logger.info("Fetching ads.txt and app-ads.txt...")
        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"

        ads_txt_url = urljoin(base_url, "/ads.txt")
        app_ads_txt_url = urljoin(base_url, "/app-ads.txt")

        response_ads, content_ads = await self._make_request(ads_txt_url)
        if response_ads and response_ads.status == 200 and content_ads:
            try:
                self.results["content_analysis"]["ads_txt_content"] = content_ads.decode(
                    response_ads.charset or 'utf-8', errors='replace')
            except Exception as e_decode_ads:
                self.results["content_analysis"]["ads_txt_content"] = f"Error decoding content: {e_decode_ads}"
                logger.warning(f"Failed to decode ads.txt from {ads_txt_url}: {e_decode_ads}")
        else:
            self.results["content_analysis"][
                "ads_txt_content"] = f"Not found or not accessible (Status: {response_ads.status if response_ads else 'N/A'})."

        response_app_ads, content_app_ads = await self._make_request(app_ads_txt_url)
        if response_app_ads and response_app_ads.status == 200 and content_app_ads:
            try:
                self.results["content_analysis"]["app_ads_txt_content"] = content_app_ads.decode(
                    response_app_ads.charset or 'utf-8', errors='replace')
            except Exception as e_decode_app_ads:
                self.results["content_analysis"]["app_ads_txt_content"] = f"Error decoding content: {e_decode_app_ads}"
                logger.warning(f"Failed to decode app-ads.txt from {app_ads_txt_url}: {e_decode_app_ads}")
        else:
            self.results["content_analysis"][
                "app_ads_txt_content"] = f"Not found or not accessible (Status: {response_app_ads.status if response_app_ads else 'N/A'})."
        logger.info("ads.txt and app-ads.txt fetching complete.")

    async def fetch_and_analyze_robots_txt(self):
        logger.info("Fetching and analyzing robots.txt...")
        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        robots_url = urljoin(f"{final_url_parsed.scheme}://{final_url_parsed.netloc}", "/robots.txt")

        response, content_bytes = await self._make_request(robots_url)
        if response and response.status == 200 and content_bytes:
            try:
                self._robots_txt_cache = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                self.results["content_analysis"]["robots_txt_content"] = self._robots_txt_cache

                sitemaps_in_robots = re.findall(r"Sitemap:\s*(.*)", self._robots_txt_cache, re.IGNORECASE)
                for sm_url in sitemaps_in_robots:
                    sm_url_clean = sm_url.strip()
                    if sm_url_clean:
                        if sm_url_clean not in self.results["content_analysis"]["sitemap_urls_found"]:
                            self.results["content_analysis"]["sitemap_urls_found"].append(sm_url_clean)
                        if sm_url_clean not in self._processed_sitemap_urls and sm_url_clean not in list(
                                self._sitemap_processing_queue._queue):
                            await self._sitemap_processing_queue.put(sm_url_clean)

                disallowed_paths = [line.split(":", 1)[1].strip() for line in self._robots_txt_cache.splitlines() if
                                    line.lower().strip().startswith("disallow:") and len(line.split(":", 1)) > 1 and
                                    line.split(":", 1)[1].strip()]
                if disallowed_paths:
                    self.results["content_analysis"].setdefault("robots_disallowed_paths", []).extend(disallowed_paths)
                    self.results["content_analysis"]["robots_disallowed_paths"] = sorted(
                        list(set(self.results["content_analysis"]["robots_disallowed_paths"])))

                    interesting_keywords = ["admin", "login", "config", "secret", "backup", "wp-admin", "includes",
                                            "cgi-bin", "api", "internal", "private", "test", "dev", "staging", "tmp",
                                            "temp", "log", "trace", "dump", "secret", "confidential", "etc", "shadow",
                                            "passwd", "htpasswd", "env", "settings", "database", "sql", "user",
                                            "account", "credit", "payment"]
                    for path in disallowed_paths:
                        if any(keyword in path.lower() for keyword in interesting_keywords):
                            add_finding(self.results["security_posture"], "vulnerability_findings",
                                        {"type": "Information Disclosure (Robots.txt)",
                                         "description": f"Potentially sensitive path '{path}' found disallowed in robots.txt. While disallowed for crawlers, it indicates existence and may hint at sensitive resources.",
                                         "severity": "Low", "confidence": "Medium", "target_url": robots_url,
                                         "evidence_summary": f"robots.txt Disallow: {path}",
                                         "recommendation": f"Review if '{path}' should be publicly discoverable via robots.txt. Robots.txt does not provide access control; ensure sensitive resources are properly secured server-side."},
                                        log_message=f"Interesting Disallowed path in robots.txt: {path}",
                                        severity_for_log="LOW")
            except Exception as e_robots:
                self.results["content_analysis"]["robots_txt_content"] = f"Error parsing robots.txt: {e_robots}"
                logger.error(f"Error parsing robots.txt content from {robots_url}: {e_robots}")
        else:
            status_code_robots = response.status if response else "N/A (Fetch Failed)"
            self.results["content_analysis"][
                "robots_txt_content"] = f"Not found or not accessible (Status: {status_code_robots})."
            if status_code_robots == 404:
                logger.info(f"robots.txt not found at {robots_url} (HTTP 404).")
            elif status_code_robots != "N/A (Fetch Failed)":
                logger.warning(f"robots.txt at {robots_url} returned status {status_code_robots}.")
        logger.info("robots.txt analysis complete.")

    async def discover_and_fetch_sitemaps(self):
        logger.info("Discovering sitemaps (common paths, robots.txt output, HTML links)...")
        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"
        common_sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz", "/sitemap_index.xml.gz",
                                "/sitemap.txt", "/sitemaps.xml", "/gss/sitemap.xml", "/sitemap-index.xml",
                                "/sitemapindex.xml", "/sitemap.php", "/post-sitemap.xml", "/page-sitemap.xml",
                                "/category-sitemap.xml", "/product-sitemap.xml", "/news-sitemap.xml",
                                "/video-sitemap.xml", "/image-sitemap.xml", "/sitemap", "/sitemap/index.xml",
                                "/sitemap.ashx", "/sitemap.axd"]

        for common_path in common_sitemap_paths:
            full_sitemap_url = urljoin(base_url, common_path)
            if full_sitemap_url not in self._processed_sitemap_urls and full_sitemap_url not in list(
                    self._sitemap_processing_queue._queue):
                await self._sitemap_processing_queue.put(full_sitemap_url)

        if self._main_page_soup_cache:  # Check links in main page
            for link_tag in self._main_page_soup_cache.find_all(['a', 'link'], href=True):
                href = link_tag.get('href', '')
                if 'sitemap' in href.lower() and any(
                        href.lower().endswith(ext) for ext in ['.xml', '.xml.gz', '.txt', '.php']):
                    linked_sitemap_url = urljoin(base_url, href)
                    if linked_sitemap_url not in self._processed_sitemap_urls and linked_sitemap_url not in list(
                            self._sitemap_processing_queue._queue):
                        await self._sitemap_processing_queue.put(linked_sitemap_url)
        logger.info("Sitemap discovery phase complete. Queued sitemaps will be processed iteratively.")

    async def _process_sitemap_url(self, sitemap_url_to_check: str, all_urls_from_sitemaps: set):
        if sitemap_url_to_check in self._processed_sitemap_urls: return
        self._processed_sitemap_urls.add(sitemap_url_to_check)
        logger.debug(f"Processing sitemap URL: {sitemap_url_to_check}")

        sitemap_timeout = aiohttp.ClientTimeout(
            total=max(45, self.config["request_timeout_seconds"] + 15))  # Longer timeout for large sitemaps
        response, content_bytes = await self._make_request(sitemap_url_to_check, timeout_override=sitemap_timeout)

        if response and response.status == 200 and content_bytes:
            if sitemap_url_to_check not in self.results["content_analysis"]["sitemap_urls_found"]:
                self.results["content_analysis"]["sitemap_urls_found"].append(sitemap_url_to_check)

            sitemap_content_str = ""
            try:
                if sitemap_url_to_check.endswith(".gz"):
                    sitemap_content_str = gzip.decompress(content_bytes).decode(response.charset or 'utf-8',
                                                                                errors='replace')
                else:
                    sitemap_content_str = content_bytes.decode(response.charset or 'utf-8', errors='replace')
            except Exception as e_decode:
                logger.warning(f"Failed to decode sitemap {sitemap_url_to_check}: {e_decode}");
                return

            is_xml_sitemap = sitemap_url_to_check.endswith((".xml", ".xml.gz")) or \
                             "<urlset" in sitemap_content_str[:500].lower() or \
                             "<sitemapindex" in sitemap_content_str[:500].lower()

            if is_xml_sitemap:
                try:
                    sitemap_soup = BeautifulSoup(sitemap_content_str, 'xml')  # Use 'xml' parser
                    sitemap_index_entries = sitemap_soup.find_all("sitemap")  # For sitemap index files
                    if sitemap_index_entries:
                        for s_loc_tag in sitemap_index_entries:
                            loc_tag = s_loc_tag.find("loc")
                            if loc_tag and loc_tag.string:
                                nested_sitemap_url = loc_tag.string.strip()
                                if nested_sitemap_url not in self._processed_sitemap_urls and nested_sitemap_url not in list(
                                        self._sitemap_processing_queue._queue):
                                    await self._sitemap_processing_queue.put(nested_sitemap_url)
                        return  # This was an index, URLs are in nested sitemaps
                    url_entries = sitemap_soup.find_all("url")  # For regular sitemaps
                    for url_entry_tag in url_entries:
                        loc_tag = url_entry_tag.find("loc")
                        if loc_tag and loc_tag.string: all_urls_from_sitemaps.add(loc_tag.string.strip())
                except Exception as e_xml_parse:
                    logger.warning(f"Error parsing XML sitemap {sitemap_url_to_check}: {e_xml_parse}")
            elif sitemap_url_to_check.endswith(".txt") or not is_xml_sitemap:  # Treat as text sitemap
                for line in sitemap_content_str.splitlines():
                    line_stripped = line.strip()
                    if line_stripped.startswith("http"): all_urls_from_sitemaps.add(line_stripped)

        elif response and 300 <= response.status < 400:  # Handle redirects
            redirected_sitemap_url = response.headers.get("Location")
            if redirected_sitemap_url:
                full_redirect_url = urljoin(sitemap_url_to_check, redirected_sitemap_url)
                logger.info(f"Sitemap {sitemap_url_to_check} redirected to {full_redirect_url}. Adding to queue.")
                if full_redirect_url not in self._processed_sitemap_urls and full_redirect_url not in list(
                        self._sitemap_processing_queue._queue):
                    await self._sitemap_processing_queue.put(full_redirect_url)
        else:
            status_code_sitemap = response.status if response else 'N/A (Fetch Failed)'
            # Log less verbosely for common non-existent index files if main sitemap.xml was already processed.
            is_common_index_variant = "_index" in sitemap_url_to_check or "sitemaps.xml" in sitemap_url_to_check
            base_sitemap_url = urljoin(sitemap_url_to_check, "/sitemap.xml")
            if not (
                    status_code_sitemap == 404 and is_common_index_variant and base_sitemap_url in self._processed_sitemap_urls):
                logger.warning(
                    f"Failed to fetch or invalid sitemap: {sitemap_url_to_check} (Status: {status_code_sitemap})")

    async def _process_sitemap_queue_iteratively(self):
        logger.info(
            f"Starting iterative processing of sitemap queue (Initial size: {self._sitemap_processing_queue.qsize()})...")
        all_urls_from_sitemaps: set[str] = set()
        max_iterations = 100;
        iterations = 0  # Limit iterations to prevent infinite loops with malformed sitemaps

        while not self._sitemap_processing_queue.empty() and iterations < max_iterations:
            sitemap_url = await self._sitemap_processing_queue.get()
            if sitemap_url not in self._processed_sitemap_urls:
                await self._process_sitemap_url(sitemap_url, all_urls_from_sitemaps)
            self._sitemap_processing_queue.task_done()
            iterations += 1

        if iterations >= max_iterations and not self._sitemap_processing_queue.empty():
            logger.warning(
                f"Sitemap processing reached max iterations ({max_iterations}) with {self._sitemap_processing_queue.qsize()} items still in queue.")

        if all_urls_from_sitemaps:
            self.results["content_analysis"]["sitemap_extracted_url_count"] = len(all_urls_from_sitemaps)
            sample_size = 100
            self.results["content_analysis"]["sitemap_extracted_url_sample"] = sorted(list(all_urls_from_sitemaps))[
                                                                               :sample_size]
            if len(all_urls_from_sitemaps) > sample_size:
                self.results["content_analysis"]["sitemap_extracted_url_sample"].append(
                    f"... and {len(all_urls_from_sitemaps) - sample_size} more URLs.")

        if not isinstance(self.results["content_analysis"]["sitemap_urls_found"], list):
            self.results["content_analysis"]["sitemap_urls_found"] = []  # Ensure it's a list
        if not self.results["content_analysis"]["sitemap_urls_found"] and not all_urls_from_sitemaps:
            self.results["content_analysis"]["sitemap_urls_found"] = [
                "None found or accessible after processing all potential sitemap locations."]
        logger.info("Sitemap processing complete.")

    async def perform_ssl_tls_analysis(self):
        logger.info(f"Performing SSL/TLS analysis for {self.domain} (if applicable)...")
        parsed_final_ssl_url = urlparse(self.results["general_info"]["final_url"])

        if parsed_final_ssl_url.scheme != "https":
            self.results["security_posture"]["ssl_tls_config"] = {"status": "Target is not HTTPS. SSL/TLS analysis skipped."}
            logger.info(f"Target {self.results['general_info']['final_url']} is not HTTPS. Skipping SSL/TLS analysis.")
            return

        target_host_for_ssl = parsed_final_ssl_url.hostname
        target_port_for_ssl = parsed_final_ssl_url.port or 443

        if not target_host_for_ssl:
            self.results["security_posture"]["ssl_tls_config"] = {"error": "No valid hostname extracted from final URL for SSL check."}
            logger.error("Cannot perform SSL/TLS analysis: No valid hostname.")
            return

        writer = None # Initialize writer to None
        try:
            ssl_context_for_check = ssl.create_default_context()
            conn_timeout = self.config["dns_timeout_seconds"] + 15 # Generous timeout for SSL handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=target_host_for_ssl, port=target_port_for_ssl, ssl=ssl_context_for_check, server_hostname=target_host_for_ssl),
                timeout=conn_timeout
            )
            peer_cert = writer.get_extra_info('peercert')
            ssl_object = writer.get_extra_info('ssl_object')

            if not peer_cert or not ssl_object:
                self.results["security_posture"]["ssl_tls_config"] = {"error": "Failed to retrieve certificate or SSL object details."}
                logger.error(f"Could not get peercert or ssl_object for {target_host_for_ssl}:{target_port_for_ssl}")
                if writer and not writer.is_closing(): writer.close(); await writer.wait_closed()
                return

            ssl_info = {
                "issuer": dict(x[0] for x in peer_cert.get("issuer", []) if x and len(x)>0),
                "subject": dict(x[0] for x in peer_cert.get("subject", []) if x and len(x)>0),
                "valid_from": peer_cert.get("notBefore"), "valid_until": peer_cert.get("notAfter"),
                "serial_number": peer_cert.get("serialNumber"), "version": peer_cert.get("version"),
                "subject_alt_names": [name[1] for name in peer_cert.get("subjectAltName", []) if name and len(name)>1],
                "ocsp_responders": peer_cert.get("OCSP", []), "ca_issuers": peer_cert.get("caIssuers", []),
                "crl_distribution_points": peer_cert.get("crlDistributionPoints", []),
                "cipher_suite_used": ssl_object.cipher()[0] if ssl_object.cipher() else "Unknown",
                "tls_version_used": ssl_object.version() if ssl_object.version() else "Unknown",
                "signature_algorithm": peer_cert.get("signatureAlgorithm", "Unknown")
            }
            self.results["security_posture"]["ssl_tls_config"] = ssl_info

            if ssl_info["valid_until"]:
                try:
                    expiry_date_str = ssl_info["valid_until"]
                    # Standardize parsing of the date string which can vary slightly
                    expiry_date_utc = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    days_to_expiry = (expiry_date_utc - now_utc).days
                    ssl_info["days_to_expiry"] = days_to_expiry

                    if expiry_date_utc < now_utc:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue (Expired Cert)", "description": f"SSL/TLS certificate for {target_host_for_ssl} has expired on {expiry_date_str}.", "severity": "High", "confidence":"High", "recommendation": "Renew the SSL/TLS certificate immediately."},
                                    log_message=f"SSL certificate EXPIRED for {target_host_for_ssl}", severity_for_log="HIGH")
                    elif days_to_expiry < 14:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue (Expiring Soon)", "description": f"SSL/TLS certificate for {target_host_for_ssl} is expiring in {days_to_expiry} days (on {expiry_date_str}).", "severity": "Medium", "confidence":"High", "recommendation": "Renew the SSL/TLS certificate very soon."},
                                    log_message=f"SSL cert for {target_host_for_ssl} expiring in {days_to_expiry} days", severity_for_log="MEDIUM")
                    elif days_to_expiry < 30:
                         add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "SSL/TLS Issue (Expiring)", "description": f"SSL/TLS certificate for {target_host_for_ssl} is expiring in {days_to_expiry} days (on {expiry_date_str}).", "severity": "Low", "confidence":"High", "recommendation": f"Plan to renew the SSL/TLS certificate for {target_host_for_ssl} before expiry."},
                                    log_message=f"SSL cert for {target_host_for_ssl} expiring in {days_to_expiry} days", severity_for_log="LOW")
                except ValueError as e_date:
                    logger.warning(f"Could not parse SSL certificate expiry date '{ssl_info['valid_until']}' for {target_host_for_ssl}: {e_date}")
                    ssl_info["days_to_expiry"] = "Error parsing date"

            weak_sig_algos = ["sha1WithRSAEncryption", "md5WithRSAEncryption", "sha1", "md5", "md2", "ecdsa-with-SHA1"]
            sig_algo_lower = ssl_info.get("signature_algorithm", "").lower()
            if any(weak_algo.lower() in sig_algo_lower for weak_algo in weak_sig_algos):
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "SSL/TLS Issue (Weak Signature)", "description": f"SSL/TLS certificate for {target_host_for_ssl} uses a weak signature algorithm: {ssl_info.get('signature_algorithm')}.", "severity": "Medium", "confidence":"High", "recommendation": "Reissue the certificate using a strong signature algorithm (e.g., SHA256withRSA or ECDSA with SHA256)."},
                            log_message=f"Weak SSL cert signature: {ssl_info.get('signature_algorithm')} for {target_host_for_ssl}", severity_for_log="MEDIUM")

            tls_version_used = ssl_info.get("tls_version_used", "")
            if tls_version_used in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]: # SSLv2 is extremely rare but check
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "SSL/TLS Issue (Weak Protocol)", "description": f"Connection to {target_host_for_ssl} established using an outdated/weak protocol: {tls_version_used}. Modern standard is TLS 1.2 or TLS 1.3.", "severity": "Medium", "confidence":"High", "recommendation": "Configure server to support only TLS 1.2 and TLS 1.3, and disable older protocols like TLS 1.0/1.1 and SSLv3."},
                            log_message=f"Outdated/Weak TLS protocol used for {target_host_for_ssl}: {tls_version_used}", severity_for_log="MEDIUM")
            if writer and not writer.is_closing(): writer.close(); await writer.wait_closed()
        except ssl.SSLCertVerificationError as e_ssl_verify:
            verify_msg_raw = str(e_ssl_verify.reason if hasattr(e_ssl_verify, 'reason') else e_ssl_verify.strerror if hasattr(e_ssl_verify, 'strerror') else str(e_ssl_verify))
            verify_msg = "Unknown Verification Error"
            if "hostname mismatch" in verify_msg_raw.lower(): verify_msg = "Hostname mismatch"
            elif "self-signed certificate" in verify_msg_raw.lower(): verify_msg = "Self-signed certificate"
            elif "certificate verify failed" in verify_msg_raw.lower():
                if "unable to get local issuer certificate" in verify_msg_raw.lower(): verify_msg = "Untrusted CA / Incomplete Chain"
                else: verify_msg = "Certificate verification failed (General)"
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Certificate Verification Failed: {verify_msg} ({verify_msg_raw})"}
            add_finding(self.results["security_posture"], "vulnerability_findings",
                        {"type": "SSL/TLS Issue (Verification)", "description": f"SSL/TLS Certificate Verification Error for {target_host_for_ssl}: {verify_msg}.", "severity": "High", "confidence":"High", "recommendation": f"Investigate the certificate chain for {target_host_for_ssl}. Ensure it's valid, trusted, matches hostname, and full chain is served."},
                        log_message=f"SSL cert verification error ({verify_msg}) for {target_host_for_ssl}", severity_for_log="HIGH")
        except socket.gaierror as e_gaierr:
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"DNS resolution failed for {target_host_for_ssl} during SSL check: {e_gaierr}"}
            logger.error(f"DNS resolution failed for {target_host_for_ssl} during SSL check: {e_gaierr}")
        except ConnectionRefusedError:
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Connection refused by {target_host_for_ssl}:{target_port_for_ssl} during SSL check."}
            logger.warning(f"Connection refused for SSL check on {target_host_for_ssl}:{target_port_for_ssl}")
        except asyncio.TimeoutError:
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Timeout connecting to {target_host_for_ssl}:{target_port_for_ssl} for SSL check."}
            logger.warning(f"SSL check timed out for {target_host_for_ssl}:{target_port_for_ssl}")
        except Exception as e_ssl_generic:
            self.results["security_posture"]["ssl_tls_config"] = {"error": f"Unexpected SSL Error: {type(e_ssl_generic).__name__} - {e_ssl_generic}"}
            logger.error(f"Unexpected SSL error for {target_host_for_ssl}: {e_ssl_generic}", exc_info=True)
        finally:
            if writer and not writer.is_closing():
                writer.close(); await writer.wait_closed()

    async def check_http_options_and_auth(self):
        logger.info(f"Checking HTTP OPTIONS and authentication for {self.results['general_info']['final_url']}...")
        response, _ = await self._make_request(self.results["general_info"]["final_url"], method="OPTIONS", allow_redirects=False)

        if response:
            allow_header = response.headers.get("Allow")
            if allow_header:
                allowed_methods = sorted(list(set([method.strip().upper() for method in allow_header.split(',')])))
                self.results["http_details"]["allowed_methods"] = allowed_methods
                risky_methods_found = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'OPTIONS'}.intersection(allowed_methods) # OPTIONS is risky if it reveals too much
                if risky_methods_found:
                    for risky_method in risky_methods_found:
                        sev = "Medium" if risky_method in ['PUT', 'DELETE', 'PATCH', 'TRACE'] else "Low"
                        desc = f"Potentially risky HTTP method '{risky_method}' is listed in 'Allow' header for {response.url}."
                        recomm = f"Ensure '{risky_method}' is intentionally enabled and secured (strong auth/authz). Disable if not necessary."
                        if risky_method == 'TRACE': desc += " TRACE can be used in Cross-Site Tracing (XST)."
                        if risky_method == 'OPTIONS' and len(allowed_methods) > 3 : desc += " OPTIONS itself can reveal server capabilities." # Many methods listed via OPTIONS
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "HTTP Method Information", "description": desc, "severity": sev, "confidence":"High", "details":{"method": risky_method, "url_checked": str(response.url), "all_allowed": allowed_methods}, "recommendation": recomm},
                                    log_message=f"Risky HTTP method '{risky_method}' enabled on {response.url}", severity_for_log=sev.upper())
            else:
                self.results["http_details"]["allowed_methods"] = ["N/A (No 'Allow' header in OPTIONS response)"]

            www_auth_header_options = response.headers.get("WWW-Authenticate")
            www_auth_header_main = self._main_page_response_cache[0].headers.get("WWW-Authenticate") if self._main_page_response_cache and self._main_page_response_cache[0] else None
            effective_www_auth = www_auth_header_options or www_auth_header_main
            source_auth = ""
            if www_auth_header_options: source_auth = "OPTIONS response"
            elif www_auth_header_main: source_auth = "main page response"

            if effective_www_auth:
                auth_type_match = re.match(r"(\w+)", effective_www_auth) # Get first word (e.g., Basic, Digest)
                auth_type = auth_type_match.group(1) if auth_type_match else "Unknown"
                self.results["security_posture"]["http_auth_type"] = auth_type
                log_msg_auth = f"HTTP {auth_type} auth found (Header: '{effective_www_auth[:30]}...', Source: {source_auth})"
                finding_desc_auth = f"HTTP {auth_type} authentication detected via WWW-Authenticate header (from {source_auth}). Full header: '{effective_www_auth}'."
                recomm_auth = f"Ensure '{auth_type}' auth is robust. Basic Auth transmits credentials in cleartext (Base64) - use only over HTTPS. Digest is better but has weaknesses. Modern token-based/federated auth preferred."
                sev_auth = "Medium" if auth_type.lower() == "basic" and self.scheme != "https" else ("Low" if auth_type.lower() == "basic" and self.scheme == "https" else "Info")
                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Authentication Mechanism Detected", "description": finding_desc_auth, "severity": sev_auth, "confidence":"High", "details":{"auth_header": effective_www_auth, "source": source_auth, "auth_type_detected": auth_type}, "recommendation": recomm_auth},
                            log_message=log_msg_auth, severity_for_log=sev_auth.upper())
        else:
            logger.warning(f"OPTIONS request to {self.results['general_info']['final_url']} failed or returned no response.")
            self.results["http_details"]["allowed_methods"] = ["N/A (OPTIONS request failed)"]

    async def scan_for_open_ports(self):
        if not self.config.get("enable_nmap_scan", True) or not NMAP_AVAILABLE:
            self.results["security_posture"]["open_ports"] = [{"status": "Skipped - Nmap scan disabled or python-nmap library not found."}]
            if not NMAP_AVAILABLE: logger.info("Nmap scan skipped: python-nmap library not found.")
            return
        if not self.results["general_info"]["ip_addresses"]:
            self.results["security_posture"]["open_ports"] = [{"status": "Skipped - No IP addresses resolved for Nmap scan."}]
            logger.warning("Nmap scan skipped: No IP addresses were resolved for the target domain.")
            return

        target_ip = next((ip_info["ip"] for ip_info in self.results["general_info"]["ip_addresses"] if ip_info.get("version") == 4), self.results["general_info"]["ip_addresses"][0]["ip"] if self.results["general_info"]["ip_addresses"] else None)
        if not target_ip:
            self.results["security_posture"]["open_ports"] = [{"status": "Skipped - No valid IP address available for Nmap scan."}]
            logger.error("Nmap scan skipped: Could not determine a valid IP address from resolved IPs.")
            return

        ports_str = self.config.get('common_ports_to_scan', "80,443")
        nmap_args = f"-sV -T4 --open -Pn -p {ports_str}" # -Pn to scan even if host seems down (e.g., ICMP blocked)
        logger.info(f"Starting Nmap scan on IP {target_ip} (Ports: {ports_str}, Args: {nmap_args}). This may take some time...")

        try:
            nm_scanner = nmap.PortScanner()
            scan_results = await asyncio.to_thread(nm_scanner.scan, target_ip, arguments=nmap_args)

            if target_ip in scan_results.get('scan', {}):
                host_data = scan_results['scan'][target_ip]
                if 'tcp' in host_data:
                    for port, data in host_data['tcp'].items():
                        if data['state'] == 'open':
                            port_info = {"port": int(port), "protocol": "tcp", "state": data['state'], "service_name": data.get('name', 'unknown'), "product": data.get('product', ''), "version": data.get('version', ''), "extrainfo": data.get('extrainfo', ''), "cpe": data.get('cpe', '')}
                            self.results["security_posture"]["open_ports"].append(port_info)
                            logger.info(f"Open port (Nmap): {port_info['port']}/tcp - {port_info['service_name']} {port_info['product']} {port_info['version']}")

                            if port_info['product'] and (port_info['product'] not in self.results["technology_fingerprint"]["software_versions_found"] or port_info['version']):
                                version_key = f"{port_info['product']} (Port {port_info['port']})"
                                self.results["technology_fingerprint"]["software_versions_found"][version_key] = port_info['version'] if port_info['version'] else "Unknown"

                            if int(port) not in [80, 443]: # Flag non-standard web ports or other services
                                sev = "Low"; service_name_lower = port_info['service_name'].lower(); product_lower = (port_info['product'] or "").lower()
                                risky_service_keywords = ["ssh", "ftp", "telnet", "mysql", "postgres", "mongo", "redis", "rdp", "smb", "rpcbind", "vnc", "x11", "docker", "kubernetes", "jenkins", "gitlab", "elasticsearch", "kibana", "webmin", "cpanel", "directadmin", "plesk", "solr", "zookeeper", "kafka", "rabbitmq", "memcached", "activemq", "jmx", "rmi", "ldap", "snmp"]
                                if any(kw in service_name_lower or kw in product_lower for kw in risky_service_keywords):
                                    sev = "Medium"
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Network Service Exposure", "description": f"Service '{port_info['service_name']}' on port {port}/tcp. Product: {port_info['product']} {port_info['version']}.", "severity": sev, "confidence":"High", "details":port_info, "target_url": f"{target_ip}:{port}",
                                             "recommendation": f"Ensure service on port {port} is intentionally exposed and secured (strong auth, encryption, patched). If not needed externally, restrict via firewall."},
                                            log_message=f"Nmap found service {port_info['service_name']} on non-standard port {port}/tcp", severity_for_log=sev.upper())
                if not self.results["security_posture"]["open_ports"]:
                    self.results["security_posture"]["open_ports"].append({"status": f"No open TCP ports found in range {ports_str} on {target_ip}."})
            else:
                self.results["security_posture"]["open_ports"].append({"status": f"Nmap scan did not return data for {target_ip}."})
                logger.warning(f"Nmap scan for {target_ip} completed but no host data returned.")
        except nmap.nmap.PortScannerError as e_nmap_exec:
            self.results["security_posture"]["open_ports"].append({"error": f"Nmap executable/execution failed: {e_nmap_exec}. Ensure Nmap is installed and in PATH."})
            logger.error(f"Nmap PortScannerError: {e_nmap_exec}. Is Nmap installed and in your system's PATH?")
        except Exception as e_nmap:
            self.results["security_posture"]["open_ports"].append({"error": f"Nmap scan error: {type(e_nmap).__name__} - {e_nmap}"})
            logger.error(f"Unexpected Nmap error during scan of {target_ip}: {e_nmap}", exc_info=True)
        logger.info("Nmap scan finished.")

    async def scan_for_exposed_paths_and_files(self):
        logger.info("Scanning for common exposed sensitive paths and files...")
        if not self.results["general_info"]["final_url"]:
            logger.warning("Final URL not available, skipping exposed path scan.")
            return

        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"
        paths_to_check = []
        for category, path_list in self.config["sensitive_paths_categories"].items():
            if category == "security_txt_paths_list": continue # Handled separately
            for path_item in path_list: paths_to_check.append({"path": path_item, "category": category})

        async def check_path(path_info: dict):
            path_suffix = path_info["path"]; category = path_info["category"]
            target_url = urljoin(base_url, path_suffix.lstrip('/'))
            is_file_like = "." in path_suffix.split('/')[-1] or any(kw in category.lower() for kw in ["files", "archives", "log", "config"])

            resp_get, content_get = await self._make_request(target_url, method="GET", allow_redirects=False, max_retries=0)

            if resp_get:
                status = resp_get.status; content_len = len(content_get) if content_get is not None else int(resp_get.headers.get("Content-Length", 0)); content_type_header = resp_get.headers.get("Content-Type", "N/A").lower()

                if status == 200:
                    finding_details = {"path": path_suffix, "url": target_url, "status": status, "category": category, "length": content_len, "content_type": content_type_header}
                    sev = "High"; conf = "Medium"
                    if category in ["config_files", "backup_archives", "version_control_exposed", "credentials"]: sev = "Critical"; conf = "High"
                    elif category in ["log_files", "exposed_services_info"]: sev = "Medium"; conf = "Medium"
                    elif category in ["common_admin_interfaces", "sensitive_directories"]: sev = "Low"; conf = "Low"
                    desc = f"Potentially sensitive {'file' if is_file_like else 'resource/directory'} '{path_suffix}' (Category: {category}) is accessible (HTTP 200)."
                    recomm = f"Review resource at '{target_url}'. If sensitive or unintended, restrict access (server config, file perms, remove). For directories, disable listing."

                    if (not is_file_like or "html" in content_type_header) and content_get: # Check for directory listing signature
                        try:
                            page_text_lower = content_get.decode(resp_get.charset or 'utf-8', errors='replace').lower()
                            if any(s_listing.lower() in page_text_lower for s_listing in ['Index of /', '<h1>Index of', '<title>Index of', 'Parent Directory', 'To Parent Directory']):
                                if target_url not in self.results["security_posture"]["directory_listings_found"]:
                                    self.results["security_posture"]["directory_listings_found"].append(target_url)
                                desc += " (Directory listing detected)."
                                sev_dir_list="Medium"; recomm_dir_list = f"Directory listing enabled at '{target_url}'. Disable via server config (e.g., 'Options -Indexes' in Apache). Review listed files."
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Information Disclosure (Directory Listing)", "description": f"Directory listing found at: {target_url}",
                                             "severity": sev_dir_list, "confidence": "High", "target_url": target_url, "recommendation": recomm_dir_list},
                                            log_message=f"Directory listing at {target_url}", severity_for_log=sev_dir_list.upper())
                                return # Already logged specific directory listing
                        except UnicodeDecodeError: pass
                        except Exception as e_dir_list_check: logger.debug(f"Error checking for directory listing at {target_url}: {e_dir_list_check}")

                    # Avoid duplicate with dir listing if path is also in general exposed paths
                    if not any(f.get('description','').startswith("Directory listing found at") and f.get('target_url') == target_url for f in self.results["security_posture"].get("vulnerability_findings",[])):
                        if not any(exposed_file_item.get("url") == target_url for exposed_file_item in self.results["security_posture"]["exposed_sensitive_files"]):
                             self.results["security_posture"]["exposed_sensitive_files"].append(finding_details)
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Information Disclosure (Exposed Path)", "description": desc, "severity": sev, "confidence":conf, "details":finding_details, "target_url": target_url, "recommendation": recomm},
                                    log_message=f"Exposed path: {target_url} (Status {status}, Category: {category})", severity_for_log=sev.upper())

                elif status == 403: # Forbidden - indicates existence
                    if not any(f.get('url') == target_url and f.get('status') == 403 for f in self.results["security_posture"]["exposed_sensitive_files"]):
                        self.results["security_posture"]["exposed_sensitive_files"].append({"path": path_suffix, "url": target_url, "status": 403, "category": category, "length": content_len, "content_type": content_type_header})
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Information Disclosure (Path Existence)", "description": f"Path '{path_suffix}' (Category: {category}) exists but is Forbidden (HTTP 403).",
                                     "severity": "Low", "confidence": "High", "details": {"path": path_suffix, "url": target_url, "status": 403, "category": category}, "target_url": target_url,
                                     "recommendation": f"Path '{target_url}' (403 Forbidden) confirms existence. If path should not be discoverable, consider server configs to return 404 for unauthorized access to non-public paths, or rename/remove if not needed."},
                                    log_message=f"Forbidden (403) path (existence confirmed): {target_url}", severity_for_log="LOW")

        path_tasks = [check_path(p_info) for p_info in paths_to_check]
        if path_tasks: await self._execute_task_group(path_tasks, "Sensitive Path Scan")
        logger.info("Sensitive path scan complete.")

    async def check_for_version_control_exposure(self):
        logger.info("Checking for version control system exposure (.git, .svn, etc.)...")
        vc_paths_config = self.config["sensitive_paths_categories"].get("version_control_exposed", [])
        if not vc_paths_config:
            logger.info("No version control paths configured for checking.")
            return

        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"

        for path_suffix in vc_paths_config:
            vc_type = "Unknown"
            if ".git" in path_suffix.lower(): vc_type = "Git"
            elif ".svn" in path_suffix.lower(): vc_type = "SVN"
            elif ".hg" in path_suffix.lower(): vc_type = "Mercurial (Hg)"
            elif ".bzr" in path_suffix.lower(): vc_type = "Bazaar (Bzr)"

            vc_url = urljoin(base_url, path_suffix.lstrip('/'))
            response, content_bytes = await self._make_request(vc_url, allow_redirects=False, max_retries=0)

            if response and response.status == 200 and content_bytes:
                details_key = f"exposed_{vc_type.lower().replace(' (hg)', '_hg').replace(' (bzr)', '_bzr')}_details"
                if self.results["security_posture"].get(details_key) is None:
                    self.results["security_posture"][details_key] = []
                exposed_info = {"path": path_suffix, "url": vc_url, "status": 200, "length": len(content_bytes)}
                if not any(item.get("url") == vc_url for item in self.results["security_posture"][details_key]):
                    self.results["security_posture"][details_key].append(exposed_info)

                add_finding(self.results["security_posture"], "vulnerability_findings",
                            {"type": "Version Control Exposure", "description": f"Exposed {vc_type} artifact: '{path_suffix}'. This can leak source code, history, and potentially sensitive configuration or credentials.",
                             "severity": "Critical", "confidence": "High", "target_url": vc_url, "details": exposed_info,
                             "recommendation": f"Immediately restrict access to '{vc_url}' and entire .{vc_type.lower().split(' ')[0]}/ directory. Ensure web server rules block access. Audit exposed content for leakage and rotate compromised credentials."},
                            log_message=f"Exposed {vc_type} artifact: {vc_url}", severity_for_log="CRITICAL")

                if self.results["technology_fingerprint"]["version_control_type"] is None: # Set if not already set
                    self.results["technology_fingerprint"]["version_control_type"] = vc_type

                if vc_type == "Git" and GITPYTHON_AVAILABLE and path_suffix.endswith(".git/config"):
                    try:
                        config_content_str = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                        config_file_like = io.StringIO(config_content_str)
                        git_config = git.GitConfigParser(config_file_like, read_only=True)

                        if git_config.sections():
                            remotes = {}
                            for section in git_config.sections():
                                if section.startswith('remote "') and section.endswith('"'):
                                    remote_name = section.split('"')[1]
                                    remote_url_val = git_config.get(section, 'url', fallback=None)
                                    remote_fetch_val = git_config.get(section, 'fetch', fallback=None)
                                    if remote_url_val: remotes[remote_name] = {'url': remote_url_val, 'fetch': remote_fetch_val}
                            if remotes:
                                exposed_info["parsed_git_config_remotes"] = remotes
                                for r_name, r_details in remotes.items():
                                    if r_details.get('url'):
                                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                                    {"type": "Information Disclosure (Git Config)", "description": f"Git remote '{r_name}' URL exposed in .git/config: {r_details['url']}. May reveal repository location.",
                                                     "severity": "Medium", "confidence":"High", "target_url": vc_url, "details": {"remote_name": r_name, "remote_url": r_details['url']},
                                                     "recommendation": "If repository at exposed URL is private, ensure exposure is intended and access controls are robust. Consider if .git/config should be web-accessible."},
                                                    log_message=f"Git remote '{r_name}' URL in exposed .git/config: {r_details['url']}", severity_for_log="MEDIUM")
                        else:
                            logger.debug(f"Git config file at {vc_url} was empty or had no sections after parsing.")
                    except Exception as e_git_parse:
                        exposed_info["gitpython_analysis_error"] = str(e_git_parse)
                        logger.error(f"Error parsing .git/config with GitPython from {vc_url}: {e_git_parse}")
        logger.info("Version control exposure check complete.")

    async def scan_page_for_malware_signatures(self, content: str | None, source_url: str, content_type: str = "HTML Content"):
        if not content: return
        signatures_to_check = []
        if "javascript" in content_type.lower() or "html" in content_type.lower(): # Only check JS-relevant signatures in these content types
            signatures_to_check.extend(self.config.get("malware_js_signatures", []))
        if not signatures_to_check: return

        for sig_pattern in signatures_to_check:
            try:
                for match in re.finditer(sig_pattern, content, re.IGNORECASE | re.MULTILINE):
                    snippet = match.group(0)[:120] + ("..." if len(match.group(0)) > 120 else "")
                    sig_info = {"type": content_type, "pattern_name": sig_pattern, "matched_snippet": snippet, "source_url": source_url}
                    is_dup_malware = False
                    for existing_malware_sig in self.results["security_posture"]["malware_code_signatures"]:
                        if existing_malware_sig.get("pattern_name") == sig_pattern and existing_malware_sig.get("source_url") == source_url and existing_malware_sig.get("matched_snippet") == snippet:
                            is_dup_malware = True; break
                    if not is_dup_malware:
                        self.results["security_posture"]["malware_code_signatures"].append(sig_info)
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Suspicious Code Signature Detected", "description": f"Potential malware/suspicious code signature in {content_type} from {os.path.basename(source_url)}. Pattern: '{sig_pattern[:30]}...'.",
                                     "severity": "High", "confidence": "Medium", "target_url": source_url, "details": sig_info,
                                     "recommendation": f"Manually review code at '{source_url}' (around: '{snippet}') matching pattern '{sig_pattern}'. If malicious, remove and investigate. Consider server-side scanning and checking with tools like VirusTotal."},
                                    log_message=f"Malware/suspicious signature ({sig_pattern[:30]}...) in {source_url}", severity_for_log="HIGH")
            except re.error as re_err_malware:
                logger.error(f"Regex error with malware signature '{sig_pattern}' for {source_url}: {re_err_malware}")

    async def analyze_linked_javascript_files(self):
        if not self.config.get("enable_js_file_analysis", True):
            logger.info("JavaScript file analysis disabled in configuration.")
            return
        js_files_to_analyze = self.results["content_analysis"]["javascript_files"].get("files", [])
        if not js_files_to_analyze:
            logger.info("No linked JavaScript files found to analyze.")
            return
        logger.info(f"Analyzing {len(js_files_to_analyze)} linked JavaScript files (JSense Maxima - Regex + AST)...")

        max_js_size_for_regex_kb = self.config.get("js_analysis_max_file_size_kb", 1024)
        max_js_size_for_regex_bytes = max_js_size_for_regex_kb * 1024
        ast_config = self.config.get("js_ast_analysis_config", {})
        enable_ast_globally = ast_config.get("enabled", False) and ESPRIMA_AVAILABLE
        max_js_size_for_ast_kb = ast_config.get("max_file_size_kb_for_ast", 512)
        max_js_size_for_ast_bytes = max_js_size_for_ast_kb * 1024
        if not hasattr(self, '_js_logged_regex_findings_set'): self._js_logged_regex_findings_set = set() # To avoid excessive logging for same regex finding type

        async def analyze_single_js(js_url: str):
            if js_url in self._fetched_js_urls: logger.debug(f"Skipping already analyzed JS: {js_url}"); return
            self._fetched_js_urls.add(js_url)

            js_timeout = aiohttp.ClientTimeout(total=self.config.get("request_timeout_seconds",20) + 20) # Longer timeout for JS files
            response, content_bytes = await self._make_request(js_url, timeout_override=js_timeout)
            analysis_item = {"url": js_url, "status": "Fetch Failed", "size_bytes": 0, "regex_findings": [], "ast_analysis_status": "Not Attempted"}

            if response and response.status == 200 and content_bytes:
                analysis_item["status"] = "Partially Analyzed"; analysis_item["size_bytes"] = len(content_bytes); js_content = None
                try: js_content = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                except UnicodeDecodeError: analysis_item["status"] = "Regex/AST Analysis Failed (Decoding Error)"; logger.warning(f"Failed to decode JS content from {js_url}.")

                if js_content:
                    if len(content_bytes) > max_js_size_for_regex_bytes:
                        analysis_item["status"] += " | Regex Skipped (Too Large)"; logger.warning(f"JS file {js_url} ({len(content_bytes)/1024:.1f} KB) too large for regex (limit {max_js_size_for_regex_kb} KB).")
                    else:
                        analysis_item["status"] = "Analyzed (Regex)"
                        try:
                            await self.scan_page_for_malware_signatures(js_content, js_url, "JavaScript File")
                            for key_name, pattern in self.config["api_key_patterns"].items():
                                try:
                                    for match in re.finditer(pattern, js_content):
                                        val = match.group(0)
                                        if any(s_kw in val.lower() for s_kw in ["example", "placeholder", "test", "xxxx", "your_api_key", "sample", "demo", "token_here", "not_a_real_key", "api-key-goes-here"]): continue
                                        context = js_content[max(0, match.start() - 50):min(len(js_content), match.end() + 50)].replace("\n", " ")
                                        line_number = js_content.count('\n', 0, match.start()) + 1
                                        key_info = {"key_name": key_name, "matched_value_preview": val[:20] + "...", "source_js_url": js_url, "context_snippet": context, "source_type": "JS Regex", "line": line_number}
                                        if not any(k.get("matched_value_preview") == key_info["matched_value_preview"] and k.get("key_name") == key_name and k.get("source_js_url") == js_url and k.get("source_type") == "JS Regex" for k in self.results["content_analysis"]["suspected_api_keys"]):
                                            self.results["content_analysis"]["suspected_api_keys"].append(key_info)
                                            add_finding(self.results["security_posture"], "vulnerability_findings",
                                                        {"type": "Sensitive Data Exposure", "description": f"Potential API key/secret ('{key_name}') found in JS file: {os.path.basename(js_url)} (Regex).", "severity": "High", "confidence":"Medium", "target_url": js_url, "details":key_info, "recommendation": f"Verify if '{key_name}' in '{js_url}' (approx. line {line_number}) is live. If so, revoke and investigate. Avoid hardcoding secrets in client-side JS. Use backend proxies/token-based auth."},
                                                        log_message=f"Potential API key '{key_name}' in JS (Regex): {js_url}", severity_for_log="HIGH")
                                        analysis_item["regex_findings"].append({"type": f"API Key ({key_name})", "value_preview": val[:20] + "...", "line": line_number})
                                except re.error as re_err_api_js: logger.debug(f"Regex error for API key pattern '{key_name}' in JS {js_url}: {re_err_api_js}")

                            for find_type, js_pattern in self.config.get("js_interesting_patterns", {}).items():
                                try:
                                    for match in re.finditer(js_pattern, js_content, re.IGNORECASE | re.MULTILINE):
                                        found_item = (match.group(1) if match.groups() else match.group(0))[:150].strip()
                                        line_number = js_content.count('\n', 0, match.start()) + 1
                                        analysis_item["regex_findings"].append({"type": find_type, "match": found_item, "line": line_number})
                                        log_key_js_regex = (find_type, js_url, found_item[:50]) # Create a key for logging to avoid spam
                                        if log_key_js_regex not in self._js_logged_regex_findings_set:
                                            logger.info(f"JSense (Regex - {find_type}) in {os.path.basename(js_url)} line ~{line_number}: {found_item[:60]}...")
                                            self._js_logged_regex_findings_set.add(log_key_js_regex)

                                        if "endpoint" in find_type.lower() or "url" in find_type.lower() or "firebaseio.com" in found_item:
                                            add_finding(self.results["security_posture"], "potential_api_endpoints",
                                                        {"type": f"JS Discovery ({find_type})", "endpoint_or_info": found_item, "source_url": js_url, "severity": "Info", "confidence":"Low", "line": line_number, "recommendation": f"Review URL/endpoint '{found_item}' from '{js_url}' (line {line_number}) for intentional exposure and security."},
                                                        log_message=f"JS (Regex - {find_type}) in {js_url}: {found_item}", severity_for_log="INFO")
                                        elif "DOM XSS Sink" in find_type:
                                            add_finding(self.results["security_posture"], "vulnerability_findings",
                                                        {"type": "Potential DOM XSS (JS Regex)", "description": f"Potential DOM XSS sink pattern '{find_type}' found via regex in {os.path.basename(js_url)}.", "severity": "Low", "confidence":"Low", "target_url": js_url, "details":{"js_url": js_url, "pattern": js_pattern, "match": found_item, "line": line_number}, "recommendation": f"Manually review code at '{js_url}' (line {line_number}) around: '{found_item}'. Verify if user-controlled data can reach this sink without sanitization. Prefer AST-based findings."},
                                                        log_message=f"Potential DOM XSS (Regex - {find_type}) in {js_url}", severity_for_log="LOW")
                                except re.error as re_err_js_patterns: logger.debug(f"Regex error for JS pattern '{find_type}' in {js_url}: {re_err_js_patterns}")
                        except Exception as e_regex_js_block:
                            analysis_item["status"] = f"Regex Analysis Error: {type(e_regex_js_block).__name__}"; logger.error(f"Error during regex analysis of {js_url}: {e_regex_js_block}")

                    if enable_ast_globally and js_content:
                        if len(content_bytes) > max_js_size_for_ast_bytes:
                            analysis_item["ast_analysis_status"] = f"Skipped (Too Large for AST - {len(content_bytes)/1024:.1f}KB > {max_js_size_for_ast_kb}KB)"; logger.warning(f"JS file {js_url} ({len(content_bytes)/1024:.1f} KB) too large for AST (limit {max_js_size_for_ast_kb} KB).")
                        else:
                            try:
                                logger.debug(f"Attempting AST parsing for {js_url}")
                                ast_tree = parseScript(js_content, loc=True, tolerant=True, range=True, comment=True) # Tolerant mode is crucial for real-world JS
                                analysis_item["ast_analysis_status"] = "AST Parsed"; analysis_item["status"] = "Analyzed (Regex + AST)" if "Analyzed (Regex)" in analysis_item["status"] else "Analyzed (AST)"
                                ast_findings_for_file = self._analyze_js_ast(ast_tree, js_url, ast_config, js_content) # Pass full content for snippet extraction
                                if ast_findings_for_file:
                                    self.results["content_analysis"]["javascript_files"]["ast_findings"].extend(ast_findings_for_file)
                                    analysis_item["ast_findings_count"] = len(ast_findings_for_file)
                            except error_handler.Error as e_esprima:
                                error_desc_str = str(e_esprima.description if hasattr(e_esprima, 'description') and e_esprima.description else e_esprima.message if hasattr(e_esprima, 'message') else str(e_esprima))
                                analysis_item["ast_analysis_status"] = f"AST Parsing Failed: {error_desc_str[:150]}"; logger.warning(f"Esprima AST parsing failed for {js_url}: {error_desc_str}")
                            except Exception as e_ast_general:
                                analysis_item["ast_analysis_status"] = f"AST Analysis Error: {type(e_ast_general).__name__}"; logger.error(f"General error during AST analysis of {js_url}: {e_ast_general}", exc_info=True)
                    elif not js_content: analysis_item["ast_analysis_status"] = "Skipped (JS Content Decoding Failed)"
                    elif not ESPRIMA_AVAILABLE: analysis_item["ast_analysis_status"] = "Skipped (Esprima library not available)"
                    elif not enable_ast_globally: analysis_item["ast_analysis_status"] = "Skipped (Disabled in config)"
            elif response: analysis_item["status"] = f"Fetch Failed (HTTP {response.status})"
            self.results["content_analysis"]["javascript_files"]["analysis_summary"].append(analysis_item)

        js_tasks = [analyze_single_js(js_url) for js_url in js_files_to_analyze]
        if js_tasks: await self._execute_task_group(js_tasks, "JavaScript File Analysis")
        logger.info("JavaScript file analysis complete.")

    def _get_node_source_code(self, node, full_js_content_str: str) -> str:
        if hasattr(node, 'range') and node.range and len(node.range) == 2:
            start, end = node.range
            if full_js_content_str and isinstance(full_js_content_str, str) and 0 <= start < end <= len(full_js_content_str):
                return full_js_content_str[start:end][:250] # Limit snippet length
            return "Snippet N/A (invalid content or range)"
        return "Snippet N/A (no range)"

    def _is_potential_user_input_ast(self, node, ast_config) -> bool:
        if not node or not hasattr(node, 'type'): return False

        # Direct sources
        if node.type == esprima_nodes.MemberExpression and hasattr(node.object, 'name') and hasattr(node.property, 'name'):
            obj_prop = f"{node.object.name}.{node.property.name}"
            if ast_config.get("potential_source_identifiers_ast", {}).get(obj_prop) == True: return True

        if node.type == esprima_nodes.Identifier and ast_config.get("potential_source_identifiers_ast", {}).get(node.name) == True:
             return True

        # Method call sources
        if node.type == esprima_nodes.CallExpression and hasattr(node.callee, 'type'):
            if node.callee.type == esprima_nodes.MemberExpression:
                # For URLSearchParams().get()
                if hasattr(node.callee.object, 'type') and node.callee.object.type == esprima_nodes.NewExpression and \
                   hasattr(node.callee.object.callee, 'name') and node.callee.object.callee.name == "URLSearchParams" and \
                   hasattr(node.callee.property, 'name') and node.callee.property.name == "get" and \
                   ast_config.get("potential_source_identifiers_ast", {}).get("URLSearchParams.get") == True:
                    return True
                # For jQuery val()
                if hasattr(node.callee.object, 'type') and node.callee.object.type == esprima_nodes.CallExpression and \
                   hasattr(node.callee.object.callee, 'name') and node.callee.object.callee.name == "$" and \
                   hasattr(node.callee.property, 'name') and node.callee.property.name == "val" and \
                   isinstance(ast_config.get("potential_source_identifiers_ast", {}).get("jQuery.val"), dict):
                    return True
            # For custom functions like getParameterByName
            if node.callee.type == esprima_nodes.Identifier and \
               ast_config.get("potential_source_identifiers_ast", {}).get(node.callee.name) == True:
                return True

        # Input element value (heuristic)
        if node.type == esprima_nodes.MemberExpression and hasattr(node.property, 'name') and node.property.name == 'value':
            # This is a very broad heuristic. Could check if node.object is an Identifier that was assigned an element.
            if ast_config.get("potential_source_identifiers_ast", {}).get("formInput.value") == True:
                return True

        return False

    def _analyze_js_ast(self, ast_tree, js_url, ast_config, js_content_str: str):
        findings = []
        if not ast_tree or not ESPRIMA_AVAILABLE or not esprima_nodes: return findings

        root_nodes_to_traverse = getattr(ast_tree, 'body', [])
        if not isinstance(root_nodes_to_traverse, list):
            root_nodes_to_traverse = [root_nodes_to_traverse] if hasattr(ast_tree, 'type') else []

        def find_variable_declaration_in_scope(var_name, start_node):
            # Simple heuristic: Look up the closest function/block scope for declaration
            current_scope_node = start_node
            max_depth = 15 # Increased depth slightly
            current_depth = 0
            while hasattr(current_scope_node, 'parent_kairos') and current_depth < max_depth:
                scope_body_attr_name = None
                if current_scope_node.type in [esprima_nodes.FunctionDeclaration, esprima_nodes.FunctionExpression, esprima_nodes.ArrowFunctionExpression]:
                    scope_body_attr_name = 'body' # The body of a function can be a BlockStatement or a single Expression
                elif current_scope_node.type == esprima_nodes.BlockStatement:
                    scope_body_attr_name = 'body'
                elif current_scope_node.type == esprima_nodes.Program:
                    scope_body_attr_name = 'body'

                scope_body_container = getattr(current_scope_node, scope_body_attr_name, None)
                scope_statements = []
                if scope_body_container:
                    # Function body can be a BlockStatement or directly an Expression
                    if hasattr(scope_body_container, 'body') and isinstance(scope_body_container.body, list): # e.g. function foo() { ... }
                        scope_statements = scope_body_container.body
                    elif isinstance(scope_body_container, list): # e.g. Program.body or BlockStatement.body
                        scope_statements = scope_body_container
                    # Note: This doesn't handle arrow function concise bodies (e.g., () => expr) well for var lookup within that expression.

                for stmt in scope_statements:
                    if stmt and stmt.type == esprima_nodes.VariableDeclaration:
                        for decl in stmt.declarations:
                            if hasattr(decl, 'id') and decl.id.type == esprima_nodes.Identifier and decl.id.name == var_name:
                                return decl.init # Return the initializer expression
                current_scope_node = current_scope_node.parent_kairos
                current_depth +=1
            return None

        def traverse(node, parent=None):
            if not node or not hasattr(node, 'type'): return

            if parent: node.parent_kairos = parent # Attach parent for scope traversal

            node_line = node.loc.start.line if hasattr(node, 'loc') and node.loc and hasattr(node.loc, 'start') and node.loc.start else 'N/A'
            node_code_snippet = self._get_node_source_code(node, js_content_str)

            # Dangerous function calls (eval, Function, setTimeout/setInterval with string)
            if node.type == esprima_nodes.CallExpression and hasattr(node.callee, 'type'):
                func_name_to_check = None
                if node.callee.type == esprima_nodes.Identifier: func_name_to_check = node.callee.name

                if func_name_to_check and func_name_to_check in ast_config.get("dangerous_function_calls", []):
                    is_timed_func_with_string_arg = func_name_to_check in ["setTimeout", "setInterval"] and \
                                                    node.arguments and len(node.arguments) > 0 and \
                                                    node.arguments[0].type == esprima_nodes.Literal and \
                                                    isinstance(node.arguments[0].value, str)
                    is_direct_dangerous_func = func_name_to_check in ["eval", "Function"]

                    if is_timed_func_with_string_arg or is_direct_dangerous_func:
                        desc_detail = "with literal string argument" if is_timed_func_with_string_arg else "which can execute dynamic code"
                        severity_level_df = "Medium"; confidence_df = "High"
                        recommendation_df = f"Avoid using '{func_name_to_check}' {'with string literals for code execution if it is setTimeout/setInterval' if is_timed_func_with_string_arg else 'for dynamic code execution if it is eval/Function'}. If dynamic execution is essential, ensure input is rigorously sanitized or refactor to safer alternatives."

                        if is_direct_dangerous_func and node.arguments and len(node.arguments) > 0:
                            arg_node = node.arguments[0]
                            source_is_user_input_df = False
                            if arg_node.type == esprima_nodes.Identifier:
                                init_node_df = find_variable_declaration_in_scope(arg_node.name, node)
                                if self._is_potential_user_input_ast(init_node_df, ast_config):
                                    source_is_user_input_df = True
                            elif self._is_potential_user_input_ast(arg_node, ast_config):
                                source_is_user_input_df = True

                            if source_is_user_input_df:
                                desc_detail += " with argument potentially derived from user input"
                                severity_level_df = "High"; confidence_df = "Medium"
                                recommendation_df = f"Critical: '{func_name_to_check}' is called with an argument potentially derived from user input. This is a strong indicator of XSS. Thoroughly sanitize or avoid this pattern."

                        findings.append({
                            "type": "JS AST Finding", "description": f"Dangerous function call: '{func_name_to_check}' {desc_detail}.",
                            "severity": severity_level_df, "confidence": confidence_df,
                            "details": {"js_url": js_url, "finding_type": "Dangerous Function Call", "function_name": func_name_to_check, "code_snippet": node_code_snippet, "line": node_line},
                            "recommendation": recommendation_df
                        })

            # DOM XSS Sinks - Assignment (e.g., element.innerHTML = ...)
            if node.type == esprima_nodes.AssignmentExpression and node.operator == '=' and \
               hasattr(node.left, 'type') and node.left.type == esprima_nodes.MemberExpression and \
               hasattr(node.left.property, 'name'):
                target_prop_name = node.left.property.name
                for sink_name_cfg, sink_details_cfg in ast_config.get("dom_xss_sinks", {}).items():
                    if sink_details_cfg.get("type") == "Assignment" and sink_details_cfg.get("property_match") == target_prop_name:
                        obj_name_left = node.left.object.name if hasattr(node.left.object, 'name') else None
                        if sink_details_cfg.get("object_match") and sink_details_cfg.get("object_match") != obj_name_left: continue # Skip if specific object doesn't match

                        source_is_user_input_assign = False
                        if node.right.type == esprima_nodes.Identifier:
                            init_node_assign = find_variable_declaration_in_scope(node.right.name, node)
                            if self._is_potential_user_input_ast(init_node_assign, ast_config):
                                source_is_user_input_assign = True
                        elif self._is_potential_user_input_ast(node.right, ast_config):
                             source_is_user_input_assign = True

                        severity_xss_assign = "High" if source_is_user_input_assign else "Medium"
                        confidence_xss_assign = "Medium" if source_is_user_input_assign else "Low"
                        desc_xss_assign = f"Potential DOM XSS sink: Assignment to '{target_prop_name}'."
                        if source_is_user_input_assign: desc_xss_assign += " The source appears to be user-controllable."

                        findings.append({
                            "type": "JS AST Finding", "description": desc_xss_assign,
                            "severity": severity_xss_assign, "confidence": confidence_xss_assign,
                            "details": {"js_url": js_url, "finding_type": "DOM XSS Sink (Assignment)", "sink_property": target_prop_name, "code_snippet": node_code_snippet, "line": node_line, "source_is_user_input_guess": source_is_user_input_assign},
                            "recommendation": f"If data assigned to '{target_prop_name}' at '{os.path.basename(js_url)}' (line {node_line}) can be user-influenced, ensure proper sanitization/encoding. Use safer alternatives like '.textContent'."
                        }); break # Found matching sink

            # DOM XSS Sinks - Call (e.g., document.write(), $(...).html())
            if node.type == esprima_nodes.CallExpression and hasattr(node.callee, 'type'):
                callee_prop_name = None; callee_obj_name = None
                if node.callee.type == esprima_nodes.MemberExpression:
                    if hasattr(node.callee.property, 'name'): callee_prop_name = node.callee.property.name
                    if hasattr(node.callee.object, 'name'): callee_obj_name = node.callee.object.name # e.g. document
                    elif hasattr(node.callee.object, 'type') and node.callee.object.type == esprima_nodes.ThisExpression: callee_obj_name = 'this'
                    elif hasattr(node.callee.object, 'type') and node.callee.object.type == esprima_nodes.CallExpression and \
                         hasattr(node.callee.object.callee, 'name') and node.callee.object.callee.name == '$': callee_obj_name = '$' # For jQuery $(...)

                for sink_name_cfg, sink_details_cfg in ast_config.get("dom_xss_sinks", {}).items():
                    if sink_details_cfg.get("type") == "Call" and sink_details_cfg.get("property_match") == callee_prop_name:
                        obj_match_cfg = sink_details_cfg.get("object_match")
                        if obj_match_cfg and obj_match_cfg != callee_obj_name: continue # Skip if specific object doesn't match

                        source_is_user_input_call = False
                        sink_arg_index = sink_details_cfg.get("arg_index_is_sink", 0) # Default to first arg
                        if node.arguments and len(node.arguments) > sink_arg_index:
                            arg_node_call = node.arguments[sink_arg_index]
                            if arg_node_call.type == esprima_nodes.Identifier:
                                init_node_call = find_variable_declaration_in_scope(arg_node_call.name, node)
                                if self._is_potential_user_input_ast(init_node_call, ast_config):
                                    source_is_user_input_call = True
                            elif self._is_potential_user_input_ast(arg_node_call, ast_config):
                                source_is_user_input_call = True

                        severity_xss_call = "High" if source_is_user_input_call else "Medium"
                        confidence_xss_call = "Medium" if source_is_user_input_call else "Low"
                        desc_xss_call = f"Potential DOM XSS sink: Call to function/method '{callee_prop_name}'."
                        if source_is_user_input_call: desc_xss_call += " An argument appears to be user-controllable."

                        if callee_prop_name == "setAttribute" and sink_details_cfg.get("arg_index_is_sink") == 1: # Special handling for setAttribute
                            if node.arguments and len(node.arguments) > 0 and node.arguments[0].type == esprima_nodes.Literal:
                                attr_name_literal = str(node.arguments[0].value)
                                if any(re.fullmatch(pattern, attr_name_literal, re.I) for pattern in sink_details_cfg.get("first_arg_name_match_regex", [])):
                                    desc_xss_call = f"Potential DOM XSS sink: Call to '{callee_prop_name}' setting attribute '{attr_name_literal}'."
                                    if source_is_user_input_call: desc_xss_call += " The value appears to be user-controllable."
                                    findings.append({
                                        "type": "JS AST Finding", "description": desc_xss_call,
                                        "severity": severity_xss_call, "confidence": confidence_xss_call,
                                        "details": {"js_url": js_url, "finding_type": "DOM XSS Sink (setAttribute)", "sink_function": callee_prop_name, "attribute_set": attr_name_literal, "code_snippet": node_code_snippet, "line": node_line, "source_is_user_input_guess": source_is_user_input_call},
                                        "recommendation": f"If data in second argument of '{callee_prop_name}(\"{attr_name_literal}\", ...)' at '{os.path.basename(js_url)}' (line {node_line}) is user-controlled, ensure sanitization/encoding. Avoid setting event handlers (on*) with user data."
                                    })
                        elif callee_prop_name != "setAttribute": # For other call-based sinks
                            findings.append({
                                "type": "JS AST Finding", "description": desc_xss_call,
                                "severity": severity_xss_call, "confidence": confidence_xss_call,
                                "details": {"js_url": js_url, "finding_type": "DOM XSS Sink (Call)", "sink_function": callee_prop_name, "code_snippet": node_code_snippet, "line": node_line, "source_is_user_input_guess": source_is_user_input_call},
                                "recommendation": f"If data passed to '{callee_prop_name}' at '{os.path.basename(js_url)}' (line {node_line}) is user-controlled, ensure sanitization/encoding. Use safer APIs."
                            })
                        break # Found matching sink

            # Sensitive client-side storage
            if node.type == esprima_nodes.CallExpression and hasattr(node.callee, 'type') and node.callee.type == esprima_nodes.MemberExpression:
                if hasattr(node.callee.object, 'name') and node.callee.object.name in ["localStorage", "sessionStorage"] and \
                   hasattr(node.callee.property, 'name') and node.callee.property.name == "setItem":
                    if node.arguments and len(node.arguments) > 0 and node.arguments[0].type == esprima_nodes.Literal:
                        storage_key_name = str(node.arguments[0].value).lower()
                        if any(sensitive_key_pattern in storage_key_name for sensitive_key_pattern in ast_config.get("sensitive_storage_keys_ast", [])):
                            findings.append({
                                "type": "JS AST Finding", "description": f"Potentially sensitive data stored in {node.callee.object.name} with key '{storage_key_name}'.",
                                "severity": "Medium", "confidence": "Medium",
                                "details": {"js_url": js_url, "finding_type": "Sensitive Client-Side Storage", "storage_type": node.callee.object.name, "key_name": storage_key_name, "code_snippet": node_code_snippet, "line": node_line},
                                "recommendation": f"Review the use of {node.callee.object.name}.setItem for key '{storage_key_name}' in '{os.path.basename(js_url)}' (line {node_line}). Storing sensitive data like tokens or PII in client-side storage can be risky if XSS vulnerabilities exist. Consider HttpOnly cookies for session tokens."
                            })

            # API Keys/Secrets in String Literals
            if node.type == esprima_nodes.Literal and isinstance(node.value, str) and len(node.value) > 5: # Min length to avoid tiny strings
                literal_str = node.value
                for key_name_api, pattern_api in self.config["api_key_patterns"].items():
                    if re.search(pattern_api, literal_str):
                        if not any(skip_kw in literal_str.lower() for skip_kw in ["example", "placeholder", "test", "xxxx", "sample", "demo", "token_here", "not_a_real_key", "api-key-goes-here"]):
                            key_info_ast = {"key_name": key_name_api, "matched_value_preview": literal_str[:20] + "...", "source_js_url": js_url, "context_snippet": node_code_snippet, "source_type": "AST Literal", "line": node_line}
                            if not any(k.get("matched_value_preview") == key_info_ast["matched_value_preview"] and k.get("key_name") == key_name_api and k.get("source_js_url") == js_url and k.get("source_type") == "AST Literal" for k in self.results["content_analysis"]["suspected_api_keys"]):
                                self.results["content_analysis"]["suspected_api_keys"].append(key_info_ast)
                                add_finding(self.results["security_posture"], "vulnerability_findings",
                                            {"type": "Sensitive Data Exposure", "description": f"Potential API key/secret ('{key_name_api}') confirmed in JS string literal (AST): {os.path.basename(js_url)}.",
                                             "severity": "High", "confidence": "High", "target_url": js_url, "details":key_info_ast,
                                             "recommendation": f"Verify if '{key_name_api}' in '{js_url}' (AST literal line {node_line}) is live. If so, revoke and investigate. Avoid hardcoding secrets."},
                                            log_message=f"Potential API key '{key_name_api}' in JS (AST Literal): {js_url} line {node_line}", severity_for_log="HIGH")
                            findings.append({
                                "type": "JS AST Finding", "description": f"Potential API key '{key_name_api}' in string literal.",
                                "severity": "High", "confidence": "High",
                                "details": {"js_url": js_url, "finding_type": "API Key Literal", "key_name": key_name_api, "value_preview": literal_str[:20] + "...", "code_snippet": node_code_snippet, "line": node_line}
                            })
                            break # Found an API key pattern, move to next node or literal check

                # Interesting patterns in string literals
                for find_type_js, js_pattern_js in self.config.get("js_interesting_patterns", {}).items():
                    # Only check patterns likely to be found in literals (URLs, IPs, etc.)
                    if any(kw in find_type_js for kw in ["Cloud Storage URL", "Internal IP Address", "Potential Endpoint Path", "WebSocket URL", "Firebase Database URL"]):
                        if re.search(js_pattern_js, f"'{literal_str}'", re.IGNORECASE): # Wrap literal in quotes for regex that expect them
                            findings.append({
                                "type": "JS AST Finding", "description": f"Interesting pattern '{find_type_js}' found in string literal.",
                                "severity": "Info", "confidence": "Medium",
                                "details": {"js_url": js_url, "finding_type": find_type_js, "match": literal_str[:100] + "...", "code_snippet": node_code_snippet, "line": node_line}
                            })
                            if "endpoint" in find_type_js.lower() or "url" in find_type_js.lower() or "firebaseio.com" in literal_str:
                                add_finding(self.results["security_posture"], "potential_api_endpoints",
                                            {"type": f"JS AST Discovery ({find_type_js})", "endpoint_or_info": literal_str, "source_url": js_url, "severity": "Info", "confidence":"Medium", "line": node_line,
                                             "recommendation": f"Review URL/endpoint '{literal_str}' from '{js_url}' (AST literal line {node_line}) for exposure and security."},
                                            log_message=f"JS AST ({find_type_js}) in {js_url}: {literal_str}", severity_for_log="INFO")
                            break # Found one interesting pattern, move on

            # Recursively traverse child nodes
            for key, value in node.__dict__.items():
                if key in ['loc', 'range', 'parent_kairos', 'leadingComments', 'trailingComments']: continue # Avoid internal/metadata keys
                if isinstance(value, list):
                    for item_node in value:
                        if isinstance(item_node, esprima_nodes.Node): traverse(item_node, node)
                elif isinstance(value, esprima_nodes.Node):
                    traverse(value, node)

        try:
            for root_node_item in root_nodes_to_traverse:
                traverse(root_node_item)
        except Exception as e_traverse:
            logger.error(f"Error during AST traversal for {js_url}: {e_traverse}", exc_info=True)

        # Deduplicate AST findings for this specific file before returning
        unique_ast_findings_for_file = []
        seen_ast_signatures = set()
        for f_item in findings:
            details_data = f_item.get("details", {})
            sig_ast = (details_data.get("finding_type"), details_data.get("function_name"), details_data.get("sink_property"),
                       details_data.get("attribute_set"), details_data.get("key_name"), str(details_data.get("code_snippet",""))[:50],
                       str(details_data.get("line"))) #Ensure line is string for tuple hashing
            if sig_ast not in seen_ast_signatures:
                unique_ast_findings_for_file.append(f_item)
                seen_ast_signatures.add(sig_ast)
        return unique_ast_findings_for_file

    async def conduct_basic_vulnerability_checks(self):
        logger.info("Conducting basic automated vulnerability checks (debug flags, mixed content, software versions)...")
        sec_posture = self.results["security_posture"]
        external_api_integrations_enabled = self.config.get("enable_external_api_integrations", {})
        nvd_enabled = external_api_integrations_enabled.get("nvd", False)
        nvd_api_key = self.config.get("external_api_keys", {}).get("nvd_api_key")

        # Check software versions from technology fingerprinting
        if self.results["technology_fingerprint"]["software_versions_found"]:
            for sw_name, ver_info in self.results["technology_fingerprint"]["software_versions_found"].items():
                # Handle cases where ver_info might be a dict (from Wappalyzer) or string (from headers)
                version_val = ver_info if isinstance(ver_info, str) else (ver_info.get('version') if isinstance(ver_info, dict) else None)
                if version_val is None or str(version_val).strip() == "" or str(version_val).lower() == "unknown": continue

                # Avoid re-checking CMS version if it's already handled by CMS specific scan
                cms_name_check = self.results["technology_fingerprint"].get("cms_identified")
                if cms_name_check and cms_name_check.lower() in sw_name.lower(): # Basic check if sw_name is the CMS
                    continue # Will be handled by run_cms_specific_scans_if_detected

                finding_entry_sw = {
                     "type": "Software Version Information",
                     "description": f"Software '{sw_name}' version '{version_val}' detected. Check against known vulnerability databases (CVEs).",
                     "severity": "Info", "confidence": "High",
                     "details": {"software": sw_name, "version": version_val, "search_links": generate_vuln_search_url(sw_name, version_val), "nvd_cves": []},
                     "recommendation": f"Regularly check '{sw_name} v{version_val}' for published vulnerabilities and apply patches promptly. Prioritize vulnerabilities with known exploits or high severity scores. Check NVD (https://nvd.nist.gov/vuln/search) and Vulners (https://vulners.com)."
                }
                add_finding(sec_posture, "vulnerability_findings", finding_entry_sw,
                            log_message=f"Software '{sw_name} v{version_val}'. Recommend CVE check.", severity_for_log="INFO")

                if nvd_enabled and nvd_api_key and REQUESTS_AVAILABLE:
                    nvd_cves_found = await self._fetch_nvd_cves(sw_name, version_val)
                    if nvd_cves_found:
                        # Find the corresponding finding and add NVD CVEs
                        for finding in sec_posture["vulnerability_findings"]:
                            if finding.get("details", {}).get("software") == sw_name and finding.get("details", {}).get("version") == version_val:
                                finding["details"]["nvd_cves"] = nvd_cves_found
                                critical_cves = [cve for cve in nvd_cves_found if cve.get("baseSeverity", "").upper() == "CRITICAL"]
                                high_cves = [cve for cve in nvd_cves_found if cve.get("baseSeverity", "").upper() == "HIGH"]
                                if critical_cves:
                                    finding["severity"] = "Critical" # Escalate severity of the KAIROS finding
                                    add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                        {"type": "High Impact CVE (NVD)", "description": f"CRITICAL CVE(s) found for {sw_name} v{version_val} (e.g., {critical_cves[0]['cve_id']}). Immediate attention required.", "severity": "Critical", "confidence":"High", "details": {"software": sw_name, "version":version_val, "cve_sample": critical_cves[0]}},
                                        log_message=f"CRITICAL NVD CVEs found for {sw_name} v{version_val}", severity_for_log="CRITICAL")
                                elif high_cves:
                                    if finding["severity"] not in ["Critical"]: finding["severity"] = "High"
                                    add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                        {"type": "High Impact CVE (NVD)", "description": f"HIGH severity CVE(s) found for {sw_name} v{version_val} (e.g., {high_cves[0]['cve_id']}). Requires review.", "severity": "High", "confidence":"High", "details": {"software": sw_name, "version":version_val, "cve_sample": high_cves[0]}},
                                        log_message=f"HIGH NVD CVEs found for {sw_name} v{version_val}", severity_for_log="HIGH")
                                break # Found and updated the finding
                        self.results["security_posture"]["external_api_analysis_summary"]["nvd_cves_found_total"] += len(nvd_cves_found)
                elif nvd_enabled and not nvd_api_key: logger.warning(f"NVD lookup for {sw_name} v{version_val} skipped: NVD API key not configured.")
                elif nvd_enabled and not REQUESTS_AVAILABLE: logger.warning(f"NVD lookup for {sw_name} v{version_val} skipped: 'requests' library not available.")

        # Debug information / Verbose errors in page source
        if self._main_page_html_cache:
            debug_patterns = [
                r"(?i)debug\s*=\s*(true|1)", r"(?i)display_errors\s*=\s*on", r"Traceback \(most recent call last\)",
                r"<b>Warning</b>\s*:", r"<b>Notice</b>\s*:", r"<b>Fatal error</b>\s*:",
                r"An unhandled exception occurred", r"Stack Overflow at line", r"exception occurred", r"PHP Error",
                r"ASP.NET is configured to show verbose error messages", r"Detailed Error Information",
                r"Microsoft .NET Framework Version", r"Ruby on Rails", r"Django Version", r"Werkzeug", # Common framework debug signatures
                r"Whitelabel Error Page", r"symfony\/profiler", r"xdebug_error", r"Call Stack", r"SQLSTATE\[" # Database errors
            ]
            for pattern in debug_patterns:
                if re.search(pattern, self._main_page_html_cache, re.IGNORECASE):
                    add_finding(sec_posture, "vulnerability_findings",
                                {"type": "Information Disclosure (Debug/Error)", "description": "Potential debug information or verbose error messages exposed in page source. This can leak sensitive system details.",
                                 "severity": "Medium", "confidence": "Medium", "target_url": self.results["general_info"]["final_url"], "evidence_summary": f"Matched pattern: '{pattern[:50]}...'",
                                 "recommendation": "Disable debug mode and verbose error messages on production. Configure custom, generic error pages."},
                                log_message="Potential debug indicators/verbose errors in HTML.", severity_for_log="MEDIUM")
                    break # Found one, no need to check others for this page

        # Mixed content
        if self.scheme == "https" and self._main_page_soup_cache:
            mixed_content_elements = []
            tags_and_attrs_for_mixed_content = {'img': 'src', 'script': 'src', 'link': 'href', 'iframe': 'src', 'object': 'data', 'embed': 'src', 'form': 'action', 'audio': 'src', 'video': 'src', 'source': 'src', 'track': 'src'}
            for tag_name, attr_name in tags_and_attrs_for_mixed_content.items():
                for tag in self._main_page_soup_cache.find_all(tag_name, **{attr_name: re.compile(r"^http://", re.I)}): # src/href starts with http://
                    mixed_content_elements.append({"tag": tag_name, "attribute": attr_name, "value": tag.get(attr_name)})
            if mixed_content_elements:
                add_finding(sec_posture, "vulnerability_findings",
                            {"type": "Security Misconfiguration (Mixed Content)", "description": f"Mixed Content: {len(mixed_content_elements)} insecure HTTP resource(s) loaded on HTTPS page. Can compromise page security and trigger browser warnings.",
                             "severity": "Medium", "confidence": "High", "target_url": self.results["general_info"]["final_url"],
                             "details": {"resources_sample": mixed_content_elements[:5], "count": len(mixed_content_elements)},
                             "recommendation": "Ensure all resources are loaded via HTTPS. Update hardcoded HTTP links. Consider CSP 'upgrade-insecure-requests' directive, but fixing sources is preferred."},
                            log_message=f"Mixed content found: {len(mixed_content_elements)} HTTP resources on HTTPS page.", severity_for_log="MEDIUM")
        logger.info("Basic vulnerability checks complete.")

    async def fetch_and_analyze_security_txt(self):
        logger.info("Fetching and analyzing security.txt...")
        final_url_parsed = urlparse(self.results["general_info"]["final_url"])
        base_url = f"{final_url_parsed.scheme}://{final_url_parsed.netloc}"
        security_txt_info = None
        security_txt_paths_to_check = self.config["sensitive_paths_categories"].get("security_txt_paths_list", ["/.well-known/security.txt", "/security.txt"])

        for path_suffix in security_txt_paths_to_check:
            sec_txt_url = urljoin(base_url, path_suffix.lstrip('/'))
            response, content_bytes = await self._make_request(sec_txt_url)
            if response and response.status == 200 and content_bytes:
                try:
                    text_content = content_bytes.decode(response.charset or 'utf-8', errors='replace')
                    # Basic RFC 9116 validation
                    parsed_fields = {}; issues_found = []; required_fields = {"contact", "expires"}; present_fields = set()
                    for line_num, line_content in enumerate(text_content.splitlines(), 1):
                        line_content = line_content.strip()
                        if line_content.startswith("#") or not line_content: continue
                        if ":" not in line_content: issues_found.append(f"Malformed line (no colon separator) at line {line_num}: '{line_content[:50]}...'"); continue
                        key, val = line_content.split(":", 1); key_clean = key.strip().lower(); val_clean = val.strip()
                        if key_clean in parsed_fields: issues_found.append(f"Duplicate field '{key_clean}' found at line {line_num}.")
                        parsed_fields[key_clean] = val_clean; present_fields.add(key_clean)

                    for req_field in required_fields:
                        if req_field not in present_fields: issues_found.append(f"Required field '{req_field.capitalize()}' is missing.")
                    if "expires" in parsed_fields:
                        try:
                            exp_dt_str_raw = parsed_fields["expires"]
                            exp_dt = datetime.fromisoformat(exp_dt_str_raw.replace("Z", "+00:00")) # Ensure TZ aware
                            if exp_dt.tzinfo is None: exp_dt = exp_dt.replace(tzinfo=timezone.utc) # Default to UTC if no tz
                            if exp_dt < datetime.now(timezone.utc): issues_found.append(f"The 'Expires' field value ('{exp_dt_str_raw}') is in the past.")
                        except ValueError: issues_found.append(f"Invalid 'Expires' field format: '{parsed_fields['expires']}'. Must be ISO 8601 datetime.")
                    if "contact" in parsed_fields and not parsed_fields["contact"]: issues_found.append("'Contact' field is present but empty.")
                    for opt_fld in ["acknowledgments", "policy", "hiring", "canonical"]: # These should be URLs
                        if opt_fld in parsed_fields and not parsed_fields[opt_fld].startswith("http"): issues_found.append(f"'{opt_fld.capitalize()}' field should be a URL.")
                    if "preferred-languages" in parsed_fields and not parsed_fields["preferred-languages"]: issues_found.append("'Preferred-Languages' field is present but empty.")

                    security_txt_info = {"url": sec_txt_url, "content_preview": text_content[:500] + ("..." if len(text_content) > 500 else ""), "parsed_fields": parsed_fields, "validation_issues": issues_found}
                    if issues_found:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Policy (security.txt Issues)", "description": f"security.txt at {sec_txt_url} has validation issues: {'; '.join(issues_found[:3])}{'...' if len(issues_found)>3 else ''}",
                                     "severity": "Low", "confidence": "High", "target_url": sec_txt_url, "details": security_txt_info,
                                     "recommendation": f"Review and correct issues in security.txt at {sec_txt_url} per RFC 9116."},
                                    log_message=f"security.txt at {sec_txt_url} has issues: {'; '.join(issues_found)}", severity_for_log="LOW")
                    else:
                        add_finding(self.results["security_posture"], "vulnerability_findings",
                                    {"type": "Security Policy (security.txt Found)", "description": f"Valid security.txt found at {sec_txt_url}.",
                                     "severity": "Info", "confidence": "High", "target_url": sec_txt_url, "details": security_txt_info,
                                     "recommendation": "Regularly review and update security.txt, especially 'Expires' and 'Contact' information."},
                                    log_message=f"Valid security.txt found at {sec_txt_url}", severity_for_log="INFO")
                    break # Found and processed, no need to check other paths
                except Exception as e_sec_txt_parse:
                    security_txt_info = {"url": sec_txt_url, "error": f"Failed to parse security.txt: {str(e_sec_txt_parse)}"}
                    logger.error(f"Error parsing security.txt from {sec_txt_url}: {e_sec_txt_parse}"); break
            elif response: # Not 200
                logger.debug(f"security.txt not found or error at {sec_txt_url} (Status: {response.status})")

        self.results["security_posture"]["security_txt_contents"] = security_txt_info or "Not found at common locations."
        logger.info("security.txt analysis complete.")

    async def enumerate_and_verify_subdomains(self):
        current_domain_for_subs = self.results["scan_metadata"].get("effective_domain", self.domain)
        if not current_domain_for_subs:
            logger.error("Cannot enumerate subdomains: No valid domain identified for the target.")
            self.results["subdomain_discovery"]["discovered_subdomains"] = [{"error": "No valid domain to enumerate."}]
            return

        logger.info(f"Starting subdomain enumeration for {current_domain_for_subs}...")
        discovered_subs_map: dict[str, dict] = {} # Store best result per subdomain name
        wildcard_analysis = self.results["dns_information"]["wildcard_dns_analysis"]
        wildcard_likely = wildcard_analysis.get("detected", False)

        base_domain_for_subs_enum = current_domain_for_subs # Use effective domain
        if base_domain_for_subs_enum.lower().startswith("www."): # Strip www if present for broader crt.sh etc.
            parts = base_domain_for_subs_enum.split('.', 1)
            if len(parts) > 1: base_domain_for_subs_enum = parts[1]
        logger.info(f"Base domain for subdomain enumeration checks: {base_domain_for_subs_enum}")

        if wildcard_likely:
            logger.warning(f"Wildcard DNS likely active for *.{base_domain_for_subs_enum} (Evidence: {wildcard_analysis.get('evidence', 'N/A')}). Subdomain verification will attempt to filter false positives using content/title comparison.")
            self.results["subdomain_discovery"]["subdomain_verification_methodology"] += f" Wildcard detected for *.{base_domain_for_subs_enum}; using content/title comparison against main domain and baseline 404."

        main_page_title_norm = self._main_page_title_cache.lower().strip() if self._main_page_title_cache else ""
        main_page_content_hash = hashlib.md5((self._main_page_html_cache or "").encode(errors='ignore')).hexdigest() if self._main_page_html_cache is not None else None
        _, baseline_404_content_bytes, baseline_404_title_str = self._baseline_404_response_cache
        baseline_404_title_norm = baseline_404_title_str.lower().strip() if baseline_404_title_str else ""
        baseline_404_content_hash = hashlib.md5(baseline_404_content_bytes or b"").hexdigest() if baseline_404_content_bytes is not None else None
        title_sim_threshold = self.config.get("wildcard_dns_config",{}).get("title_similarity_threshold_ratio", 0.65)

        def is_similar_title(title1_str: str, title2_str: str) -> bool:
            if not title1_str or not title2_str: return False
            words1 = set(title1_str.lower().split()); words2 = set(title2_str.lower().split())
            if not words1 or not words2: return False # Avoid division by zero if a title is empty after split
            common_words_count = len(words1.intersection(words2))
            return (common_words_count / len(words1) >= title_sim_threshold) or (common_words_count / len(words2) >= title_sim_threshold)

        async def check_sub(sub_prefix: str, source: str):
            subdomain_full = f"{sub_prefix}.{base_domain_for_subs_enum}".lower()
            if not sub_prefix or subdomain_full == self.results["scan_metadata"]["effective_domain"] or subdomain_full == base_domain_for_subs_enum: return # Skip blank, self, or base domain

            schemes_to_try = ["https", "http"] if self.scheme == "https" else ["http", "https"] # Prioritize original scheme
            for scheme_sub in schemes_to_try:
                test_url_sub = f"{scheme_sub}://{subdomain_full}"
                try:
                    sub_timeout = aiohttp.ClientTimeout(total=max(15, self.config["request_timeout_seconds"]//2 + 5)) # Shorter timeout for subs
                    resp_sub, content_sub_bytes = await self._make_request(test_url_sub, method="GET", allow_redirects=True, timeout_override=sub_timeout, max_retries=0)

                    if resp_sub and content_sub_bytes: # Got a response
                        sub_status = resp_sub.status; sub_final_url = str(resp_sub.url)
                        sub_title = ""; sub_content_hash = hashlib.md5(content_sub_bytes).hexdigest()
                        try:
                            sub_html = content_sub_bytes.decode(resp_sub.charset or 'utf-8', errors='replace')
                            sub_soup = BeautifulSoup(sub_html, 'html.parser')
                            title_tag_sub = sub_soup.find("title")
                            if title_tag_sub and title_tag_sub.string: sub_title = title_tag_sub.string.strip()
                        except Exception: pass # Ignore parsing errors for title

                        if wildcard_likely: # Apply wildcard filtering
                            is_like_main_page_content = main_page_content_hash and sub_content_hash == main_page_content_hash
                            is_like_main_page_title = main_page_title_norm and sub_title and is_similar_title(sub_title.lower(), main_page_title_norm)
                            is_like_404_page_content = baseline_404_content_hash and sub_content_hash == baseline_404_content_hash
                            is_like_404_page_title = baseline_404_title_norm and sub_title and is_similar_title(sub_title.lower(), baseline_404_title_norm)
                            if is_like_main_page_content or is_like_main_page_title: logger.debug(f"Wildcard Filter: {test_url_sub} content/title resembles main page. Skipping."); return
                            if is_like_404_page_content or is_like_404_page_title: logger.debug(f"Wildcard Filter: {test_url_sub} content/title resembles baseline 404. Skipping."); return

                        logger.info(f"Subdomain Verified: {test_url_sub} -> {sub_final_url} (Status: {sub_status}, Source: {source}, Title: '{sub_title[:50]}...')")
                        current_entry = {"subdomain": subdomain_full, "status": sub_status, "url": sub_final_url, "source": source, "title": sub_title, "content_hash": sub_content_hash, "scheme": scheme_sub, "virustotal_report": None}
                        if subdomain_full not in discovered_subs_map or \
                           (scheme_sub == "https" and discovered_subs_map[subdomain_full]["scheme"] == "http") or \
                           (sub_status == 200 and discovered_subs_map[subdomain_full].get("status",0) != 200): # Prefer HTTPS and 200 status
                            discovered_subs_map[subdomain_full] = current_entry
                        return # Found on this scheme, no need to check other scheme
                except aiohttp.ClientConnectorDNSError: logger.debug(f"DNS resolution failed for subdomain {test_url_sub} (Source: {source}). Expected for non-existent subdomains.")
                except (asyncio.TimeoutError, aiohttp.ClientError) as e_client_sub: logger.debug(f"Subdomain check failed (Timeout/ClientError: {type(e_client_sub).__name__}) for {test_url_sub}")
                except Exception as e_sub_check: logger.debug(f"Unexpected error checking subdomain {test_url_sub}: {type(e_sub_check).__name__} - {e_sub_check}")
            logger.debug(f"Subdomain {subdomain_full} did not respond on tested schemes (Source: {source}).")

        bruteforce_tasks = []
        if self.config.get("enable_subdomain_bruteforce", True) and self.config.get("common_subdomains"):
            for sub_bf in self.config["common_subdomains"]:
                if sub_bf: bruteforce_tasks.append(check_sub(sub_bf, "Bruteforce"))
        if bruteforce_tasks: await self._execute_task_group(bruteforce_tasks, "Subdomain Bruteforce")

        crtsh_subs_to_check_tasks = []
        if self.config.get("enable_crtsh_subdomain_search", True) and REQUESTS_AVAILABLE:
            try:
                crtsh_url = f"https://crt.sh/?q=%.{base_domain_for_subs_enum}&output=json"
                logger.debug(f"Querying crt.sh: {crtsh_url}")
                resp_crtsh = await asyncio.to_thread(requests.get, crtsh_url, timeout=self.config["crtsh_timeout_seconds"])
                resp_crtsh.raise_for_status()
                json_data = resp_crtsh.json()
                unique_sub_prefixes_from_crtsh = set()
                for entry in json_data:
                    for name_field_key in ["name_value", "common_name"]: # crt.sh uses name_value, some tools might use common_name
                        name_field_val = entry.get(name_field_key, "")
                        for name_entry in name_field_val.split('\n'): # Sometimes multiple names in one field
                            name_clean = name_entry.strip().lower()
                            if name_clean.endswith(f".{base_domain_for_subs_enum}") and \
                               not name_clean.startswith("*.") and \
                               name_clean != base_domain_for_subs_enum and \
                               name_clean != self.results["scan_metadata"]["effective_domain"]: # Exclude wildcard certs and base domain itself
                                sub_part = name_clean[:-len(f".{base_domain_for_subs_enum}")-1] # Get just the subdomain part
                                if sub_part and '.' not in sub_part: # Only consider direct subdomains (e.g., 'mail', not 'sub.mail')
                                     unique_sub_prefixes_from_crtsh.add(sub_part)
                if unique_sub_prefixes_from_crtsh:
                    logger.info(f"Found {len(unique_sub_prefixes_from_crtsh)} unique potential subdomain prefixes from crt.sh. Verifying...")
                    for sub_crtsh in unique_sub_prefixes_from_crtsh:
                        if sub_crtsh: crtsh_subs_to_check_tasks.append(check_sub(sub_crtsh, "crt.sh"))
            except requests.exceptions.Timeout: logger.error(f"crt.sh lookup timed out after {self.config['crtsh_timeout_seconds']}s.")
            except requests.exceptions.RequestException as e_crtsh: logger.error(f"crt.sh lookup failed: {type(e_crtsh).__name__} - {e_crtsh}")
            except json.JSONDecodeError:
                response_text_preview = "N/A (response object not available)"
                if 'resp_crtsh' in locals() and hasattr(resp_crtsh, 'text'): response_text_preview = resp_crtsh.text[:200]
                logger.error(f"crt.sh returned non-JSON response. Preview: {response_text_preview}")
            except Exception as e_crtsh_general: logger.error(f"Unexpected error during crt.sh processing: {type(e_crtsh_general).__name__} - {e_crtsh_general}", exc_info=True)
        elif not REQUESTS_AVAILABLE:
             logger.info("crt.sh subdomain search skipped: 'requests' library not available or callable (checked at startup).")

        if crtsh_subs_to_check_tasks: await self._execute_task_group(crtsh_subs_to_check_tasks, "crt.sh Subdomain Verification")

        self.results["subdomain_discovery"]["discovered_subdomains"] = sorted(list(discovered_subs_map.values()), key=lambda x_item: x_item["subdomain"])
        if not self.results["subdomain_discovery"]["discovered_subdomains"]: logger.info(f"No active subdomains found for {base_domain_for_subs_enum} after verification.")
        else: logger.info(f"Found {len(self.results['subdomain_discovery']['discovered_subdomains'])} active subdomains for {base_domain_for_subs_enum}.")

    async def fetch_wayback_urls_and_check_live_status(self):
        if not self.config.get("enable_wayback_machine_scan", True) or not REQUESTS_AVAILABLE:
            if not REQUESTS_AVAILABLE: logger.info("Wayback Machine scan skipped: 'requests' library not available or callable (checked at startup).")
            return

        wayback_cfg = self.config.get("wayback_machine_config", {})
        limit_wb = wayback_cfg.get("limit", 75)
        interesting_exts_wb = wayback_cfg.get("interesting_extensions", [])
        interesting_keywords_wb = wayback_cfg.get("interesting_keywords_in_path_or_query", [])
        check_live_wb = wayback_cfg.get("fetch_current_status_for_interesting", True)

        base_domain_for_wayback = self.results["scan_metadata"].get("effective_domain", self.domain)
        if base_domain_for_wayback.lower().startswith("www."): # Search for *.domain.com if www was initial target
            parts = base_domain_for_wayback.split('.', 1)
            if len(parts) > 1: base_domain_for_wayback = parts[1]

        logger.info(f"Fetching up to {limit_wb} archived URLs for *.{base_domain_for_wayback} from Wayback Machine CDX API...")
        archived_urls_result_dict = self.results["content_analysis"]["archived_urls"]

        try:
            # Filter more aggressively at API level for common noise, and limit results early
            cdx_api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{base_domain_for_wayback}/*&output=json&fl=original,mimetype,timestamp,statuscode&collapse=urlkey&limit={limit_wb * 5}&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:application/javascript&filter=!mimetype:application/x-javascript" # Fetch more initially to allow local filtering
            logger.debug(f"Wayback CDX API URL: {cdx_api_url}")

            if not (hasattr(requests, 'get') and callable(requests.get)):
                logger.critical("[FATAL] `requests.get` is not callable for Wayback, though REQUESTS_AVAILABLE was true. Skipping.")
                archived_urls_result_dict["error"] = "requests.get not callable (runtime check failed)"
                return

            resp_wayback = await asyncio.to_thread(requests.get, cdx_api_url, timeout=45) # Increased timeout for CDX
            resp_wayback.raise_for_status()
            data_wb = resp_wayback.json()

            if not data_wb or not isinstance(data_wb, list) or len(data_wb) <=1 or data_wb[0] != ["original", "mimetype", "timestamp", "statuscode"]: # Check header row
                logger.info(f"No valid data or unexpected format from Wayback Machine CDX API for *.{base_domain_for_wayback}. Response: {str(data_wb)[:200]}"); archived_urls_result_dict["fetched_count"] = 0; archived_urls_result_dict["sample"] = ["No results or unexpected format from CDX API."]; return
            data_wb = data_wb[1:] # Skip header row

            fetched_urls_details_list = []; seen_urls_set = set()
            for item_wb in data_wb:
                if item_wb and len(item_wb) >= 1 and item_wb[0] not in seen_urls_set: # Basic validation and uniqueness
                    url_str_wb, mimetype_wb, timestamp_str_wb, statuscode_str_wb = item_wb[0], (item_wb[1] if len(item_wb)>1 else "unknown"), (item_wb[2] if len(item_wb)>2 else "unknown"), (item_wb[3] if len(item_wb)>3 else "unknown")
                    # Further filter common static resources unless they contain interesting keywords
                    is_common_static = any(url_str_wb.lower().endswith(noise_ext) for noise_ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico'])
                    if is_common_static and not any(keyword_wb in url_str_wb.lower() for keyword_wb in interesting_keywords_wb): continue
                    if len(fetched_urls_details_list) < limit_wb: fetched_urls_details_list.append({"url": url_str_wb, "mimetype": mimetype_wb, "timestamp_wb": timestamp_str_wb, "statuscode_wb": statuscode_str_wb}); seen_urls_set.add(url_str_wb)

            archived_urls_result_dict["fetched_count"] = len(fetched_urls_details_list)
            archived_urls_result_dict["sample"] = [item_detail['url'] for item_detail in fetched_urls_details_list[:20]] # Sample for report
            logger.info(f"Found {len(fetched_urls_details_list)} unique, potentially relevant archived URLs from Wayback Machine (after filtering).")

            interesting_historical_paths_status_list = []; tasks_check_live_status = []
            async def check_live_status_task_wb(archived_item_detail):
                url_str_wb = archived_item_detail["url"]; parsed_url_wb = urlparse(url_str_wb)
                path_lower_wb, query_lower_wb = parsed_url_wb.path.lower(), parsed_url_wb.query.lower()
                is_interesting_wb = any(path_lower_wb.endswith(ext_wb) for ext_wb in interesting_exts_wb) or \
                                  any(keyword_wb in path_lower_wb for keyword_wb in interesting_keywords_wb) or \
                                  any(keyword_wb in query_lower_wb for keyword_wb in interesting_keywords_wb)
                if is_interesting_wb:
                    live_status_code = "Not Checked"; live_url_checked = "N/A"
                    if check_live_wb:
                        live_url_to_check = urljoin(f"{self.scheme}://{self.results['scan_metadata']['effective_domain']}", parsed_url_wb.path) # Use effective domain
                        if parsed_url_wb.query: live_url_to_check += f"?{parsed_url_wb.query}"
                        live_url_checked = live_url_to_check
                        resp_live_wb, _ = await self._make_request(live_url_to_check, method="HEAD", allow_redirects=False, max_retries=0)
                        if resp_live_wb: live_status_code = resp_live_wb.status
                        else: # Fallback to GET if HEAD fails (some servers don't support HEAD well)
                            resp_live_get_wb, _ = await self._make_request(live_url_to_check, method="GET", allow_redirects=False, max_retries=0)
                            if resp_live_get_wb: live_status_code = resp_live_get_wb.status
                            else: live_status_code = "Fetch Failed (Live)"

                    entry_wb = {"archived_url": url_str_wb, "wayback_mimetype": archived_item_detail.get("mimetype"), "wayback_timestamp": archived_item_detail.get("timestamp_wb"), "wayback_statuscode": archived_item_detail.get("statuscode_wb"), "live_check_url": live_url_checked, "live_status": live_status_code}
                    interesting_historical_paths_status_list.append(entry_wb)
                    severity_wb, desc_suffix_wb, conf_wb = "Low", "", "Medium"
                    if check_live_wb:
                        if live_status_code == 200:
                            severity_wb, desc_suffix_wb, conf_wb = "High", " Crucially, it is STILL ACCESSIBLE (HTTP 200) on the live site.", "High"
                            # Further escalate if path/ext is very sensitive
                            if any(keyword_admin in path_lower_wb for keyword_admin in ["admin", "config", "backup", "wp-admin", "secret", "env", "settings", ".git", ".svn"]) or \
                               any(path_lower_wb.endswith(ext_critical) for ext_critical in [".sql", ".bak", ".zip", ".tar.gz", ".env", ".config", ".ini", ".pem", ".key", ".mdb"]):
                                severity_wb = "Critical"
                        elif live_status_code == 403: severity_wb, desc_suffix_wb, conf_wb = "Low", " It is FORBIDDEN (HTTP 403) on the live site (path exists).", "High"
                        elif live_status_code == 404: severity_wb, desc_suffix_wb, conf_wb = "Info", " It is NOT FOUND (HTTP 404) on the live site (good, resource seems removed).", "High"
                        elif isinstance(live_status_code, int) and 300 <= live_status_code < 400 : severity_wb, desc_suffix_wb, conf_wb = "Info", f" It REDIRECTS (HTTP {live_status_code}) on the live site.", "High"
                        elif live_status_code == "Fetch Failed (Live)": desc_suffix_wb = " Could not fetch its live status."; conf_wb="Low"

                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Information Disclosure (Historical URL)", "description": f"Potentially sensitive URL '{url_str_wb}' (Mimetype: {archived_item_detail.get('mimetype')}) found in Wayback Machine archives.{desc_suffix_wb}",
                                 "severity": severity_wb, "confidence":conf_wb, "target_url": url_str_wb, "details":entry_wb,
                                 "recommendation": f"Review content of '{url_str_wb}' from archives and its current status at '{live_url_checked}'. If sensitive and still accessible/misconfigured, remediate. Ensure proper access controls or removal."},
                                log_message=f"Interesting archived URL: {url_str_wb} (Live Status: {live_status_code})", severity_for_log=severity_wb.upper())

            if fetched_urls_details_list and check_live_wb: # Only run tasks if there are interesting URLs and live check is enabled
                for item_detail_wb in fetched_urls_details_list: tasks_check_live_status.append(check_live_status_task_wb(item_detail_wb))
                if tasks_check_live_status: await self._execute_task_group(tasks_check_live_status, "Wayback Machine - Live Status Check")
            archived_urls_result_dict["interesting_historical_paths_status"] = interesting_historical_paths_status_list
        except requests.exceptions.Timeout: logger.error(f"Wayback Machine CDX API lookup timed out."); archived_urls_result_dict["error"] = "Wayback Machine CDX API lookup timed out."
        except requests.exceptions.RequestException as e_wayback_req: logger.error(f"Wayback Machine CDX API lookup error: {type(e_wayback_req).__name__} - {e_wayback_req}"); archived_urls_result_dict["error"] = f"Wayback Machine CDX API lookup error: {e_wayback_req}"
        except json.JSONDecodeError as e_json_wayback: logger.error(f"Wayback Machine CDX API returned non-JSON: {e_json_wayback}"); archived_urls_result_dict["error"] = f"Wayback Machine CDX API JSON decode error: {e_json_wayback}"
        except Exception as e_wayback_other_exc: logger.error(f"Unexpected error during Wayback Machine processing: {type(e_wayback_other_exc).__name__} - {e_wayback_other_exc}", exc_info=True); archived_urls_result_dict["error"] = f"Unexpected Wayback error: {type(e_wayback_other_exc).__name__}"
        logger.info("Wayback Machine URL fetching and live status check complete.")

    async def discover_api_endpoints(self):
        logger.info("Discovering potential API endpoints (Swagger/OpenAPI, GraphQL, common paths, JS findings)...")
        api_results_list = self.results["security_posture"].setdefault("potential_api_endpoints", [])
        common_api_doc_paths = ["/swagger.json", "/openapi.json", "/swagger.yaml", "/openapi.yaml", "/api/swagger.json", "/api/openapi.json", "/api/swagger.yaml", "/api/openapi.yaml", "/v1/swagger.json", "/v1/openapi.json", "/v1/swagger.yaml", "/v1/openapi.yaml", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/v1/api-docs", "/api/v2/api-docs", "/api/v3/api-docs", "/api/spec", "/api.json", "/api.yaml", "/swagger/v1/swagger.json", "/openapi/v3.json"]
        common_api_ui_paths = ["/swagger-ui.html", "/swagger-ui/", "/redoc", "/docs", "/api/docs", "/api/index.html", "/index.html", "/swagger", "/openapi", "/api-explorer", "/dev/portal"]
        common_graphql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/query"]
        generic_api_base_paths = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rpc", "/jsonrpc", "/webservice", "/ws", "/_next/data/", "/.netlify/functions/", "/service", "/services", "/gateway"]
        all_paths_to_check_api = set(common_api_doc_paths + common_api_ui_paths + common_graphql_paths + generic_api_base_paths)

        # Add paths found in JS (Regex and AST)
        if self.results["content_analysis"]["javascript_files"].get("ast_findings"):
            for js_ast_find in self.results["content_analysis"]["javascript_files"]["ast_findings"]:
                if js_ast_find.get("details", {}).get("finding_type") == "Potential Endpoint Path" and js_ast_find["details"].get("match"):
                    all_paths_to_check_api.add(js_ast_find["details"]["match"])
        if self.results["content_analysis"]["javascript_files"].get("analysis_summary"):
            for js_summary in self.results["content_analysis"]["javascript_files"]["analysis_summary"]:
                for regex_find in js_summary.get("regex_findings", []):
                    if regex_find.get("type") == "Potential Endpoint Path" and regex_find.get("match"): all_paths_to_check_api.add(regex_find["match"])

        final_url_parsed_api = urlparse(self.results["general_info"]["final_url"])
        base_url_api = f"{final_url_parsed_api.scheme}://{final_url_parsed_api.netloc}"

        async def check_api_path_task(path_to_check_api: str):
            api_full_url = urljoin(base_url_api, path_to_check_api.lstrip('/'))
            if any(item.get("url") == api_full_url for item in api_results_list): return # Already checked

            response_api, content_bytes_api = await self._make_request(api_full_url, allow_redirects=True, max_retries=0)

            if response_api and response_api.status == 200 and content_bytes_api:
                api_info_entry = {"url": api_full_url, "status": 200, "type": "Generic API-like Path", "source": "Common Path/JS Discovery", "details": {}}
                content_type_api = response_api.headers.get("Content-Type", "").lower()

                is_json_spec_type = ("json" in content_type_api or b'"swagger":' in content_bytes_api or b'"openapi":' in content_bytes_api) and \
                                   any(doc_kw in path_to_check_api.lower() for doc_kw in ["swagger.json", "openapi.json", "api-docs"])
                is_yaml_spec_type = ("yaml" in content_type_api or "x-yaml" in content_type_api or b"swagger:" in content_bytes_api or b"openapi:" in content_bytes_api) and \
                                   any(doc_kw in path_to_check_api.lower() for doc_kw in ["swagger.yaml", "openapi.yaml"])

                if is_json_spec_type or (is_yaml_spec_type and PYYAML_AVAILABLE):
                    api_info_entry["type"] = "API Documentation/Specification"; spec_content_str_api = ""; spec_data_api = None
                    try:
                        spec_content_str_api = content_bytes_api.decode(response_api.charset or 'utf-8', errors='replace')
                        if is_json_spec_type: spec_data_api = json.loads(spec_content_str_api)
                        elif is_yaml_spec_type and PYYAML_AVAILABLE: spec_data_api = yaml.safe_load(spec_content_str_api)

                        if spec_data_api and isinstance(spec_data_api, dict):
                            info_block = spec_data_api.get("info", {}); api_info_entry["details"]["title"] = info_block.get("title", "N/A"); api_info_entry["details"]["version"] = info_block.get("version", "N/A"); desc_val_api = info_block.get("description", "N/A"); api_info_entry["details"]["description"] = (desc_val_api[:200] + "...") if desc_val_api and len(desc_val_api) > 200 else desc_val_api

                            parsed_paths_api = []; paths_without_security_spec = []
                            global_security_schemes = spec_data_api.get("security", []) # OpenAPI v3
                            components_security_schemes = spec_data_api.get("components", {}).get("securitySchemes", {}) # OpenAPI v3
                            security_definitions_v2 = spec_data_api.get("securityDefinitions", {}) # Swagger v2
                            all_defined_security_schemes = {**components_security_schemes, **security_definitions_v2}

                            for api_path_key_spec, methods_obj_spec in spec_data_api.get("paths", {}).items():
                                path_details_entry_spec = {"path": api_path_key_spec, "methods": []}
                                if isinstance(methods_obj_spec, dict):
                                    for method_name_spec, method_spec_val in methods_obj_spec.items():
                                        if isinstance(method_spec_val, dict) and method_name_spec.lower() not in ["parameters", "$ref"]: # Common HTTP methods
                                            path_level_security = method_spec_val.get("security", None) # OpenAPI v3 path-level security
                                            effective_security_requirements = path_level_security if path_level_security is not None else global_security_schemes

                                            has_defined_security = False
                                            if effective_security_requirements: # This is a list of security requirement objects
                                                for req_scheme_obj in effective_security_requirements: # e.g., [{"petstore_auth": ["write:pets", "read:pets"]}]
                                                    for scheme_name_req in req_scheme_obj.keys():
                                                        if scheme_name_req in all_defined_security_schemes:
                                                            has_defined_security = True; break
                                                    if has_defined_security: break

                                            if not has_defined_security and effective_security_requirements: # Security is listed, but scheme name not in definitions
                                                paths_without_security_spec.append(f"{method_name_spec.upper()} {api_path_key_spec} (Required: {effective_security_requirements}, but scheme not found in definitions)")
                                            elif not effective_security_requirements: # No security requirements listed at all for this path/method
                                                 paths_without_security_spec.append(f"{method_name_spec.upper()} {api_path_key_spec} (No security requirement specified)")


                                            method_detail_spec = {"method": method_name_spec.upper(), "summary": (method_spec_val.get("summary") or method_spec_val.get("description", ""))[:100], "parameters_count": len(method_spec_val.get("parameters", [])), "security_schemes_applied": effective_security_requirements if effective_security_requirements else "None"}
                                            path_details_entry_spec["methods"].append(method_detail_spec)
                                parsed_paths_api.append(path_details_entry_spec)
                            api_info_entry["details"]["parsed_paths_summary_count"] = len(parsed_paths_api); api_info_entry["details"]["parsed_paths_sample"] = parsed_paths_api[:5] # Sample for brevity
                            if paths_without_security_spec:
                                api_info_entry["details"]["paths_lacking_security_definition"] = paths_without_security_spec
                                add_finding(self.results["correlated_intelligence"], "intelligence_items", # Log as correlated intel
                                            {"type": "API Security Concern (Specification)", "description": f"API specification at {api_full_url} defines endpoints ({len(paths_without_security_spec)} found, e.g., {paths_without_security_spec[0]}) that lack explicit security scheme definitions or have undefined schemes. This may indicate unauthenticated or improperly secured API endpoints.",
                                             "severity": "Medium", "confidence":"High", "details": {"api_spec_url": api_full_url, "endpoints_without_security": paths_without_security_spec[:5]},
                                             "recommendation": "Review all API paths in the specification. Ensure every endpoint that requires authentication or authorization has appropriate security schemes defined, and those schemes are present in securityDefinitions/components.securitySchemes. If an endpoint is intentionally public, document this clearly."},
                                            log_message=f"API Spec {api_full_url}: {len(paths_without_security_spec)} paths lack defined/applied security.", severity_for_log="MEDIUM")

                            if all_defined_security_schemes: api_info_entry["details"]["security_definitions"] = {name: {"type": detail.get("type"), "name": detail.get("name"), "in_location": detail.get("in")} for name, detail in all_defined_security_schemes.items() if isinstance(detail, dict)}
                            logger.info(f"Parsed API spec from {api_full_url}: {api_info_entry['details']['parsed_paths_summary_count']} paths. Title: {api_info_entry['details']['title']}")
                    except json.JSONDecodeError as e_json_api: api_info_entry["details"]["parsing_error"] = f"Failed to decode/parse JSON spec: {e_json_api}"
                    except yaml.YAMLError as e_yaml_api: api_info_entry["details"]["parsing_error"] = f"YAML parsing error: {e_yaml_api}"
                    except Exception as e_parse_api: api_info_entry["details"]["parsing_error"] = f"Error parsing API spec: {str(e_parse_api)[:100]}"
                elif is_yaml_spec_type and not PYYAML_AVAILABLE: api_info_entry["type"] = "API Documentation/Specification (YAML - Not Parsed)"; api_info_entry["details"]["parsing_error"] = "PyYAML library not installed."

                elif "text/html" in content_type_api and \
                     (any(ui_kw_api in path_to_check_api.lower() for ui_kw_api in ["swagger-ui", "redoc", "graphiql", "playground", "/docs", "/api/docs"]) or \
                      any(ui_kw_b in content_bytes_api.lower() for ui_kw_b in [b"swagger-ui", b"graphiql", b"graphql-playground", b"redoc", b"api explorer"])):
                    api_info_entry["type"] = "API Interactive UI"
                    try: # Attempt to get title of UI page
                        ui_soup_api = BeautifulSoup(content_bytes_api.decode(response_api.charset or 'utf-8', errors='replace'), 'html.parser')
                        ui_title_tag_api = ui_soup_api.find("title");
                        if ui_title_tag_api and ui_title_tag_api.string: api_info_entry["details"]["ui_title"] = ui_title_tag_api.string.strip()
                    except Exception: pass

                elif (path_to_check_api.endswith(("/graphql", "/query")) or "graphql" in content_type_api) and \
                     (b"data" in content_bytes_api.lower() or b"errors" in content_bytes_api.lower() or b"misplaced options" in content_bytes_api.lower() or b"GET query missing" in content_bytes_api.lower() or b"graphqlrequest" in content_bytes_api.lower()): # Heuristics for GraphQL
                    api_info_entry["type"] = "GraphQL Endpoint"; introspection_query_gql = {"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name fields { name args { name type { name ofType { name } } } } } directives { name } } } }"}
                    try:
                        resp_gql_intro, content_gql_bytes_intro = await self._make_request(api_full_url, method="POST", json=introspection_query_gql, headers={"Content-Type": "application/json"}, max_retries=0)
                        if resp_gql_intro and content_gql_bytes_intro and resp_gql_intro.status == 200:
                            gql_intro_result = json.loads(content_gql_bytes_intro.decode(resp_gql_intro.charset or 'utf-8', errors='replace'))
                            if "data" in gql_intro_result and gql_intro_result["data"] and "__schema" in gql_intro_result["data"]:
                                api_info_entry["details"]["introspection_enabled"] = True
                                query_type_name = gql_intro_result["data"]["__schema"].get("queryType", {}).get("name")
                                mutation_type_name = gql_intro_result["data"]["__schema"].get("mutationType", {}).get("name")
                                subscription_type_name = gql_intro_result["data"]["__schema"].get("subscriptionType", {}).get("name")
                                if query_type_name: api_info_entry["details"]["introspection_query_type"] = query_type_name
                                if mutation_type_name: api_info_entry["details"]["introspection_mutation_type"] = mutation_type_name
                                if subscription_type_name: api_info_entry["details"]["introspection_subscription_type"] = subscription_type_name
                                types_count = len(gql_intro_result["data"]["__schema"].get("types",[]))
                                api_info_entry["details"]["introspection_types_count"] = types_count
                                logger.info(f"GraphQL introspection successful for {api_full_url}. Query: {query_type_name or 'N/A'}, Mutation: {mutation_type_name or 'N/A'}, Types: {types_count}")
                            else: api_info_entry["details"].update({"introspection_enabled": False, "introspection_response_preview": gql_intro_result.get("errors", [{"message":"Unknown error"}])[0].get("message", "Unknown error") if gql_intro_result.get("errors") else "No __schema in data or data is null"})
                        else: api_info_entry["details"].update({"introspection_enabled": False, "introspection_error": f"Introspection query failed (Status: {resp_gql_intro.status if resp_gql_intro else 'N/A'})"})
                    except Exception as e_gql_intro_exc: api_info_entry["details"].update({"introspection_enabled": False, "introspection_error": f"Introspection query exception: {type(e_gql_intro_exc).__name__}"})

                # Update or add the finding
                existing_api_finding_index = next((i for i, item in enumerate(api_results_list) if item.get("url") == api_full_url), -1)
                should_add_or_update = False
                if existing_api_finding_index == -1: # New finding
                    should_add_or_update = True
                else: # Existing finding, update if new one is more specific
                    if api_results_list[existing_api_finding_index]["type"] == "Generic API-like Path" and api_info_entry["type"] != "Generic API-like Path":
                        api_results_list.pop(existing_api_finding_index) # Remove generic one
                        should_add_or_update = True

                if should_add_or_update:
                    api_results_list.append(api_info_entry)
                    sev_api = "Medium" if "Specification" in api_info_entry["type"] or "Interactive UI" in api_info_entry["type"] or "GraphQL Endpoint" in api_info_entry["type"] else "Info"
                    conf_api = "High" if "Specification" in api_info_entry["type"] or "Interactive UI" in api_info_entry["type"] or "GraphQL Endpoint" in api_info_entry["type"] else "Low"
                    recommendation_api = f"Review exposed API component at {api_full_url}. If spec/UI, ensure no sensitive internal details or unintended ops. For GraphQL, verify introspection intent and exposed types/fields. Ensure proper authN/authZ for all API endpoints."
                    add_finding(self.results["security_posture"], "vulnerability_findings", # Add to main vuln findings
                                {"type": "API Component Exposed", "description": f"{api_info_entry['type']} discovered at {api_full_url}.",
                                 "severity": sev_api, "confidence":conf_api, "target_url": api_full_url, "details":api_info_entry, "recommendation": recommendation_api},
                                log_message=f"{api_info_entry['type']} found at {api_full_url}", severity_for_log=sev_api.upper())

        api_tasks_list_final = [check_api_path_task(p_api) for p_api in sorted(list(all_paths_to_check_api))]
        if api_tasks_list_final: await self._execute_task_group(api_tasks_list_final, "API Endpoint & Specification Scan")
        logger.info("API endpoint discovery complete.")

    async def analyze_common_error_pages(self):
        if not self.config.get("enable_error_page_analysis", True):
            logger.info("Error page analysis disabled in configuration.")
            return

        error_page_results_list = self.results["technology_fingerprint"].setdefault("error_page_fingerprints", [])
        final_url_parsed_err = urlparse(self.results["general_info"]["final_url"])
        base_url_err = f"{final_url_parsed_err.scheme}://{final_url_parsed_err.netloc}"
        random_path_segment_err = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        error_test_paths_to_try = [f"/{random_path_segment_err}_KAIROS_ERROR_TEST.aspx", f"/{random_path_segment_err}_KAIROS_ERROR_TEST.php", f"/{random_path_segment_err}_KAIROS_ERROR_TEST.jsp", f"/{random_path_segment_err}_KAIROS_ERROR_TEST/", f"/{random_path_segment_err}KAIROS_ERROR_TEST.nonexistent", f"/{random_path_segment_err}.asp", f"/{random_path_segment_err}.cfm", f"/<>" ] # Invalid char to trigger error
        found_tech_on_error_page_set = set() # To avoid duplicate tech identification from multiple error pages

        for test_path_err in error_test_paths_to_try:
            error_test_url = urljoin(base_url_err, test_path_err)
            response_err, content_bytes_err = await self._make_request(error_test_url, allow_redirects=False, max_retries=0)

            if response_err and content_bytes_err and 400 <= response_err.status < 600: # Common error status codes
                status_err = response_err.status; html_content_error_page = ""
                try: html_content_error_page = content_bytes_err.decode(response_err.charset or 'utf-8', errors='replace')
                except UnicodeDecodeError: logger.warning(f"Could not decode error page content for {error_test_url}"); continue

                # Extensive list of error signatures
                error_signatures_map = {
                    "Apache Tomcat": [r"Apache Tomcat/([0-9\.]+)", r"HTTP Status \d{3} – (\w+)", r"JBOSS", r"ServletException", r"java\.lang\.", r"HTTP Status \d{3} – Not Found", r"NOTE: For security reasons, stack traces are not printed"],
                    "Apache (Generic)": [r"Apache.*Server at", r"mod_wsgi", r"mod_perl", r"Apache/\d\.\d\.\d+ \((\w+)\)", r"Additionally, a 404 Not Found", r"You don't have permission to access this resource."],
                    "IIS": [r"Microsoft-IIS/([0-9\.]+)", r"ASP.NET is configured to show verbose error messages", r"详细错误信息", r"HTTP Error \d{3}\.\d+", r"Server Error in '/' Application", r"HTTP \d{3} Error", r"<title>Error</title>", r"detailedError=(\d)"],
                    "Nginx": [r"<center>nginx</center>", r"nginx/([0-9\.]+)", r"openresty", r"<h1>\d{3} Not Found</h1>\s*<hr><center>nginx</center>"],
                    "LiteSpeed": [r"Proudly Served by LiteSpeed Web Server", r"lshttpd", r"Error \d{3}", r"LiteSpeed Web Server at"],
                    "Cloudflare": [r"Cloudflare", r"cf-ray", r"Error \d{3,4}", r"Attention Required! \| Cloudflare", r"Direct IP access not allowed", r"This website has been temporarily rate limited", r"error code: 10\d{2}"],
                    "AWS (S3/CloudFront/ELB/API GW)": [r"<Error><Code>NoSuchKey</Code>", r"cloudfront", r"X-Cache: Error from cloudfront", r"{\"message\":\"Forbidden\"}", r"Missing Authentication Token", r"AmazonS3", r"Generated by cloudfront \(CloudFront\)", r"The Amazon S3 bucket you are requesting does not exist", r"The specified key does not exist", r"x-amz-request-id", r"x-amz-id-2"],
                    "Google Cloud (GFE/Storage)": [r"The Google Cache", r"gws", r"Error code: \d+", r"Google Frontend", r"The requested URL was not found on this server.", r"Error 404 (Not Found)!!1"],
                    "Spring Boot": [r"Whitelabel Error Page", r"\"timestamp\":", r"\"status\": \d{3},", r"\"error\":", r"\"path\":", r"No message available", r"status=\d{3}"],
                    "Ruby on Rails": [r"Ruby on Rails", r"Application Trace", r"Framework Trace", r"WEBrick/([0-9\.]+)", r"Phusion Passenger", r"Action Controller: Exception caught", r"No route matches"],
                    "Django": [r"Django Version", r"You're seeing this error because you have <code>DEBUG = True</code>", r" CSRF verification failed.", r"Page not found \(404\)", r"DoesNotExist at /"],
                    "Flask/Werkzeug": [r"Werkzeug/([0-9\.]+)", r"jinja2.exceptions.TemplateNotFound", r"The browser \(or proxy\) sent a request that this server could not understand", r"Not Found: The requested URL was not found on the server."],
                    "ExpressJS (Node.js)": [r"Express</title>", r"Cannot GET /", r"NotFoundError:", r"<h1>Not Found</h1>", r"Error: Not Found", r"Cannot POST /"],
                    "PHP (Generic)": [r"<b>Parse error</b>:", r"<b>Warning</b>:", r"<b>Fatal error</b>:", r"on line <b>\d+</b>", r"PHP Version", r"Failed opening required"],
                    "WordPress (Debug/Error)": [r"wp-includes", r"There has been a critical error on your website.", r"WordPress database error:", r"Sorry, you are not allowed to access this page."],
                    "Drupal": [r"The website encountered an unexpected error. Please try again later.</p></div>", r"Drupal already installed", r"Drupal\\MaintenancePage", r"The requested page could not be found."],
                    "Joomla": [r"Joomla! Debug Console", r"Error displaying the error page", r"500 - An error has occurred.", r"404 - Component not found."],
                    "Magento": [r"There has been an error processing your request", r"Magento supports PHP \d+\.\d and above.", r"Exception printing is disabled by default for security reasons.", r"404 Error: Page Not Found"],
                    "Akamai": [r"You don't have permission to access", r"http://www.akamai.com/ Gesprerrt", r"Reference #\d{1,2}\.", r"Invalid URL</H1>\n<P>The requested URL \"\[no URL\]\", is invalid.<BR CLEAR=all>"],
                    "Sucuri WAF Block": [r"Sucuri WebSite Firewall - Access Denied", r"cloudproxy.sucuri.net/denial"],
                    "Incapsula/Imperva Block": [r"Incapsula incident ID", r"Request unsuccessful. Incapsula incident ID", r"Powered By Incapsula"],
                    "F5 BIG-IP Block": [r"Your support ID is:", r"The requested URL was rejected. Please consult with your administrator.", r"BIG-IP system error", r"The page was not found."],
                    "FortiWeb Block": [r"Web Page Blocked!", r"Powered by FortiGuard", r"Attack ID:"],
                    "Azure App Service/Gateway": [r"Microsoft Azure App Service", r"The page cannot be displayed because an internal server error has occurred.", r"Web Server's Default Page", r"X-Powered-By: ASP.NET", r"X-ASPNET-VERSION", r"404 - File or directory not found.", r"The resource you are looking for has been removed"],
                    "Generic Servlet Container": [r"Servlet Exception", r"javax.servlet", r"HTTP Status 404 – Not Found"],
                    "Oracle Application Server/WebLogic": [r"Oracle Application Server", r"Oracle WebLogic Server", r"Error 404--Not Found", r"From RFC 2068 <i>Hypertext Transfer Protocol -- HTTP/1.1</i>:"],
                    "IBM HTTP Server/WebSphere": [r"IBM HTTP Server", r"WebSphere Application Server", r"Error 404: SRVE0190E: File not found"],
                    "ModSecurity": [r"Mod_Security", r"mod_security", r"X-Mod-Security-Action", r"Sec- dimiliki", r"This error was generated by Mod_Security"]
                }
                tech_identified_from_this_page = False
                if html_content_error_page: # Ensure content exists
                    for tech_name_err, patterns_err in error_signatures_map.items():
                        if tech_name_err in found_tech_on_error_page_set: continue # Already logged this tech
                        for pattern_err in patterns_err:
                            try:
                                match_err = re.search(pattern_err, html_content_error_page, re.IGNORECASE | re.DOTALL)
                                if match_err:
                                    version_match_err = match_err.group(1) if len(match_err.groups()) > 0 and match_err.group(1) else None
                                    error_page_results_list.append({"status_code_triggered": status_err, "trigger_url": error_test_url, "identified_technology": tech_name_err, "matched_pattern": pattern_err, "extracted_version": version_match_err, "content_snippet_preview": html_content_error_page[:150]+"..."})
                                    found_tech_on_error_page_set.add(tech_name_err); tech_identified_from_this_page = True
                                    # Map identified tech to appropriate category in main tech fingerprint
                                    target_list_map_err = {"Apache Tomcat": "server_software", "Apache (Generic)": "server_software", "IIS": "server_software", "Nginx": "server_software", "LiteSpeed": "server_software", "Oracle Application Server/WebLogic": "server_software", "IBM HTTP Server/WebSphere": "server_software", "Cloudflare": "cdn_providers", "AWS (S3/CloudFront/ELB/API GW)": "cdn_providers", "Google Cloud (GFE/Storage)": "cdn_providers", "Akamai": "cdn_providers", "Azure App Service/Gateway": "cdn_providers", "Spring Boot": "frameworks_libraries", "Ruby on Rails": "frameworks_libraries", "Django": "frameworks_libraries", "Flask/Werkzeug": "frameworks_libraries", "ExpressJS (Node.js)": "frameworks_libraries", "PHP (Generic)": "programming_languages_detected", "WordPress (Debug/Error)": "cms_identified", "Drupal": "cms_identified", "Joomla": "cms_identified", "Magento": "cms_identified", "Sucuri WAF Block": "waf_detected", "Incapsula/Imperva Block": "waf_detected", "F5 BIG-IP Block": "waf_detected", "FortiWeb Block": "waf_detected", "Generic Servlet Container": "server_software", "ModSecurity": "waf_detected"}
                                    target_list_name_err = target_list_map_err.get(tech_name_err)
                                    if target_list_name_err:
                                        entry_name_err = tech_name_err + (f" v{version_match_err}" if version_match_err else "") + " (Error Page Fingerprint)"
                                        current_list_err = self.results["technology_fingerprint"].get(target_list_name_err, [])
                                        if not any(entry_name_err.startswith(existing_entry.split(" (")[0]) for existing_entry in current_list_err): # Avoid duplicates if Wappalyzer already found it
                                            current_list_err.append(entry_name_err); self.results["technology_fingerprint"][target_list_name_err] = current_list_err
                                        if version_match_err and (tech_name_err not in self.results["technology_fingerprint"]["software_versions_found"] or self.results["technology_fingerprint"]["software_versions_found"].get(tech_name_err)=="Unknown"):
                                            self.results["technology_fingerprint"]["software_versions_found"][tech_name_err] = version_match_err
                                    break # Found a pattern for this tech, move to next tech
                            except re.error as e_re_error_page: logger.warning(f"Regex error in error page analysis for tech '{tech_name_err}', pattern '{pattern_err}': {e_re_error_page}")
                        if tech_identified_from_this_page: break # Identified a tech from this specific error page, move to next test path

                if not tech_identified_from_this_page and status_err >= 400: # If no specific tech, log as generic
                    is_duplicate_generic_error = any(item.get("identified_technology") == "Generic Error Page" and item.get("status_code_triggered") == status_err and (item.get("content_snippet_preview","")[:100] == html_content_error_page[:100]) for item in error_page_results_list)
                    if not is_duplicate_generic_error:
                        error_page_results_list.append({"status_code_triggered": status_err, "trigger_url": error_test_url, "identified_technology": "Generic Error Page", "content_snippet_preview": html_content_error_page[:250]+"..."})
                        logger.info(f"Generic error page (HTTP {status_err}) found at {error_test_url}. Content might reveal info.")
                if tech_identified_from_this_page: break # Found a tech from this path, no need to try other error test paths for this specific fingerprinting run
        logger.info("Error page analysis complete.")

    async def fuzz_common_paths(self):
        if not self.config.get("enable_directory_file_fuzzing", False):
            logger.info("Directory/File Fuzzing disabled in configuration.")
            return
        logger.warning("EXPERIMENTAL: Directory/File Fuzzing enabled. This is active and can generate noise. Use responsibly and with EXPLICIT PERMISSION.")
        wordlist_path = self.config.get("fuzzing_wordlist_file", "common_paths_fuzz.txt")
        if not os.path.exists(wordlist_path): logger.error(f"Fuzzing wordlist {wordlist_path} not found. Skipping."); return
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f_fuzz: base_paths_from_file_fuzz = [line.strip() for line in f_fuzz if line.strip() and not line.startswith('#')]
        except Exception as e_fuzz_wl_read: logger.error(f"Could not read fuzzing wordlist {wordlist_path}: {e_fuzz_wl_read}. Skipping."); return
        if not base_paths_from_file_fuzz: logger.warning("Fuzzing wordlist is empty. Skipping."); return

        paths_to_fuzz_final_set = set(base_paths_from_file_fuzz)
        extensions_to_apply_fuzz = self.config.get("fuzzing_apply_common_extensions", [])
        if extensions_to_apply_fuzz:
            for p_base_fuzz in list(base_paths_from_file_fuzz): # Iterate over a copy
                # Only add extensions if base path doesn't look like it already has one, or is a directory
                if ('.' not in p_base_fuzz.split('/')[-1] or p_base_fuzz.endswith('/')) and not any(p_base_fuzz.lower().endswith(known_ext.lower()) for known_ext in extensions_to_apply_fuzz):
                    for ext_fuzz_item in extensions_to_apply_fuzz: paths_to_fuzz_final_set.add(f"{p_base_fuzz.rstrip('/')}{ext_fuzz_item}")
        if not paths_to_fuzz_final_set: logger.info("No paths to fuzz after processing wordlist and extensions."); return

        final_url_parsed_fuzz = urlparse(self.results["general_info"]["final_url"])
        base_url_fuzz_req = f"{final_url_parsed_fuzz.scheme}://{final_url_parsed_fuzz.netloc}"
        fuzzed_paths_found_results_list = self.results["security_posture"].setdefault("fuzzed_paths_found", [])
        _, baseline_404_content_bytes_fuzz, _ = self._baseline_404_response_cache
        baseline_404_content_hash_for_fuzz = hashlib.md5(baseline_404_content_bytes_fuzz or b"").hexdigest() if baseline_404_content_bytes_fuzz is not None else None

        async def check_fuzzed_path_task(raw_path_to_fuzz: str):
            fuzz_target_full_url = urljoin(base_url_fuzz_req, raw_path_to_fuzz.lstrip('/'))
            fuzz_timeout = aiohttp.ClientTimeout(total=max(7, self.config["request_timeout_seconds"] // 3)) # Faster timeout for fuzzing
            resp_fuzz_req, content_fuzz_bytes_req = await self._make_request(fuzz_target_full_url, method="GET", allow_redirects=False, max_retries=0, timeout_override=fuzz_timeout)
            if resp_fuzz_req:
                current_status_fuzz_req = resp_fuzz_req.status
                # Filter out responses that are identical to the baseline 404 page
                if current_status_fuzz_req == 404 and baseline_404_content_hash_for_fuzz:
                    if content_fuzz_bytes_req and hashlib.md5(content_fuzz_bytes_req).hexdigest() == baseline_404_content_hash_for_fuzz:
                        logger.debug(f"Fuzzed path {fuzz_target_full_url} (HTTP 404) matches baseline 404 content. Ignoring."); return

                # Log if status is not 404, or if it is 404 but different from baseline (or no baseline known)
                if current_status_fuzz_req != 404 or not baseline_404_content_hash_for_fuzz or (current_status_fuzz_req == 404 and baseline_404_content_hash_for_fuzz and content_fuzz_bytes_req and hashlib.md5(content_fuzz_bytes_req).hexdigest() != baseline_404_content_hash_for_fuzz):
                    finding_fuzz_data = {"path": raw_path_to_fuzz, "url": fuzz_target_full_url, "status": current_status_fuzz_req, "length": len(content_fuzz_bytes_req) if content_fuzz_bytes_req else 0, "content_type": resp_fuzz_req.headers.get("Content-Type")}
                    if not any(item.get("url") == fuzz_target_full_url and item.get("status") == current_status_fuzz_req for item in fuzzed_paths_found_results_list):
                        fuzzed_paths_found_results_list.append(finding_fuzz_data)

                    sev_fuzz_val = "Medium" if current_status_fuzz_req == 200 else ("Medium" if current_status_fuzz_req == 500 else ("Low" if current_status_fuzz_req == 403 else "Info"))
                    conf_fuzz_val = "Medium" if current_status_fuzz_req == 200 or current_status_fuzz_req == 500 else ("High" if current_status_fuzz_req == 403 else "Low")
                    add_finding(self.results["security_posture"], "vulnerability_findings",
                                {"type": "Fuzzed Path Discovery", "description": f"Fuzzed path '{raw_path_to_fuzz}' responded with HTTP status {current_status_fuzz_req}.",
                                 "severity": sev_fuzz_val, "confidence":conf_fuzz_val, "target_url": fuzz_target_full_url, "details":finding_fuzz_data,
                                 "recommendation": f"Review resource at '{fuzz_target_full_url}'. If 200, check for sensitive content/exposure. If 403, path exists. If 500, may indicate unhandled error. If 404 but different from baseline, custom error page."},
                                log_message=f"Fuzzed path: {fuzz_target_full_url} (Status {current_status_fuzz_req})", severity_for_log=sev_fuzz_val.upper())

        fuzz_tasks_to_run = [check_fuzzed_path_task(fp_fuzz_item) for fp_fuzz_item in sorted(list(paths_to_fuzz_final_set))]
        if fuzz_tasks_to_run: await self._execute_task_group(fuzz_tasks_to_run, "Path Fuzzing")
        logger.info("Path fuzzing scan complete.")

    async def run_cms_specific_scans_if_detected(self):
        cms_name = self.results["technology_fingerprint"].get("cms_identified")
        if not cms_name: logger.info("No CMS identified, skipping CMS-specific scans."); return
        logger.info(f"CMS '{cms_name}' identified. Running specific checks...")
        cms_config_data = self.config["cms_specific_checks"].get(cms_name)
        if not cms_config_data: logger.warning(f"No specific KAIROS configuration for CMS: {cms_name}."); return

        cms_results_dict_main = self.results["cms_specific_findings"].setdefault(cms_name, {"paths_status": [], "version": "Unknown", "observations": [], "vulnerabilities_info": [], "vulnerability_search_links": {}})
        final_url_parsed_cms_scan = urlparse(self.results["general_info"]["final_url"])
        base_url_cms_scan = f"{final_url_parsed_cms_scan.scheme}://{final_url_parsed_cms_scan.netloc}"

        async def check_cms_specific_path_task(path_cms_check: str):
            url_cms_to_check = urljoin(base_url_cms_scan, path_cms_check.lstrip('/'))
            resp_cms_path, content_cms_bytes_path = await self._make_request(url_cms_to_check, allow_redirects=False, max_retries=0)
            status_cms_path = resp_cms_path.status if resp_cms_path else "Fetch Failed"
            length_cms_path = len(content_cms_bytes_path) if content_cms_bytes_path else 0
            path_status_entry = {"path": path_cms_check, "url": url_cms_to_check, "status": status_cms_path, "length": length_cms_path}
            if not any(p_stat.get("url") == url_cms_to_check for p_stat in cms_results_dict_main["paths_status"]):
                cms_results_dict_main["paths_status"].append(path_status_entry)

            if resp_cms_path and status_cms_path == 200:
                add_finding(cms_results_dict_main, "observations", # This goes to cms_specific_findings section
                            {"type": "CMS Path Accessible", "path": path_cms_check, "url": url_cms_to_check, "severity": "Info", "confidence":"High", "description": f"Common {cms_name} path '{path_cms_check}' is accessible (HTTP 200)."},
                            log_message=f"CMS Path '{path_cms_check}' accessible for {cms_name} at {url_cms_to_check}", severity_for_log="INFO")
                # Specific check for WordPress install scripts
                if cms_name == "WordPress" and ("install.php" in path_cms_check.lower() or "setup-config.php" in path_cms_check.lower()) and content_cms_bytes_path:
                    if b"WordPress setup configuration file" in content_cms_bytes_path or b"install WordPress" in content_cms_bytes_path or b"Setup Configuration File" in content_cms_bytes_path :
                        add_finding(cms_results_dict_main, "vulnerabilities_info", # This is a specific vulnerability under CMS findings
                                    {"type": "CMS Misconfiguration (WordPress Install Script)", "description": "WordPress installation script (e.g., wp-admin/install.php) is accessible. This might indicate an incomplete/recoverable installation or script not removed post-installation.",
                                     "severity": "High", "confidence":"High", "details": {"path": path_cms_check, "url": url_cms_to_check},
                                     "recommendation": "If WordPress is installed, remove or restrict access to installation scripts (e.g., wp-admin/install.php, wp-admin/setup-config.php)."},
                                    log_message=f"WordPress install script accessible at {url_cms_to_check}", severity_for_log="HIGH")

        cms_path_tasks_to_run = [check_cms_specific_path_task(p_cms_item) for p_cms_item in cms_config_data.get("paths", [])]
        if cms_path_tasks_to_run: await self._execute_task_group(cms_path_tasks_to_run, f"{cms_name} Specific Path Checks")

        # Version detection for CMS
        cms_version_from_tech = self.results["technology_fingerprint"]["software_versions_found"].get(cms_name)
        if cms_version_from_tech and cms_version_from_tech != "Unknown":
            cms_results_dict_main["version"] = f"{cms_version_from_tech} (Source: Header/Wappalyzer)"
        elif self._main_page_html_cache and "version_pattern" in cms_config_data: # Fallback to HTML patterns
            for vp_regex_cms_item in cms_config_data["version_pattern"]:
                match_cms_ver_html = re.search(vp_regex_cms_item, self._main_page_html_cache, re.IGNORECASE | re.MULTILINE)
                if match_cms_ver_html and len(match_cms_ver_html.groups()) > 0:
                    ver_cms_html = match_cms_ver_html.group(1).strip(" .-")
                    if ver_cms_html and ver_cms_html != cms_results_dict_main["version"].split(" (")[0]: # Update if new/different
                        cms_results_dict_main["version"] = f"{ver_cms_html} (Source: HTML Pattern '{vp_regex_cms_item[:30]}...')"
                        if cms_name not in self.results["technology_fingerprint"]["software_versions_found"] or self.results["technology_fingerprint"]["software_versions_found"].get(cms_name) == "Unknown":
                            self.results["technology_fingerprint"]["software_versions_found"][cms_name] = ver_cms_html
                        break # Found version, stop checking patterns

        current_cms_version = cms_results_dict_main["version"].split(" (")[0] # Get just the version number
        if current_cms_version != "Unknown":
            self.results["technology_fingerprint"]["software_versions_found"][cms_name] = current_cms_version # Ensure it's in main tech list

            search_links_cms_vuln = generate_vuln_search_url(cms_name, current_cms_version)
            cms_results_dict_main["vulnerability_search_links"] = search_links_cms_vuln
            obs_text = f"{cms_name} version {current_cms_version} detected. Check this version against known vulnerability databases."
            cms_results_dict_main["observations"].append({"type": "CMS Version Identified", "description": obs_text, "search_links": search_links_cms_vuln, "severity": "Info", "confidence":"Medium"})

            # Add to main vulnerability findings as well for NVD check
            cms_finding_entry = {
                "type": f"Software Version Information (CMS: {cms_name})", "description": obs_text, "severity": "Info", "confidence":"Medium",
                "details": {"software": cms_name, "version": current_cms_version, "search_links": search_links_cms_vuln, "nvd_cves": []},
                "recommendation": f"Regularly check '{cms_name} v{current_cms_version}' for vulnerabilities. Apply patches. Use dedicated CMS scanners like {cms_config_data.get('dedicated_tool_recommendation', 'specialized tools')} for in-depth analysis."
            }
            add_finding(self.results["security_posture"], "vulnerability_findings", cms_finding_entry,
                        log_message=f"{cms_name} v{current_cms_version} detected. CVE check advised.", severity_for_log="INFO")

            # NVD Check for CMS version (re-uses logic from conduct_basic_vulnerability_checks)
            nvd_enabled = self.config["enable_external_api_integrations"].get("nvd", False)
            nvd_api_key = self.config["external_api_keys"].get("nvd_api_key")
            if nvd_enabled and nvd_api_key and REQUESTS_AVAILABLE:
                nvd_cves_found_cms = await self._fetch_nvd_cves(cms_name, current_cms_version)
                if nvd_cves_found_cms:
                    for finding in self.results["security_posture"]["vulnerability_findings"]: # Find the CMS entry we just added
                        if finding.get("details", {}).get("software") == cms_name and finding.get("details", {}).get("version") == current_cms_version:
                            finding["details"]["nvd_cves"] = nvd_cves_found_cms
                            critical_cves_cms = [cve for cve in nvd_cves_found_cms if cve.get("baseSeverity", "").upper() == "CRITICAL"]
                            high_cves_cms = [cve for cve in nvd_cves_found_cms if cve.get("baseSeverity", "").upper() == "HIGH"]
                            if critical_cves_cms:
                                finding["severity"] = "Critical"
                                add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                    {"type": "High Impact CVE (NVD - CMS)", "description": f"CRITICAL CVE(s) found for {cms_name} v{current_cms_version} (e.g., {critical_cves_cms[0]['cve_id']}). Immediate attention required.", "severity": "Critical", "confidence":"High", "details": {"software": cms_name, "version":current_cms_version, "cve_sample": critical_cves_cms[0]}},
                                    log_message=f"CRITICAL NVD CVEs found for CMS {cms_name} v{current_cms_version}", severity_for_log="CRITICAL")
                            elif high_cves_cms:
                                if finding["severity"] not in ["Critical"]: finding["severity"] = "High"
                                add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                    {"type": "High Impact CVE (NVD - CMS)", "description": f"HIGH severity CVE(s) found for {cms_name} v{current_cms_version} (e.g., {high_cves_cms[0]['cve_id']}). Requires review.", "severity": "High", "confidence":"High", "details": {"software": cms_name, "version":current_cms_version, "cve_sample": high_cves_cms[0]}},
                                    log_message=f"HIGH NVD CVEs found for CMS {cms_name} v{current_cms_version}", severity_for_log="HIGH")
                            break
                    self.results["security_posture"]["external_api_analysis_summary"]["nvd_cves_found_total"] += len(nvd_cves_found_cms)

        if cms_config_data.get("vulnerable_plugins_themes_check", False):
            tool_rec_cms_scan = cms_config_data.get("dedicated_tool_recommendation", "specialized CMS scanning tools")
            observation_text_cms_scan = (f"Automated vulnerability scanning for {cms_name} extensions (plugins, themes, etc.) is complex and requires large, updated vulnerability databases. KAIROS recommends using dedicated tools like {tool_rec_cms_scan} and manual reviews based on the identified CMS version and extensions.")
            cms_results_dict_main["observations"].append({"type": "Further Analysis Recommendation (CMS Extensions)", "description": observation_text_cms_scan, "severity": "Info", "confidence":"High"})
            logger.info(f"For detailed {cms_name} plugin/theme vulnerability analysis, manual checks and tools like {tool_rec_cms_scan} are highly recommended.")
        logger.info(f"CMS-specific checks for {cms_name} complete.")

    async def correlate_findings(self):
        logger.info("Correlating findings for deeper intelligence...")
        correlated_intel_list = self.results["correlated_intelligence"]

        # Rule 1: Exposed Version Control + Other Sensitive Files
        exposed_files_list = self.results["security_posture"].get("exposed_sensitive_files", [])
        vc_type_found = self.results["technology_fingerprint"].get("version_control_type")
        if vc_type_found and any(vc_type_found.lower() in ef.get("path","").lower() for ef in exposed_files_list if isinstance(ef, dict)):
            add_finding(correlated_intel_list, "intelligence_items",
                        {"type": "Correlated Risk: Version Control & Exposed Files", "description": f"Version control system ({vc_type_found}) artifacts (e.g., .{vc_type_found.lower().split(' ')[0]}/) are exposed, AND other sensitive files/paths were also found accessible. This significantly increases risk of source code/config/data leakage.",
                         "severity": "High", "confidence":"High", "details": {"version_control_type": vc_type_found, "sample_exposed_file_categories": list(set(ef.get("category", "N/A") for ef in exposed_files_list[:3] if isinstance(ef, dict)))},
                         "recommendation": "Prioritize immediate restriction of version control directories and all other identified exposed sensitive files. Audit for data leakage. Ensure web server configurations block access to VCS directories."},
                        log_message="Correlated: Exposed VC and other sensitive files - HIGH RISK", severity_for_log="HIGH")

        # Rule 2: Software on Exposed Non-Web Port
        software_versions_found_dict = self.results["technology_fingerprint"].get("software_versions_found", {})
        open_ports_list = self.results["security_posture"].get("open_ports", [])
        for sw_name_corr, sw_version_info_corr in software_versions_found_dict.items():
            sw_version_corr = sw_version_info_corr if isinstance(sw_version_info_corr, str) else (sw_version_info_corr.get('version', "Unknown") if isinstance(sw_version_info_corr, dict) else "Unknown")
            if sw_version_corr == "Unknown" or not sw_version_corr: continue
            sw_name_base = sw_name_corr.split(" (Port")[0] # Handle "Nginx (Port 8080)"
            for port_info_corr in open_ports_list:
                if isinstance(port_info_corr, dict) and port_info_corr.get("product") and sw_name_base.lower() in port_info_corr["product"].lower() and port_info_corr.get("port") not in [80, 443, None, "Skipped", "Error"]:
                    add_finding(correlated_intel_list, "intelligence_items",
                                {"type": "Correlated Risk: Software on Exposed Non-Web Port", "description": f"Software '{sw_name_corr} v{sw_version_corr}' is detected, and a related service '{port_info_corr['service_name']}' is exposed on non-standard port {port_info_corr['port']}. If '{sw_name_corr}' has known vulnerabilities, this exposed service is a direct attack vector.",
                                 "severity": "Medium", "confidence":"Medium", "details": {"software": sw_name_corr, "version": sw_version_corr, "port": port_info_corr['port'], "service": port_info_corr['service_name']},
                                 "recommendation": f"Urgently check '{sw_name_corr} v{sw_version_corr}' for CVEs. If vulnerable, patch or restrict access to port {port_info_corr['port']}. Ensure service requires strong authentication."},
                                log_message=f"Correlated: {sw_name_corr} v{sw_version_corr} on non-web port {port_info_corr['port']}", severity_for_log="MEDIUM")
                    break # Found correlation for this software, move to next

        # Rule 3: WAF Detected but High/Critical Vulns Found
        waf_detected_list_corr = self.results["technology_fingerprint"].get("waf_detected", [])
        high_sev_vulns_list_corr = [vf_item for vf_item in self.results["security_posture"].get("vulnerability_findings", []) if isinstance(vf_item, dict) and vf_item.get("severity", "").upper() in ["HIGH", "CRITICAL"]]
        if waf_detected_list_corr and len(high_sev_vulns_list_corr) > 1 : # More than 1 high/crit finding with WAF
            waf_names_str = ", ".join(w_item['name'] for w_item in waf_detected_list_corr if isinstance(w_item, dict) and 'name' in w_item)
            add_finding(correlated_intel_list, "intelligence_items",
                        {"type": "Correlated Observation: WAF Ineffectiveness or Bypass?", "description": f"A WAF ({waf_names_str}) is detected, yet multiple high/critical severity issues ({len(high_sev_vulns_list_corr)} found) were identified. This may indicate WAF misconfiguration, bypass, or gaps in its rule-set.",
                         "severity": "Medium", "confidence":"Medium", "details": {"waf_names": waf_names_str, "high_severity_findings_count": len(high_sev_vulns_list_corr), "sample_high_vuln_types": list(set(v_item.get("type") for v_item in high_sev_vulns_list_corr[:3] if isinstance(v_item, dict))) },
                         "recommendation": "Review WAF configuration and logs. Ensure rules are up-to-date, in blocking mode, and address common web vulnerabilities. Test WAF bypass techniques specific to the WAF and application."},
                        log_message=f"Correlated: WAF ({waf_names_str}) detected but {len(high_sev_vulns_list_corr)} high/critical vulns present.", severity_for_log="MEDIUM")
        elif waf_detected_list_corr and len(high_sev_vulns_list_corr) == 0 and len(self.results["security_posture"].get("vulnerability_findings",[])) > 0: # WAF present, no high/crit, but other findings
             waf_names_str_positive = ", ".join(w_item['name'] for w_item in waf_detected_list_corr if isinstance(w_item, dict) and 'name' in w_item)
             add_finding(correlated_intel_list, "intelligence_items",
                         {"type": "Correlated Observation: WAF Potentially Effective", "description": f"A WAF ({waf_names_str_positive}) is detected, and no high or critical severity vulnerabilities were directly identified by KAIROS automated checks. This *may* indicate WAF is providing some protection. Manual testing still required.",
                          "severity": "Info", "confidence":"Low", "details": {"waf_names": waf_names_str_positive, "low_medium_findings_count": len(self.results["security_posture"].get("vulnerability_findings",[]))},
                          "recommendation": "Absence of high/critical automated findings with a WAF is positive, but not full security. Continue with manual penetration testing, business logic abuse testing, and ensure WAF rules are comprehensive and updated. Verify WAF is in blocking mode."},
                         log_message=f"Correlated: WAF ({waf_names_str_positive}) detected, no high/critical KAIROS findings. WAF might be effective.", severity_for_log="INFO")


        # Rule 4: Exposed API Spec + Client-Side API Keys
        api_specs_found_list = [api_item for api_item in self.results["security_posture"].get("potential_api_endpoints", []) if isinstance(api_item,dict) and "Specification" in api_item.get("type", "")]
        api_keys_in_js_list = [key_item for key_item in self.results["content_analysis"].get("suspected_api_keys", []) if isinstance(key_item, dict) and ("js_url" in key_item.get("details", {}) or "source_js_url" in key_item.get("details", {}) or "source_js_url" in key_item)] # Ensure keys are from JS
        if api_specs_found_list and api_keys_in_js_list:
            key_details_for_report_corr = []
            for k_item_corr in api_keys_in_js_list[:3]: # Sample of keys
                details_dict_corr = k_item_corr.get("details", k_item_corr) # Handle if details is nested or not
                key_details_for_report_corr.append(details_dict_corr.get('key_name', 'Unknown Key'))
            add_finding(correlated_intel_list, "intelligence_items",
                        {"type": "Correlated Risk: Exposed API Spec & Client-Side API Keys", "description": "API specifications (e.g., Swagger/OpenAPI) are publicly accessible, AND potential API keys are found in client-side JavaScript. Attackers can use the specification to understand API structure and exposed keys to potentially abuse the API.",
                         "severity": "Critical", "confidence":"High", "details": {"api_spec_urls_sample": [api_item_corr['url'] for api_item_corr in api_specs_found_list[:2] if isinstance(api_item_corr, dict)], "js_api_key_names_sample": list(set(key_details_for_report_corr))},
                         "recommendation": "Restrict public access to API specifications unless intended. Revoke hardcoded API keys in JavaScript immediately. Implement secure API gateway or BFF pattern with short-lived tokens or session-based auth."},
                        log_message="Correlated: Exposed API spec and JS API keys - CRITICAL RISK", severity_for_log="CRITICAL")

        # Rule 5: Debug Mode Enabled + Exposed Config Files
        debug_vuln_item = next((v_item for v_item in self.results["security_posture"].get("vulnerability_findings",[]) if isinstance(v_item, dict) and v_item.get("type")=="Information Disclosure (Debug/Error)"), None)
        sensitive_configs_exposed_list = [ef_item for ef_item in exposed_files_list if isinstance(ef_item, dict) and ef_item.get("category") == "config_files"]
        if debug_vuln_item and sensitive_configs_exposed_list:
             add_finding(correlated_intel_list, "intelligence_items",
                         {"type": "Correlated Risk: Debug Mode & Exposed Config Files", "description": "Debug mode or verbose error messages are enabled, AND sensitive configuration files are exposed. This combination can lead to severe information leakage (credentials, paths) through error messages or direct access.",
                          "severity": "Critical", "confidence":"High", "details": {"debug_evidence": debug_vuln_item.get("evidence_summary"), "config_file_paths_sample": [ef_item.get("path") for ef_item in sensitive_configs_exposed_list[:2]]},
                          "recommendation": "Immediately disable debug mode/verbose errors in production. Restrict access to all configuration files. Audit for past leakage. Rotate all credentials in exposed config files."},
                         log_message="Correlated: Debug mode AND exposed config files - CRITICAL RISK", severity_for_log="CRITICAL")

        # Rule 6: Exposed Admin Interface + Weak SSL/TLS
        admin_interfaces = [f for f in self.results["security_posture"].get("exposed_sensitive_files", []) if isinstance(f, dict) and f.get("category") == "common_admin_interfaces" and f.get("status") == 200]
        ssl_config_details = self.results["security_posture"].get("ssl_tls_config", {})
        weak_ssl_protocol = ssl_config_details.get("tls_version_used") in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"]
        weak_ssl_sig = any(weak_algo.lower() in ssl_config_details.get("signature_algorithm","").lower() for weak_algo in ["sha1", "md5", "md2"])
        expired_ssl = ssl_config_details.get("days_to_expiry", 999) < 0 # Default to large number if not present
        if admin_interfaces and (weak_ssl_protocol or weak_ssl_sig or expired_ssl):
            ssl_issues_str_list = []
            if weak_ssl_protocol: ssl_issues_str_list.append(f"weak protocol ({ssl_config_details.get('tls_version_used')})")
            if weak_ssl_sig: ssl_issues_str_list.append(f"weak signature ({ssl_config_details.get('signature_algorithm')})")
            if expired_ssl: ssl_issues_str_list.append("expired certificate")
            ssl_issues_str = ", ".join(ssl_issues_str_list)
            add_finding(correlated_intel_list, "intelligence_items",
                        {"type": "Correlated Risk: Exposed Admin Interface & Weak SSL/TLS", "description": f"Administrative interface(s) (e.g., {admin_interfaces[0]['url']}) accessible, AND site's SSL/TLS configuration has weaknesses ({ssl_issues_str}). Increases risk of credential interception.",
                         "severity": "High", "confidence":"High", "details": {"admin_interface_sample": admin_interfaces[0]['url'], "ssl_issues": ssl_issues_str, "ssl_config_summary": {k:v for k,v in ssl_config_details.items() if k in ["tls_version_used", "signature_algorithm", "days_to_expiry", "error"]}},
                         "recommendation": "Strengthen SSL/TLS config: disable weak protocols/ciphers, renew certs, use strong signature algorithms. Restrict admin interface access (IP whitelist, VPN, MFA)."},
                        log_message=f"Correlated: Exposed admin interface(s) with weak SSL/TLS ({ssl_issues_str})", severity_for_log="HIGH")

        # Rule 7: Sensitive JS Storage + External Form Posts
        js_storage_findings = [f for f in self.results["content_analysis"].get("javascript_files", {}).get("ast_findings", []) if isinstance(f, dict) and f.get("details", {}).get("finding_type") == "Sensitive Client-Side Storage"]
        forms_with_external_action = []
        if self._main_page_soup_cache:
            for form_tag in self._main_page_soup_cache.find_all("form", action=True):
                action_url = form_tag.get("action", "")
                if action_url: # Ensure action is not empty
                    parsed_action_url = urlparse(action_url)
                    if parsed_action_url.netloc and parsed_action_url.netloc != urlparse(self.results["general_info"]["final_url"]).netloc: # Check if domain is different
                        forms_with_external_action.append(action_url)
        if js_storage_findings and forms_with_external_action:
            storage_keys_sample = list(set(f.get("details", {}).get("key_name") for f in js_storage_findings[:2]))
            add_finding(correlated_intel_list, "intelligence_items",
                        {"type": "Correlated Risk: Sensitive JS Storage & External Form Post", "description": f"Potentially sensitive data (keys: {', '.join(storage_keys_sample)}) is stored in client-side JavaScript storage (localStorage/sessionStorage), AND the page contains forms submitting data to external domains (e.g., {forms_with_external_action[0]}). If stored data is exfiltrated via XSS or insecure form handling, it could lead to account takeover or data leakage.",
                         "severity": "Medium", "confidence":"Medium", "details": {"js_storage_keys_sample": storage_keys_sample, "external_form_actions_sample": forms_with_external_action[:2]},
                         "recommendation": "Avoid storing highly sensitive data in client-side storage. Use HttpOnly cookies for session tokens. Scrutinize forms posting data to external domains; ensure this is intended and secure. Implement robust XSS protection."},
                        log_message=f"Correlated: Sensitive JS storage & external form posts found.", severity_for_log="MEDIUM")

        # Rule 8: robots.txt disallow vs sitemap.xml (live links)
        robots_disallowed = set(self.results["content_analysis"].get("robots_disallowed_paths", []))
        sitemap_urls_from_content = self.results["content_analysis"].get("sitemap_extracted_url_sample", [])
        sitemap_urls = set(u for u in sitemap_urls_from_content if isinstance(u,str) and not u.startswith("... and")) # Get actual URLs from sample

        if 'sitemap_extracted_url_count' in self.results["content_analysis"] and self.results["content_analysis"]['sitemap_extracted_url_count'] > len(sitemap_urls):
            logger.debug("Sitemap too large for full robots.txt contradiction check, using sample.") # For very large sitemaps, this check is on a sample

        contradictions_found = []
        if robots_disallowed and sitemap_urls:
            for disallow_path in robots_disallowed:
                normalized_disallow = disallow_path.strip('*').rstrip('/') # Normalize common wildcards
                for sitemap_url_str in sitemap_urls:
                    try:
                        sitemap_parsed_url = urlparse(sitemap_url_str)
                        if sitemap_parsed_url.path.rstrip('/').startswith(normalized_disallow): # Check if disallowed path is a prefix
                            # Check if this sitemap URL is actually live and 200
                            live_status_check_resp, _ = await self._make_request(sitemap_url_str, method="HEAD", allow_redirects=False, max_retries=0)
                            if live_status_check_resp and live_status_check_resp.status == 200:
                                contradictions_found.append({"disallowed_robots": disallow_path, "sitemap_live_url": sitemap_url_str})
                                break # Found one contradiction for this disallow rule
                    except Exception: pass # Ignore parsing errors for individual URLs
        if contradictions_found:
             add_finding(correlated_intel_list, "intelligence_items",
                         {"type": "Correlated Observation: Robots.txt vs Sitemap.xml Contradiction", "description": f"{len(contradictions_found)} instance(s) where robots.txt disallows a path (e.g., '{contradictions_found[0]['disallowed_robots']}') but sitemap.xml includes a corresponding live URL (e.g., '{contradictions_found[0]['sitemap_live_url']}'). This can confuse search engines and might indicate misconfiguration or unintentionally exposed content.",
                          "severity": "Low", "confidence":"Medium", "details": {"contradictions_sample": contradictions_found[:3]},
                          "recommendation": "Review robots.txt and sitemap.xml for consistency. Ensure disallowed paths are truly meant to be hidden and are not listed in sitemaps. If content listed in sitemap should not be indexed, remove it from sitemap and ensure server-side access controls are in place."},
                         log_message=f"Correlated: {len(contradictions_found)} robots.txt vs sitemap.xml contradictions found for live paths.", severity_for_log="LOW")

        # Rule 9: Exposed Emails + Weak Mail Security (SPF/DMARC)
        emails_on_page_list = self.results["content_analysis"].get("emails_on_page", [])
        mail_sec_issues_list = self.results["dns_information"].get("mail_servers_config_issues", [])
        if emails_on_page_list and mail_sec_issues_list:
            weak_spf = any("SPF Policy Weak" in issue.get("type","") or "SPF Policy Incomplete" in issue.get("type","") for issue in mail_sec_issues_list if isinstance(issue,dict))
            weak_dmarc = any("DMARC Policy Weak" in issue.get("type","") or "DMARC Policy Missing" in issue.get("type","") for issue in mail_sec_issues_list if isinstance(issue,dict))
            if weak_spf or weak_dmarc:
                issue_summary = []
                if weak_spf: issue_summary.append("Weak/Missing SPF")
                if weak_dmarc: issue_summary.append("Weak/Missing DMARC")
                add_finding(correlated_intel_list, "intelligence_items",
                            {"type": "Correlated Risk: Exposed Emails & Weak Mail Security", "description": f"Email addresses ({len(emails_on_page_list)} found, e.g., {emails_on_page_list[0]}) are exposed on the website, AND the domain has weak email security policies ({', '.join(issue_summary)}). This increases the risk of phishing attacks targeting these emails and successful email spoofing against the domain.",
                             "severity": "Medium", "confidence":"Medium", "details": {"exposed_emails_sample": emails_on_page_list[:3], "mail_security_issues": issue_summary},
                             "recommendation": "Strengthen SPF and DMARC records for the domain. Consider reducing the exposure of direct email addresses on the website (e.g., use contact forms) if spam/phishing is a concern."},
                            log_message=f"Correlated: Exposed emails on page and weak mail security ({', '.join(issue_summary)}) found.", severity_for_log="MEDIUM")

        # Rule 10: Web Server Software Identified + Exposed Non-Web Port
        # This implies that a standard web server is running, but other non-HTTP/S ports are also open,
        # potentially increasing attack surface if those services are also managed by or related to the web server stack.
        if open_ports_list and self.results["technology_fingerprint"].get("server_software"):
            generic_servers = ["Apache", "Nginx", "IIS", "LiteSpeed", "Tomcat", "Jetty", "GlassFish", "WebLogic", "WebSphere"] # Common web servers
            for port_info in open_ports_list:
                if isinstance(port_info, dict) and port_info.get("port") not in [80, 443, None, "Skipped", "Error"]: # Non-standard web port
                    for server_sw in self.results["technology_fingerprint"]["server_software"]:
                        if any(gs.lower() in server_sw.lower() for gs in generic_servers): # Check if a known web server is running
                            add_finding(correlated_intel_list, "intelligence_items",
                                        {"type": "Correlated Observation: Web Server Software & Exposed Non-Web Port", "description": f"A common web server software ({server_sw}) is identified, and a non-standard port ({port_info['port']}/tcp - Service: {port_info.get('service_name', 'unknown')}) is open. This port might host an additional service unrelated to the main web application, potentially increasing the attack surface.",
                                         "severity": "Low", "confidence":"Low", "details": {"web_server": server_sw, "exposed_port": port_info['port'], "service_on_port": port_info.get('service_name', 'unknown')},
                                         "recommendation": f"Verify the purpose of the service on port {port_info['port']}. If it's part of the web server stack (e.g., a management interface) or another essential service, ensure it's secured. If unnecessary, close the port or restrict access."},
                                        log_message=f"Correlated: Web server {server_sw} and open non-web port {port_info['port']}", severity_for_log="LOW")
                            break # Found a correlation for this port, move to next port

        if not correlated_intel_list:
            logger.info("No specific cross-module correlations identified in this scan run.")
        else:
            logger.info(f"Identified {len(correlated_intel_list)} correlated intelligence items.")

    def _format_html_value(self, value, depth=0): # Enhanced HTML formatting
        if value is None: return "<em>N/A</em>"
        if isinstance(value, bool): return "<strong>Yes</strong>" if value else "No"

        if isinstance(value, list):
            if not value: return "<em>None found.</em>"
            # Simple list of strings/numbers
            if all(isinstance(i, (str, int, float, bool, type(None))) for i in value) and len(value) < 10 and sum(len(str(i)) for i in value if i is not None) < 250:
                return ", ".join(html.escape(str(i)) for i in value if i is not None)

            items_html = ""
            if value and isinstance(value[0], dict): # List of dictionaries (likely findings or complex data)
                # Heuristic to detect if it's a list of findings-like objects
                is_findings_list = ('severity' in value[0] and ('description' in value[0] or 'type' in value[0])) or \
                                   ('type' in value[0] and 'description' in value[0] and 'recommendation' in value[0]) or \
                                   ('cve_id' in value[0] and 'description_summary' in value[0]) # For NVD CVEs
                is_ai_insight = is_findings_list and value[0].get("type", "").startswith("AI-Powered Insight")
                is_ai_explanation_related = is_findings_list and value[0].get("type", "").startswith("AI-Powered Finding Explanation")

                if is_findings_list:
                    for item_dict in value:
                        sev = item_dict.get('severity', item_dict.get('baseSeverity', 'UNKNOWN')).upper() # Handle NVD severity
                        conf = item_dict.get('confidence', 'N/A')
                        item_type = html.escape(item_dict.get('type', item_dict.get('cve_id', 'Finding'))) # Use CVE ID if type is missing
                        desc = html.escape(item_dict.get('description', item_dict.get('description_summary', 'N/A'))) # Use NVD desc if main desc missing
                        recomm = html.escape(item_dict.get('recommendation', ''))
                        target_url_val = item_dict.get('target_url')
                        details_val = item_dict.get('details')
                        ai_explanation_val = item_dict.get('ai_explanation') # Get AI explanation if present

                        items_html += f"<li><span class='severity-{sev}'>[{sev}]</span> <strong>{item_type}</strong> (Confidence: {conf}): {desc}"
                        if target_url_val: items_html += f"<br><small>Target: {self._format_html_value(target_url_val, depth + 1)}</small>"
                        if recomm: items_html += f"<br><em>Recommendation:</em> <small>{recomm}</small>"

                        if details_val:
                            if is_ai_insight and "full_ai_response" in details_val:
                                items_html += f"<br><em>Details:</em> <pre>{html.escape(str(details_val['full_ai_response']))}</pre>"
                                if "prompt_sent_preview" in details_val:
                                     items_html += f"<br><em>AI Prompt Preview:</em> <pre style='font-size:0.8em; color:#aaa;'>{html.escape(str(details_val['prompt_sent_preview']))}</pre>"
                            elif is_ai_explanation_related and "ai_explanation" in details_val:
                                items_html += f"<br><em>AI Explanation:</em> <pre>{html.escape(str(details_val['ai_explanation']))}</pre>"
                            else:
                                items_html += "<br><em>Details:</em>" + self._format_html_value(details_val, depth + 1)

                        if ai_explanation_val and isinstance(ai_explanation_val, dict) and ai_explanation_val.get('explanation'): # Display top-level AI explanation
                            items_html += f"<br><em>AI Explanation ({html.escape(ai_explanation_val.get('llm_provider','LLM'))}):</em> <pre style='background-color: #e6f7ff; border-left: 3px solid #007bff; padding: 8px; margin-top:5px;'>{html.escape(ai_explanation_val['explanation'])}</pre>"

                        items_html += "</li>"
                    return f"<ul class='findings-list'>{items_html}</ul>"
                # Specific formatting for API path summaries
                elif 'path' in value[0] and 'methods' in value[0] and isinstance(value[0]['methods'], list): # Likely API path list
                    api_paths_html = "<ul class='api-paths-list'>"
                    for api_path_data in value[:15]: # Limit displayed paths for brevity
                        api_paths_html += f"<li><strong>Path:</strong> <code class='code-inline'>{html.escape(api_path_data['path'])}</code>"
                        if api_path_data['methods']:
                            api_paths_html += "<ul>"
                            for method_data in api_path_data['methods']:
                                api_paths_html += f"<li><strong>Method:</strong> {html.escape(method_data['method'])} "
                                if method_data.get('summary'): api_paths_html += f"- <em>{html.escape(method_data['summary'])}</em>"
                                if method_data.get('parameters_count', 0) > 0 : api_paths_html += f" <small>({method_data['parameters_count']} params)</small>"
                                if method_data.get('security_schemes_applied'): api_paths_html += "<br><small>Security Schemes: " + html.escape(str(method_data['security_schemes_applied'])) + "</small>"
                                api_paths_html += "</li>"
                            api_paths_html += "</ul>"
                        api_paths_html += "</li>"
                    if len(value) > 15: api_paths_html += f"<li>... and {len(value) - 15} more paths.</li>"
                    api_paths_html += "</ul>"; return api_paths_html
                else: # Generic list of dictionaries
                    return "<ul class='list-of-dicts'>" + "".join(f"<li>{self._format_html_value(i, depth + 1)}</li>" for i in value) + "</ul>"
            else: # Simple list of items
                return "<ul>" + "".join(f"<li>{self._format_html_value(i, depth + 1)}</li>" for i in value) + "</ul>"

        if isinstance(value, dict):
                if not value: return "<em>N/A</em>"
                # Vulnerability search links
                if all(k_cve in value and isinstance(value[k_cve], str) and value[k_cve].startswith("http") for k_cve in ["Vulners", "CVE Mitre", "NIST NVD"]):
                    return " | ".join([f"<a href='{html.escape(value[k_cve_link])}' target='_blank' rel='noopener noreferrer'>Search {k_cve_link.replace('_',' ').title()}</a>" for k_cve_link in value if value.get(k_cve_link)])
                # Wildcard DNS analysis
                if "detected" in value and "evidence" in value and "probed_subdomains_details" in value: # Specific to wildcard_dns_analysis
                    tbl_wc_html = f"<p><strong>Detected:</strong> {value['detected']}<br><strong>Evidence:</strong> {html.escape(str(value['evidence']))}</p>"
                    if value.get("probed_subdomains_details"):
                        tbl_wc_html += "<table class='nested-table'><thead><tr><th>Probed Subdomain</th><th>Resolved IPs</th><th>HTTP Status</th><th>Content Hash Prefix</th><th>Resolution Status</th></tr></thead><tbody>"
                        for probe_item_wc in value["probed_subdomains_details"]:
                            tbl_wc_html += f"<tr><td>{html.escape(probe_item_wc.get('subdomain','N/A'))}</td><td>{', '.join(probe_item_wc.get('resolved_ips',[]))}</td><td>{probe_item_wc.get('http_status','N/A')}</td><td>{probe_item_wc.get('content_hash_prefix','N/A')}</td><td>{html.escape(str(probe_item_wc.get('resolution_status','N/A')))}</td></tr>"
                        tbl_wc_html += "</tbody></table>"
                    if "http_responses_summary" in value and value["http_responses_summary"]:
                        tbl_wc_html += "<p><small>HTTP Probe Summary: " + "; ".join(html.escape(str(s_http_item)) for s_http_item in value['http_responses_summary'][:3]) + ("..." if len(value['http_responses_summary'])>3 else "") + "</small></p>"
                    return tbl_wc_html
                # VirusTotal summary
                if "attributes" in value and "last_analysis_stats" in value["attributes"]: # VirusTotal report structure
                    stats = value["attributes"]["last_analysis_stats"]
                    harmless = stats.get("harmless", 0); malicious = stats.get("malicious", 0); suspicious = stats.get("suspicious", 0); undetected = stats.get("undetected", 0)
                    total_engines = harmless + malicious + suspicious + undetected
                    score_color = "green"
                    if malicious > 0: score_color = "red"
                    elif suspicious > 0: score_color = "orange"
                    vt_link_type = value.get('type','domain') # domain, ip, url
                    vt_link_id = value.get('id', '#') # actual domain, IP, or URL hash
                    vt_link = f"https://www.virustotal.com/gui/{vt_link_type}/{vt_link_id}/detection"
                    return f"<p><strong>VirusTotal Score:</strong> <span style='color:{score_color}; font-weight:bold;'>{malicious}/{total_engines} Malicious</span> ({suspicious} Suspicious)<br><a href='{vt_link}' target='_blank'>Full Report on VirusTotal</a></p>"

                # Generic dictionary formatting
                table_class_html = "nested-table" if depth > 0 else "default-table"
                table_html_content = f"<table class='{table_class_html}'><tbody>"
                for k_dict, v_dict in value.items():
                    table_html_content += f"<tr><th>{html.escape(str(k_dict).replace('_', ' ').title())}</th><td>{self._format_html_value(v_dict, depth + 1)}</td></tr>"
                table_html_content += "</tbody></table>"; return table_html_content

        # Simple string value
        escaped_str_val = html.escape(str(value))
        if isinstance(value, str) and (value.startswith("http:") or value.startswith("https://")):
            return f"<a href='{escaped_str_val}' target='_blank' rel='noopener noreferrer'>{escaped_str_val}</a>"
        if isinstance(value, str) and ("\n" in value or len(value) > 120): # Use <pre> for multiline or long strings
            return f"<pre>{escaped_str_val}</pre>"
        return escaped_str_val

    def generate_html_report(self) -> str:
        meta = self.results["scan_metadata"]
        duration_str = "N/A"
        if meta.get('start_time') and meta.get('end_time'):
            try:
                start_dt = datetime.fromisoformat(str(meta['start_time']).replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(str(meta['end_time']).replace("Z", "+00:00"))
                secs_total = (end_dt - start_dt).total_seconds()
                hours, remainder_secs = divmod(secs_total, 3600)
                minutes, seconds_val = divmod(remainder_secs, 60)
                if hours > 0: duration_str = f"{int(hours)}h {int(minutes)}m {seconds_val:.2f}s"
                elif minutes > 0: duration_str = f"{int(minutes)}m {seconds_val:.2f}s"
                else: duration_str = f"{seconds_val:.2f}s"
            except Exception as e_dur_calc: logger.error(f"Error calculating scan duration: {e_dur_calc}"); duration_str = "Error calculating"

        ai_summary_finding = next((f for f in self.results.get("correlated_intelligence", []) if f.get("type") == "AI-Powered Insight & Summary"), None)
        ai_recommendations_html = ""
        if ai_summary_finding and ai_summary_finding.get("details", {}).get("full_ai_response"):
            full_ai_response = ai_summary_finding["details"]["full_ai_response"]
            # Try to extract a "Key Recommendations" or "Actionable Insights" section
            insights_match = re.search(r"(Prioritized Actionable Insights|Key Recommendations|Next Steps):?\s*\n((?:[ \t]*[\*\-\•\d]\.?\s+.*(?:\n|$))+)", full_ai_response, re.IGNORECASE | re.MULTILINE)
            if insights_match:
                ai_recommendations_html = "<ul>"
                for line in insights_match.group(2).strip().splitlines():
                     if line.strip(): ai_recommendations_html += f"<li>{html.escape(line.strip(' *-•').strip())}</li>"
                ai_recommendations_html += "</ul>"
            # Fallback if specific section not found, show first few lines as summary
            elif not insights_match:
                summary_lines = full_ai_response.strip().splitlines()
                ai_recommendations_html = "<p>" + "<br>".join(html.escape(line) for line in summary_lines[:5]) + ("..." if len(summary_lines)>5 else "") + "</p>"


        report_html_content = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>KAIROS Report: {html.escape(meta['target_input'])}</title><style>
            body {{ font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0; background-color: #eef2f7; color: #333a45; line-height: 1.65; font-size: 16px; }}
            .container {{ max-width: 1320px; margin: 20px auto; background-color: #ffffff; padding: 25px 35px; box-shadow: 0 5px 20px rgba(0,0,0,0.08); border-radius: 12px; }}
            h1 {{ color: #2c3e50; text-align: center; border-bottom: 5px solid #3498db; padding-bottom: 20px; margin-bottom:35px; font-size: 2.6em; font-weight: 600; letter-spacing: -1px; }}
            h1 .kairos-k {{ color: #e74c3c; }}
            h2 {{ color: #2980b9; border-bottom: 3px solid #ecf0f1; padding-bottom: 12px; margin-top: 45px; font-size: 1.9em; cursor: pointer; position: relative; font-weight: 500; }}
            h2::after {{ content: ' ▼'; font-size: 0.65em; position: absolute; right: 15px; top: 50%; transform: translateY(-50%); transition: transform 0.25s ease-in-out; color: #7f8c8d; }}
            h2.collapsed::after {{ transform: translateY(-50%) rotate(-90deg); }}
            h3 {{ color: #34495e; font-size: 1.4em; margin-top: 25px; margin-bottom: 10px; font-weight:500; }}
            .section-content {{ display: block; padding-left: 25px; border-left: 5px solid #bdc3c7; margin-top:15px; background-color: #fdfefe; padding:18px; border-radius:0 8px 8px 0; box-shadow: inset 0 2px 4px rgba(0,0,0,0.03); }}
            .section-content.collapsed {{ display: none; }}
            table.default-table, table.nested-table {{ width: 100%; border-collapse: separate; border-spacing: 0; margin-bottom: 28px; table-layout: auto; border: 1px solid #e1e8ed; border-radius: 8px; overflow: hidden; font-size: 0.95em; }}
            th, td {{ padding: 15px 20px; border-bottom: 1px solid #e1e8ed; text-align: left; vertical-align: top; word-wrap: break-word; }}
            th {{ background-color: #f5f7fa; font-weight: 600; color: #4a5568; text-transform: uppercase; font-size:0.9em; letter-spacing: 0.5px; }}
            td:first-child {{ font-weight: 500; color: #2d3748; min-width: 180px; }}
            tr:last-child td {{ border-bottom: none; }}
            .nested-table th {{ background-color: #e9ecef; }} .nested-table td, .nested-table th {{ font-size:0.9em; padding:10px 15px; }}
            ul {{ padding-left: 30px; margin-top:10px; margin-bottom:15px; list-style-type: disc; }}
            li {{ margin-bottom: 8px; }}
            ul.findings-list, ul.api-paths-list {{ list-style-type: none; padding-left: 0; }}
            ul.findings-list li, ul.api-paths-list li {{ list-style-type: none; padding-left: 15px; border-left: 4px solid #76c7c0; margin-bottom:15px; padding-bottom: 10px; background-color: #f8f9f9; padding: 10px 15px; border-radius: 4px; }}
            ul.api-paths-list ul li {{ background-color: #eef2f7; border-left-color: #aed6f1;}}
            pre {{ background-color: #2c3e50; color: #ecf0f1; padding: 16px; border-radius: 6px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; border: 1px solid #34495e; max-height: 400px; overflow-y: auto; font-family: 'Consolas', 'Monaco', monospace; }}
            code.code-inline {{ background-color: #ecf0f1; padding: 2px 5px; border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; color: #c0392b; font-size: 0.9em; }}
            a {{ color: #2980b9; text-decoration: none; font-weight: 500; }}
            a:hover {{ text-decoration: underline; color: #1f618d; }}
            .severity-CRITICAL {{ color: #c0392b; font-weight: bold; }} .severity-HIGH {{ color: #e74c3c; font-weight: bold; }}
            .severity-MEDIUM {{ color: #f39c12; }} .severity-LOW {{ color: #3498db; }} .severity-INFO {{ color: #27ae60; }} .severity-UNKNOWN {{ color: #7f8c8d; }}
            .scan-summary-box, .key-recommendations-box {{ border: 1px solid #aed6f1; padding: 28px; margin-bottom:40px; border-radius: 10px; background-color: #f4faff; }}
            .scan-summary-box h3, .key-recommendations-box h3 {{ margin-top:0; color: #1a5276; font-size:1.6em; border-bottom:2px solid #aed6f1; padding-bottom:12px; cursor: pointer; position: relative;}}
            .scan-summary-box h3::after, .key-recommendations-box h3::after {{ content: ' ▼'; font-size: 0.65em; position: absolute; right: 10px; top: 50%; transform: translateY(-50%); }}
            .scan-summary-box h3.collapsed::after, .key-recommendations-box h3.collapsed::after {{ transform: translateY(-50%) rotate(-90deg); }}
            .toc {{ margin-bottom: 40px; border: 1px solid #d1d5db; padding: 22px; background-color: #f9fafb; border-radius: 8px; }}
            .toc h3 {{ margin-top:0; color: #374151; }}
            .toc ul {{ list-style-type: none; padding-left: 0; columns: 2; -webkit-columns: 2; -moz-columns: 2; column-gap: 30px; }}
            .toc li a {{ display: block; padding: 5px 0; color: #4b5563; }} .toc li a:hover {{ color: #1f2937; }}
            .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e1e8ed; font-size: 0.9em; color: #707B7C; }}
        </style><script>
            function toggleSection(headerElement) {{
                headerElement.classList.toggle('collapsed');
                const content = headerElement.nextElementSibling;
                if (content && (content.classList.contains('section-content') || (headerElement.parentElement.classList.contains('scan-summary-box') && content.tagName === 'TABLE') || (headerElement.parentElement.classList.contains('key-recommendations-box') && content.tagName === 'DIV'))) {{
                    content.classList.toggle('collapsed');
                }}
            }}
            document.addEventListener('DOMContentLoaded', () => {{
                "use strict";
                document.querySelectorAll('h2, .scan-summary-box h3, .key-recommendations-box h3').forEach(header => {{
                    header.classList.add('collapsed'); // Collapse all by default
                    const content = header.nextElementSibling;
                    if (content && (content.classList.contains('section-content') || (header.parentElement.classList.contains('scan-summary-box') && content.tagName === 'TABLE') || (header.parentElement.classList.contains('key-recommendations-box') && content.tagName === 'DIV') )) {{
                         content.classList.add('collapsed');
                    }}
                    header.onclick = () => toggleSection(header);
                }});
                // Auto-expand certain important sections
                const summaryBoxH3 = document.querySelector('.scan-summary-box h3');
                if (summaryBoxH3) {{ toggleSection(summaryBoxH3); }} // Expand summary
                const recommendationsBoxH3 = document.querySelector('.key-recommendations-box h3');
                if (recommendationsBoxH3) {{ toggleSection(recommendationsBoxH3); }} // Expand AI recommendations
                const criticalHighHeader = document.getElementById('vuln_summary_critical_high');
                if(criticalHighHeader) {{ toggleSection(criticalHighHeader); }} // Expand Critical/High
                const correlatedIntelHeader = document.getElementById('correlated_intelligence');
                if(correlatedIntelHeader) {{ toggleSection(correlatedIntelHeader); }} // Expand Correlated

                // Build TOC
                const tocList = document.getElementById('toc-list');
                let tocHtml = '';
                const summaryBox = document.querySelector('.scan-summary-box'); // Main Summary
                if (summaryBox && summaryBox.id) {{ tocHtml += `<li><a href="#${{summaryBox.id}}">Scan Summary</a></li>`; }}
                if (recommendationsBoxH3 && recommendationsBoxH3.parentElement.id) {{ tocHtml += `<li><a href="#${{recommendationsBoxH3.parentElement.id}}">Key Recommendations (AI)</a></li>`; }}
                if(criticalHighHeader && criticalHighHeader.id) {{ tocHtml += `<li><a href="#${{criticalHighHeader.id}}">${{criticalHighHeader.textContent.split("(")[0].trim()}}</a></li>`; }}
                if(correlatedIntelHeader && correlatedIntelHeader.id) {{ tocHtml += `<li><a href="#${{correlatedIntelHeader.id}}">${{correlatedIntelHeader.textContent.split("(")[0].trim()}}</a></li>`; }}
                document.querySelectorAll('h2').forEach(h => {{ // All other H2 sections
                    if(h.id && h.textContent && h.id !== 'vuln_summary_critical_high' && h.id !== 'correlated_intelligence') {{ // Avoid duplicates
                        tocHtml += `<li><a href="#${{h.id}}">${{h.textContent.split("(")[0].trim()}}</a></li>`;
                    }}
                }});
                if (tocList) {{ tocList.innerHTML = tocHtml; }}
            }});
        </script></head><body><div class="container">
        <h1><span class="kairos-k">K</span>AIROS Reconnaissance Report</h1>
        <div class="scan-summary-box" id="scan_summary_main">
            <h3>Scan Summary</h3>
            <table><tbody>
                <tr><th>Target Input</th><td>{html.escape(meta['target_input'])}</td></tr>
                <tr><th>Normalized Target</th><td>{self._format_html_value(meta['target_normalized'])}</td></tr>
                <tr><th>Effective Domain</th><td>{self._format_html_value(meta.get('effective_domain', 'N/A'))}</td></tr>
                <tr><th>Scan Started (UTC)</th><td>{html.escape(str(meta.get('start_time', 'N/A')))}</td></tr>
                <tr><th>Scan Ended (UTC)</th><td>{html.escape(str(meta.get('end_time', 'N/A')))}</td></tr>
                <tr><th>Scan Duration</th><td>{html.escape(duration_str)}</td></tr>
                <tr><th>Scanner Version</th><td>{html.escape(meta['scanner_version'])}</td></tr>
            </tbody></table>
        </div>
        """
        if ai_recommendations_html:
            report_html_content += f"""
            <div class="key-recommendations-box" id="key_recommendations_ai">
                <h3>Key Recommendations (AI Generated)</h3>
                <div>{ai_recommendations_html}</div>
            </div>
            """

        report_html_content += """
        <div class="toc"><h3>Table of Contents</h3><ul id="toc-list"></ul></div>
        """

        vuln_findings_all_list = self.results["security_posture"].get("vulnerability_findings", [])
        critical_high_vulns_html_list = [v for v in vuln_findings_all_list if isinstance(v, dict) and v.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
        if critical_high_vulns_html_list:
            report_html_content += f"<h2 id='vuln_summary_critical_high'>Critical/High Severity Findings ({len(critical_high_vulns_html_list)})</h2><div class='section-content'>{self._format_html_value(critical_high_vulns_html_list)}</div>"

        correlated_intel_html_list = [item for item in self.results.get("correlated_intelligence", []) if item.get("type") != "AI-Powered Insight & Summary"] # Exclude the main AI summary from this list
        if correlated_intel_html_list:
             report_html_content += f"<h2 id='correlated_intelligence'>Correlated Intelligence & Insights ({len(correlated_intel_html_list)})</h2><div class='section-content'>{self._format_html_value(correlated_intel_html_list)}</div>"

        sections_order_display_html = [("general_info", "General Information"), ("http_details", "HTTP Details"), ("dns_information", "DNS Information"), ("technology_fingerprint", "Technology Fingerprint"), ("content_analysis", "Content Analysis"), ("security_posture", "Full Security Posture Details"), ("subdomain_discovery", "Subdomain Discovery"), ("cms_specific_findings", "CMS Specific Findings")]

        for key_id_html, title_display_html in sections_order_display_html:
            data_for_section_html = self.results.get(key_id_html)
            section_id_attr_html = key_id_html.lower().replace(' ', '_')

            if key_id_html == "security_posture" and data_for_section_html:
                all_findings_for_sec_posture = data_for_section_html.get('vulnerability_findings', [])
                num_total_findings_html = len(all_findings_for_sec_posture)
                report_html_content += f"<h2 id='{section_id_attr_html}'>{title_display_html} ({num_total_findings_html} total findings logged)</h2><div class='section-content'>"
                other_sec_posture_items_html = {k_item_html: v_item_html for k_item_html, v_item_html in data_for_section_html.items() if k_item_html != "vulnerability_findings"}
                if other_sec_posture_items_html: report_html_content += self._format_html_value(other_sec_posture_items_html)
                if num_total_findings_html > 0:
                    severity_order_map_html = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
                    valid_vulns_for_sort_html = [v_html for v_html in all_findings_for_sec_posture if isinstance(v_html, dict)]
                    all_vulns_sorted_html = sorted(valid_vulns_for_sort_html, key=lambda x_item_html: severity_order_map_html.get(x_item_html.get("severity", "UNKNOWN").upper(), 5))
                    report_html_content += "<h3>All Identified Findings & Observations (Security Posture)</h3>"
                    report_html_content += self._format_html_value(all_vulns_sorted_html)
                report_html_content += "</div>"; continue

            is_cms_section_with_data_html = (key_id_html == "cms_specific_findings" and isinstance(data_for_section_html, dict) and any(data_for_section_html.values()))
            if not data_for_section_html and not is_cms_section_with_data_html:
                if key_id_html not in ["cms_specific_findings"]: continue # Only skip if not CMS section and empty

            count_str_display_html = ""
            if isinstance(data_for_section_html, list) and data_for_section_html: count_str_display_html = f" ({len(data_for_section_html)})"
            elif isinstance(data_for_section_html, dict):
                if 'discovered_subdomains' in data_for_section_html and isinstance(data_for_section_html['discovered_subdomains'], list):
                    actual_sub_count = len([s for s in data_for_section_html['discovered_subdomains'] if isinstance(s,dict) and 'subdomain' in s])
                    if actual_sub_count > 0: count_str_display_html = f" ({actual_sub_count} discovered)"
                elif key_id_html == "cms_specific_findings" and data_for_section_html:
                    total_cms_items_count_html = sum(len(cms_data.get('vulnerabilities_info', [])) + len(cms_data.get('observations', [])) for cms_data in data_for_section_html.values() if isinstance(cms_data, dict))
                    if total_cms_items_count_html > 0: count_str_display_html = f" ({total_cms_items_count_html} items)"

            report_html_content += f"<h2 id='{section_id_attr_html}'>{title_display_html}{count_str_display_html}</h2><div class='section-content'>"
            if not data_for_section_html and not is_cms_section_with_data_html: report_html_content += "<p><em>No data available for this section.</em></p>"
            elif key_id_html == "cms_specific_findings" and not is_cms_section_with_data_html: report_html_content += "<p><em>No CMS identified or no specific findings for identified CMS.</em></p>"
            else: report_html_content += self._format_html_value(data_for_section_html)
            report_html_content += "</div>"

        report_html_content += f"""
            <div class="footer">
                <p>KAIROS v{html.escape(meta['scanner_version'])} - Report Generated: {html.escape(datetime.now(timezone.utc).isoformat(timespec='seconds'))} UTC</p>
                <p><em>Disclaimer: This report is for ETHICAL and EDUCATIONAL purposes only. Use responsibly and with explicit permission.</em></p>
            </div></div></body></html>"""
        return report_html_content

    def generate_text_report(self) -> str:
        report_lines = []
        meta = self.results["scan_metadata"]
        report_lines.append(f"===== KAIROS Report for: {meta['target_input']} =====")
        report_lines.append(f"Normalized Target: {meta['target_normalized']}")
        report_lines.append(f"Effective Domain: {meta.get('effective_domain', 'N/A')}")
        report_lines.append(f"Scan Started (UTC): {meta.get('start_time', 'N/A')}")
        report_lines.append(f"Scan Ended (UTC): {meta.get('end_time', 'N/A')}")
        if meta.get('start_time') and meta.get('end_time'):
            try:
                start_dt_txt = datetime.fromisoformat(str(meta['start_time']).replace("Z", "+00:00"))
                end_dt_txt = datetime.fromisoformat(str(meta['end_time']).replace("Z", "+00:00"))
                secs_txt_total = (end_dt_txt - start_dt_txt).total_seconds()
                h_txt, rem_secs_txt = divmod(secs_txt_total, 3600)
                m_txt, s_val_txt = divmod(rem_secs_txt, 60)
                duration_str_txt = f"{int(h_txt)}h {int(m_txt)}m {s_val_txt:.2f}s" if h_txt > 0 else (f"{int(m_txt)}m {s_val_txt:.2f}s" if m_txt > 0 else f"{s_val_txt:.2f}s")
                report_lines.append(f"Scan Duration: {duration_str_txt}")
            except Exception as e_dur_txt: logger.debug(f"Error calculating duration for text report: {e_dur_txt}")
        report_lines.append(f"Scanner Version: {meta['scanner_version']}\n")

        vuln_findings_all_txt = self.results["security_posture"].get("vulnerability_findings", [])
        critical_high_vulns_txt_list = [v_txt for v_txt in vuln_findings_all_txt if isinstance(v_txt, dict) and v_txt.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
        if critical_high_vulns_txt_list:
            report_lines.append("\n--- Critical/High Severity Findings Summary ---")
            for vuln_item_txt_sum in critical_high_vulns_txt_list:
                report_lines.append(f"  - [{vuln_item_txt_sum['severity'].upper()}] {html.unescape(vuln_item_txt_sum.get('type', 'N/A'))}: {html.unescape(vuln_item_txt_sum.get('description', 'N/A'))} (Confidence: {vuln_item_txt_sum.get('confidence', 'N/A')})")
                if 'target_url' in vuln_item_txt_sum and vuln_item_txt_sum['target_url']: report_lines.append(f"    Target: {vuln_item_txt_sum['target_url']}")
                if 'recommendation' in vuln_item_txt_sum and vuln_item_txt_sum['recommendation']: report_lines.append(f"    Recommendation: {html.unescape(str(vuln_item_txt_sum['recommendation']))}")
                if 'ai_explanation' in vuln_item_txt_sum and isinstance(vuln_item_txt_sum['ai_explanation'], dict) and vuln_item_txt_sum['ai_explanation'].get('explanation'):
                    report_lines.append(f"    AI Explanation ({vuln_item_txt_sum['ai_explanation'].get('llm_provider','LLM')}): {html.unescape(str(vuln_item_txt_sum['ai_explanation']['explanation']))[:250]}...")
            report_lines.append("\n")

        correlated_intel_txt_list = self.results.get("correlated_intelligence", [])
        if correlated_intel_txt_list:
            report_lines.append("\n--- Correlated Intelligence & Insights ---")
            for intel_item_txt_corr in correlated_intel_txt_list:
                 report_lines.append(f"  - [{intel_item_txt_corr.get('severity','INFO').upper()}] {html.unescape(intel_item_txt_corr.get('type', 'N/A'))}: {html.unescape(intel_item_txt_corr.get('description', 'N/A'))} (Confidence: {intel_item_txt_corr.get('confidence', 'N/A')})")
                 if 'recommendation' in intel_item_txt_corr and intel_item_txt_corr['recommendation']: report_lines.append(f"    Recommendation: {html.unescape(str(intel_item_txt_corr['recommendation']))}")
                 # Add AI summary text if it's that type of correlated finding
                 if intel_item_txt_corr.get("type") == "AI-Powered Insight & Summary" and intel_item_txt_corr.get("details",{}).get("full_ai_response"):
                     report_lines.append(f"    AI Summary ({intel_item_txt_corr['details'].get('source_llm','LLM')}):\n      {html.unescape(str(intel_item_txt_corr['details']['full_ai_response'])).replace(chr(10), chr(10) + '      ')}") # Indent multiline
            report_lines.append("\n")

        sections_to_format_txt = [("General Information", self.results["general_info"]), ("HTTP Details", self.results["http_details"]), ("DNS Information", self.results["dns_information"]), ("Technology Fingerprint", self.results["technology_fingerprint"]), ("Content Analysis", self.results["content_analysis"]), ("Security Posture", self.results["security_posture"]), ("Subdomain Discovery", self.results["subdomain_discovery"])]
        for title_txt, data_val_txt in sections_to_format_txt: report_lines.append(format_report_section(title_txt, data_val_txt))
        if self.results["cms_specific_findings"] and any(self.results["cms_specific_findings"].values()):
            report_lines.append(format_report_section("CMS Specific Findings", self.results["cms_specific_findings"]))
        report_lines.append("\n===== End of KAIROS Report =====")
        return "\n".join(report_lines)

    def save_reports(self, directory: str, formats: list[str] | str = "all"):
        if not os.path.exists(directory):
            try: os.makedirs(directory, exist_ok=True); logger.info(f"Created report directory: {directory}")
            except OSError as e_dir_create: logger.error(f"Could not create report directory {directory}: {e_dir_create}. Saving to current directory instead."); directory = "."

        safe_domain_name_report = re.sub(r'[^\w\-_\.]', '_', self.results["scan_metadata"].get("effective_domain", self.domain) or "unknown_domain")
        utc_timestamp_str_report = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_filename_path_report = os.path.join(directory, f"kairos_scan_{safe_domain_name_report}_{utc_timestamp_str_report}")

        if isinstance(formats, str): formats = [formats.lower()]
        if "all" in formats: formats = ["json", "txt", "html"]

        class KairosJsonEncoder(json.JSONEncoder):
            def default(self, obj_to_encode):
                if isinstance(obj_to_encode, datetime): return obj_to_encode.isoformat()
                if isinstance(obj_to_encode, set): return list(obj_to_encode)
                try: return json.JSONEncoder.default(self, obj_to_encode)
                except TypeError: return str(obj_to_encode) # Fallback for unhandled types

        if "json" in formats:
            json_file_path_report = f"{base_filename_path_report}.json"
            try:
                with open(json_file_path_report, 'w', encoding='utf-8') as f_json_report: json.dump(self.results, f_json_report, indent=2, ensure_ascii=False, cls=KairosJsonEncoder)
                logger.info(f"JSON report saved to: {json_file_path_report}")
            except Exception as e_json_save_report: logger.error(f"Failed to save JSON report to {json_file_path_report}: {e_json_save_report}")
        if "txt" in formats:
            txt_file_path_report = f"{base_filename_path_report}.txt"
            try:
                with open(txt_file_path_report, 'w', encoding='utf-8') as f_txt_report: f_txt_report.write(self.generate_text_report())
                logger.info(f"Text report saved to: {txt_file_path_report}")
            except Exception as e_txt_save_report: logger.error(f"Failed to save text report to {txt_file_path_report}: {e_txt_save_report}")
        if "html" in formats:
            html_file_path_report = f"{base_filename_path_report}.html"
            try:
                with open(html_file_path_report, 'w', encoding='utf-8') as f_html_report: f_html_report.write(self.generate_html_report())
                logger.info(f"HTML report saved to: {html_file_path_report}")
            except Exception as e_html_save_report: logger.error(f"Failed to save HTML report to {html_file_path_report}: {e_html_save_report}", exc_info=True)

    async def _fetch_nvd_cves(self, software_name: str, version: str) -> list:
        nvd_config = self.config.get("nvd_api_config", {})
        base_url = nvd_config.get("base_url")
        api_key = self.config["external_api_keys"].get("nvd_api_key")
        delay_seconds = nvd_config.get("request_delay_seconds", 7) # Default to 7s for NVD
        results_per_page = nvd_config.get("results_per_page", 20) # NVD allows up to 2000, but smaller is fine for targeted queries
        cves_found = []

        if not base_url or not api_key or not REQUESTS_AVAILABLE:
            if not api_key: logger.debug(f"NVD API key not provided for {software_name} v{version}. Skipping CVE lookup.") # Changed to debug
            elif not REQUESTS_AVAILABLE: logger.warning(f"'requests' library not available. Skipping NVD CVE lookup for {software_name} v{version}.")
            return cves_found # Return empty list if prerequisites not met

        current_time = time.time()
        if current_time - self._last_nvd_api_call_time < delay_seconds:
            await asyncio.sleep(delay_seconds - (current_time - self._last_nvd_api_call_time))
        self._last_nvd_api_call_time = time.time()

        keyword_search = f"{software_name} {version}"
        params = {"keywordSearch": keyword_search, "keywordExactMatch": "", "resultsPerPage": results_per_page} # Use keywordExactMatch for version
        headers = {"apiKey": api_key}
        logger.info(f"Querying NVD for CVEs related to: {keyword_search}")
        self.results["security_posture"]["external_api_analysis_summary"]["nvd_checks_performed"] +=1

        try:
            response = await asyncio.to_thread(requests.get, base_url, params=params, headers=headers, timeout=20) # 20s timeout for NVD
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            if data.get("vulnerabilities"):
                for vuln_item in data["vulnerabilities"]:
                    cve_data = vuln_item.get("cve", {})
                    cve_id = cve_data.get("id")
                    descriptions = cve_data.get("descriptions", [])
                    description_summary = "N/A"
                    for desc in descriptions:
                        if desc.get("lang") == "en": description_summary = desc.get("value", "N/A"); break

                    base_severity = "Unknown"
                    # Prioritize CVSS v3.1 if available
                    cvss_metrics_v3_1 = cve_data.get("metrics", {}).get("cvssMetricV31", [])
                    if cvss_metrics_v3_1: base_severity = cvss_metrics_v3_1[0].get("cvssData", {}).get("baseSeverity", "Unknown")
                    else: # Fallback to CVSS v2
                        cvss_metrics_v2 = cve_data.get("metrics", {}).get("cvssMetricV2", [])
                        if cvss_metrics_v2: base_severity = cvss_metrics_v2[0].get("baseSeverity", "Unknown")

                    cves_found.append({
                        "cve_id": cve_id, "description_summary": description_summary,
                        "published_date": cve_data.get("published"), "last_modified_date": cve_data.get("lastModified"),
                        "baseSeverity": base_severity, "nvd_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
                logger.info(f"Found {len(cves_found)} CVEs for '{keyword_search}' from NVD.")
            else:
                logger.info(f"No CVEs found by NVD for '{keyword_search}'.")

        except requests.exceptions.HTTPError as e: logger.error(f"NVD API HTTP error for '{keyword_search}': {e.response.status_code} - {e.response.text[:200]}")
        except requests.exceptions.RequestException as e: logger.error(f"NVD API request error for '{keyword_search}': {e}")
        except json.JSONDecodeError: logger.error(f"NVD API returned non-JSON response for '{keyword_search}'.")
        return cves_found

    async def _fetch_virustotal_report(self, resource_id: str, resource_type: str = "domain") -> dict | None:
        vt_config = self.config.get("virustotal_api_config", {})
        base_url = vt_config.get("base_url")
        api_key = self.config["external_api_keys"].get("virustotal_api_key")
        delay_seconds = vt_config.get("request_delay_seconds", 16) # Default to 16s for VT (4 reqs/min for public API)
        report_data = None

        if not base_url or not api_key or not REQUESTS_AVAILABLE:
            if not api_key: logger.debug(f"VirusTotal API key not provided for {resource_type} report on '{resource_id}'. Skipping.") # Changed to debug
            elif not REQUESTS_AVAILABLE: logger.warning(f"'requests' library not available. Skipping VirusTotal {resource_type} report for '{resource_id}'.")
            return None

        current_time = time.time()
        if current_time - self._last_vt_api_call_time < delay_seconds:
            await asyncio.sleep(delay_seconds - (current_time - self._last_vt_api_call_time))
        self._last_vt_api_call_time = time.time()

        endpoint_map = {"domain": vt_config.get("domain_report_endpoint"), "ip": vt_config.get("ip_report_endpoint"), "url": vt_config.get("url_report_endpoint")}
        endpoint = endpoint_map.get(resource_type)
        if not endpoint: logger.error(f"Unsupported resource type for VirusTotal: {resource_type}"); return None

        url_display_id = resource_id
        if resource_type == "url": # URLs need to be SHA256 hashed for VT API v3 GET request
            resource_id = hashlib.sha256(resource_id.encode('utf-8')).hexdigest()
            url_display_id = "URL HASH" # Don't log the full URL, just that it's a hash

        url = f"{base_url}{endpoint}{resource_id}"
        headers = {"x-apikey": api_key}
        logger.info(f"Querying VirusTotal for {resource_type}: {url_display_id}")
        self.results["security_posture"]["external_api_analysis_summary"]["virustotal_checks_performed"] += 1

        try:
            response = await asyncio.to_thread(requests.get, url, headers=headers, timeout=30) # 30s timeout for VT
            response.raise_for_status()
            report_data = response.json().get("data") # The actual report is under 'data'
            if report_data:
                 last_analysis_stats = report_data.get("attributes", {}).get("last_analysis_stats", {})
                 malicious_count = last_analysis_stats.get("malicious", 0)
                 if malicious_count > 0:
                     self.results["security_posture"]["external_api_analysis_summary"]["virustotal_detections"] += 1
                     logger.warning(f"VirusTotal flagged {resource_type} '{url_display_id}' as malicious ({malicious_count} detections).")
                 else:
                     logger.info(f"VirusTotal: {resource_type} '{url_display_id}' appears clean ({malicious_count} detections).")
            else:
                logger.warning(f"No data in VirusTotal response for {resource_type} '{url_display_id}'.")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404: logger.info(f"VirusTotal: {resource_type} '{url_display_id}' not found in dataset.")
            else: logger.error(f"VirusTotal API HTTP error for {resource_type} '{url_display_id}': {e.response.status_code} - {e.response.text[:200]}")
        except requests.exceptions.RequestException as e: logger.error(f"VirusTotal API request error for {resource_type} '{url_display_id}': {e}")
        except json.JSONDecodeError: logger.error(f"VirusTotal API returned non-JSON response for {resource_type} '{url_display_id}'.")
        return report_data

    async def run_external_api_integrations(self):
        logger.info("--- Stage: External API Integrations ---")
        ext_api_config = self.config.get("enable_external_api_integrations", {})

        # VirusTotal for Domain
        if ext_api_config.get("virustotal") and self.results["scan_metadata"].get("effective_domain"):
            vt_domain_report = await self._fetch_virustotal_report(self.results["scan_metadata"]["effective_domain"], "domain")
            if vt_domain_report:
                self.results["general_info"]["domain_reputation_vt"] = vt_domain_report
        elif not ext_api_config.get("virustotal"):
            logger.info("VirusTotal integration for domain disabled in config.")


        # VirusTotal for IP Addresses (limit to first few IPs to manage API calls)
        if ext_api_config.get("virustotal") and self.results["general_info"]["ip_addresses"]:
            for ip_info_entry in self.results["general_info"]["ip_addresses"][:3]: # Check up to 3 IPs
                ip_addr_vt = ip_info_entry.get("ip")
                if ip_addr_vt:
                    vt_ip_report = await self._fetch_virustotal_report(ip_addr_vt, "ip")
                    if vt_ip_report:
                        ip_info_entry["virustotal_report"] = vt_ip_report
        elif not ext_api_config.get("virustotal") and self.results["general_info"]["ip_addresses"]:
             logger.info("VirusTotal integration for IPs disabled in config.")

        logger.info("External API Integrations stage complete (VirusTotal checks run, NVD is integrated elsewhere).")

    async def _query_llm_provider(self, provider_name: str, prompt: str, purpose: str = "summary") -> tuple[str | None, str | None]:
        provider_config_key = f"{provider_name}_api_config" # e.g., "openai_api_config"
        api_key_name = f"{provider_name}_api_key" # e.g., "openai_api_key"

        llm_config = self.config.get(provider_config_key, {})
        api_key = self.config["external_api_keys"].get(api_key_name)

        # Check library availability (OpenAI lib is used for both)
        if provider_name == "openai" and not OPENAI_AVAILABLE:
            logger.warning("OpenAI library not available. Cannot query OpenAI.")
            return None, None
        if provider_name == "deepseek" and not DEEPSEEK_CLIENT_AVAILABLE: # DeepSeek uses OpenAI client
            logger.warning("OpenAI library (for DeepSeek client) not available. Cannot query DeepSeek.")
            return None, None
        if not api_key:
            logger.warning(f"{provider_name.capitalize()} API key not configured. Skipping query.")
            self.results["security_posture"]["external_api_analysis_summary"].setdefault(provider_name, {})["status"] = "Skipped (API Key Missing)"
            return None, None

        model = llm_config.get("model")
        if not model:
            logger.warning(f"Model not configured for {provider_name.capitalize()}. Skipping query.")
            self.results["security_posture"]["external_api_analysis_summary"].setdefault(provider_name, {})["status"] = "Skipped (Model Not Configured)"
            return None, None

        max_tokens = llm_config.get(f"max_tokens_{purpose}", llm_config.get("max_tokens_summary", 800)) # purpose-specific or default
        temperature = llm_config.get("temperature", 0.3)
        api_timeout = llm_config.get("timeout_seconds", 90)
        request_delay = llm_config.get("request_delay_seconds", 3)
        base_url = llm_config.get("base_url") # Allow custom base URL for proxies or self-hosted models

        client_args = {"api_key": api_key, "timeout": api_timeout}
        if base_url: client_args["base_url"] = base_url # Pass base_url if configured
        client = openai.AsyncOpenAI(**client_args) # type: ignore

        prompt_preview_for_report = prompt[:1000] + ("..." if len(prompt) > 1000 else "") # For report brevity
        logger.info(f"Sending prompt to {provider_name.capitalize()} (Model: {model}, Purpose: {purpose}, Length: {len(prompt)} chars)...")
        self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "In Progress", "error": None}

        # Rate limiting for LLM calls
        current_time_llm = time.time()
        last_call_time_provider = self._last_llm_api_call_time.get(provider_name, 0)
        if current_time_llm - last_call_time_provider < request_delay:
            await asyncio.sleep(request_delay - (current_time_llm - last_call_time_provider))
        self._last_llm_api_call_time[provider_name] = time.time()

        try:
            completion = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity analyst assistant. Provide concise, professional, and actionable insights based on the KAIROS scan data provided."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                n=1, # Request one completion
                stop=None # No specific stop sequence
            )
            ai_response_text = completion.choices[0].message.content.strip() if completion.choices and completion.choices[0].message else ""

            logger.info(f"Response received from {provider_name.capitalize()} (Length: {len(ai_response_text)} chars).")
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name]["status"] = "Success"
            return ai_response_text, prompt_preview_for_report
        except openai.APIConnectionError as e:
            err_msg = f"{provider_name.capitalize()} API connection error: {e}"
            logger.error(err_msg)
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "Failed", "error": f"API Connection Error: {str(e)[:100]}"}
        except openai.RateLimitError as e:
            err_msg = f"{provider_name.capitalize()} API rate limit exceeded: {e}"
            logger.error(err_msg)
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "Failed", "error": f"Rate Limit Error: {str(e)[:100]}"}
        except openai.AuthenticationError as e:
            err_msg = f"{provider_name.capitalize()} API authentication error (check API key): {e}"
            logger.error(err_msg)
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "Failed", "error": f"Authentication Error: {str(e)[:100]}"}
        except openai.APIStatusError as e: # For non-200 responses
            err_msg = f"{provider_name.capitalize()} API status error: {e.status_code} - {e.response}"
            logger.error(err_msg)
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "Failed", "error": f"API Status Error {e.status_code}: {e.message[:100]}"}
        except Exception as e: # Catch-all for other OpenAI errors or unexpected issues
            err_msg = f"Unexpected error during {provider_name.capitalize()} call: {type(e).__name__} - {e}"
            logger.error(err_msg, exc_info=True)
            self.results["security_posture"]["external_api_analysis_summary"]["llm_analysis_status"][provider_name] = {"status": "Failed", "error": f"Unexpected Error: {type(e).__name__}"}
        return None, prompt_preview_for_report # Return prompt preview even on failure for debugging

    async def run_llm_analysis_tasks(self):
        llm_preference = self.config.get("llm_analysis_preference", ["openai", "deepseek"])
        llm_tasks_config = self.config.get("llm_analysis_tasks", {})

        # --- AI Summary Task ---
        llm_provider_used_summary = None; ai_summary_text = None; prompt_preview_summary = None
        summary_task_attempted = False
        for provider_name in llm_preference:
            if self.config["enable_external_api_integrations"].get(f"{provider_name}_analysis", False):
                summary_task_attempted = True
                logger.info(f"Attempting LLM summary with {provider_name.capitalize()}...")
                prompt_sections = [f"KAIROS Scan Report Summary for Target: {self.results['scan_metadata']['target_normalized']} (Effective Domain: {self.results['scan_metadata']['effective_domain']})"]
                key_findings_summary = []
                crit_high_vulns = [f" - Type: {v.get('type')}, Severity: {v.get('severity')}, Description: {str(v.get('description'))[:100]}..." for v in self.results["security_posture"].get("vulnerability_findings", []) if v.get("severity") in ["CRITICAL", "HIGH"]]
                if crit_high_vulns: key_findings_summary.append(f"Critical/High Vulnerabilities ({len(crit_high_vulns)}):\n" + "\n".join(crit_high_vulns[:5]))
                exposed_sensitive = [f" - Path: {f.get('path')}, Category: {f.get('category')}" for f in self.results["security_posture"].get("exposed_sensitive_files", [])]
                if exposed_sensitive: key_findings_summary.append(f"Exposed Sensitive Paths/Files ({len(exposed_sensitive)}):\n" + "\n".join(exposed_sensitive[:3]))
                correlated_items = [f" - Type: {c.get('type')}, Severity: {c.get('severity')}, Description: {str(c.get('description'))[:100]}..." for c in self.results.get("correlated_intelligence", []) if c.get("type") != "AI-Powered Insight & Summary"]
                if correlated_items: key_findings_summary.append(f"Key Correlated Intelligence ({len(correlated_items)}):\n" + "\n".join(correlated_items[:3]))
                tech_summary = []
                if self.results["technology_fingerprint"].get("cms_identified"): tech_summary.append(f"CMS: {self.results['technology_fingerprint']['cms_identified']}")
                if self.results["technology_fingerprint"].get("server_software"): tech_summary.append(f"Server Software: {', '.join(self.results['technology_fingerprint']['server_software'][:2])}")
                if self.results["technology_fingerprint"].get("waf_detected"): tech_summary.append(f"WAFs: {', '.join([w['name'] for w in self.results['technology_fingerprint']['waf_detected'][:2]])}")
                if tech_summary: key_findings_summary.append("Key Technologies:\n" + "\n".join([f" - {t}" for t in tech_summary]))

                if not key_findings_summary:
                    logger.info(f"Not enough diverse findings to generate a meaningful AI summary with {provider_name.capitalize()}. Skipping for this provider.")
                    self.results["security_posture"]["external_api_analysis_summary"].setdefault(provider_name, {})["status"] = "Skipped (Summary - No Key Findings)"
                    continue

                prompt_sections.append("\nKey Findings Overview:")
                prompt_sections.extend(key_findings_summary)
                final_prompt_summary = "\n".join(prompt_sections)
                final_prompt_summary += (
                    "\n\nBased on the KAIROS scan findings summarized above, please provide:\n"
                    "1. An Executive Summary (2-3 sentences) highlighting the overall security posture and most critical risk areas.\n"
                    "2. Prioritized Actionable Insights (3-5 bullet points) suggesting immediate next steps for remediation or further investigation, focusing on the highest impact items.\n"
                    "Be concise and professional. Focus on security implications. Output should be easily parsable markdown if possible for bullet points."
                )
                ai_summary_text, prompt_preview_summary = await self._query_llm_provider(provider_name, final_prompt_summary, "summary")
                if ai_summary_text:
                    llm_provider_used_summary = provider_name.capitalize()
                    break
            else:
                 logger.info(f"LLM analysis for summary with {provider_name.capitalize()} is disabled in configuration.")

        if not summary_task_attempted:
            logger.info("LLM summary analysis skipped: No LLM providers enabled in configuration.")


        if llm_provider_used_summary and ai_summary_text:
            summary_hash = hashlib.md5(ai_summary_text.encode()).hexdigest()
            add_finding(self.results["correlated_intelligence"], "intelligence_items",
                {"type": "AI-Powered Insight & Summary",
                 "description": f"{llm_provider_used_summary} generated the following executive summary and prioritized insights based on the scan findings.",
                 "severity": "Info", "confidence": "Medium (AI Generated)",
                 "details": {"source_llm": llm_provider_used_summary, "summary_hash": summary_hash, "full_ai_response": ai_summary_text, "prompt_sent_preview": prompt_preview_summary},
                 "recommendation": "Review the AI-generated summary for a quick overview. Always validate AI insights against the detailed findings in the report. Use as a guide for prioritization and further investigation."},
                log_message=f"AI-Powered summary and insights generated by {llm_provider_used_summary}.", severity_for_log="INFO")
        elif summary_task_attempted: # Only warn if an attempt was made
            logger.warning("Failed to generate AI summary using any configured and enabled LLM provider.")

        # --- LLM Task: Explain Findings ---
        explain_task_config = llm_tasks_config.get("explain_finding", {})
        explain_task_attempted = False
        if explain_task_config.get("enabled"):
            findings_to_explain = [
                f for f in self.results["security_posture"].get("vulnerability_findings", [])
                if f.get("severity") in ["CRITICAL", "HIGH"] and not f.get("ai_explanation")
            ][:3]

            if findings_to_explain:
                for finding_item in findings_to_explain:
                    llm_provider_used_explain = None
                    for provider_name in llm_preference:
                        if self.config["enable_external_api_integrations"].get(f"{provider_name}_analysis", False):
                            explain_task_attempted = True
                            logger.info(f"Attempting LLM explanation for finding '{finding_item.get('type')}' with {provider_name.capitalize()}...")
                            explain_prompt = explain_task_config["prompt_template"].format(
                                finding_type=finding_item.get("type", "N/A"),
                                finding_description=str(finding_item.get("description", "N/A"))[:200],
                                target_url=finding_item.get("target_url", self.results["general_info"]["final_url"]),
                                finding_details=str(finding_item.get("details", {}))[:300]
                            )
                            explanation_text, _ = await self._query_llm_provider(provider_name, explain_prompt, "explanation")
                            if explanation_text:
                                llm_provider_used_explain = provider_name.capitalize()
                                finding_item["ai_explanation"] = {
                                    "llm_provider": llm_provider_used_explain,
                                    "explanation": explanation_text,
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                                add_finding(self.results["correlated_intelligence"], "intelligence_items",
                                    {"type": "AI-Powered Finding Explanation",
                                     "description": f"{llm_provider_used_explain} provided an explanation for the finding: '{finding_item.get('type')}'.",
                                     "severity": "Info", "confidence": "Medium (AI Generated)",
                                     "details": {"original_finding_type": finding_item.get('type'), "original_finding_target": finding_item.get("target_url"), "ai_explanation": explanation_text},
                                     "recommendation": "Use this AI-generated explanation for better understanding. Always cross-verify with official documentation and your own expertise."},
                                    log_message=f"AI Explanation for '{finding_item.get('type')}' by {llm_provider_used_explain} added.", severity_for_log="INFO")
                                break
                        else:
                             logger.info(f"LLM analysis for explanation with {provider_name.capitalize()} is disabled in configuration.")
                    if not llm_provider_used_explain and explain_task_attempted:
                        logger.warning(f"Failed to get AI explanation for finding: {finding_item.get('type')} using any enabled provider.")
            else:
                logger.info("No critical/high findings needing AI explanation at this time.")
        else:
            logger.info("LLM task 'explain_finding' is disabled in configuration.")

        if not explain_task_attempted and explain_task_config.get("enabled"):
             logger.info("LLM explanation task skipped: No LLM providers enabled in configuration for this task.")


async def main_cli():
    load_config() # Load config first
    # ANSI Colors (conditional for Windows)
    bright_blue_ansi, bold_red_ansi, reset_color_ansi = "\033[1;94m", "\033[1;91m", "\033[0m"
    if platform.system() == "Windows" and not os.getenv('WT_SESSION') and not os.getenv('CONEMUANSI') and not ('TERM' in os.environ and 'xterm' in os.environ['TERM']): # Basic Windows cmd doesn't support ANSI well
        bright_blue_ansi = bold_red_ansi = reset_color_ansi = ""

    print(bright_blue_ansi + r"""
    ╦╔═╗ █████╗ ██╗██████╗  ██████╗ ███████╗
    ║║ ╦╗██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
    ╚╩═╝╝███████║██║██████╔╝██║   ██║███████╗
        ██╔══██║██║██╔══██╗██║   ██║╚════██║
        ██║  ██║██║██████╔╝╚██████╔╝███████║
        ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
    """ + reset_color_ansi)
    print(f"================================================================================================")
    print(f" {bold_red_ansi}KAIROS{reset_color_ansi} - The Zenith of Intelligent Site Reconnaissance (v{CONFIG.get('scanner_version', 'N/A')})")
    print(f" Developed by Karim Karam (Cyber-Alchemist & K.A.I.) for ETHICAL & EDUCATIONAL purposes. ")
    print(f" Enhanced and Completed by AI by user request.")
    print(f"================================================================================================\n")

    target_url_input_cli = ""
    while not target_url_input_cli:
        target_url_input_cli = input("Enter the full target URL (e.g., https://example.com or example.com): ").strip()
        if not target_url_input_cli: logger.error("Target URL cannot be empty. Please try again."); continue

        parsed_cli_url_initial = urlparse(target_url_input_cli)
        if not parsed_cli_url_initial.scheme: # If no scheme, probe for HTTPS then HTTP
            logger.info(f"No scheme provided for '{target_url_input_cli}'. Probing for HTTPS...")
            temp_https_url_cli = f"https://{target_url_input_cli.split('/')[0]}"; temp_http_url_cli = f"http://{target_url_input_cli.split('/')[0]}"; final_probed_scheme = None
            try: # Probe HTTPS
                temp_ssl_ctx_probe = ssl.create_default_context(); temp_ssl_ctx_probe.check_hostname = False; temp_ssl_ctx_probe.verify_mode = ssl.CERT_NONE
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=temp_ssl_ctx_probe)) as temp_session_probe:
                    async with temp_session_probe.head(temp_https_url_cli, timeout=aiohttp.ClientTimeout(total=7), allow_redirects=False) as resp_check_probe:
                        if resp_check_probe.status < 500: final_probed_scheme = "https"; logger.info(f"HTTPS probe successful for {temp_https_url_cli}. Using HTTPS.")
                        else: logger.info(f"HTTPS probe for {temp_https_url_cli} returned status {resp_check_probe.status}. Trying HTTP.")
            except Exception as e_probe_https: logger.warning(f"HTTPS probe for {temp_https_url_cli} failed ({type(e_probe_https).__name__}). Trying HTTP.")

            if not final_probed_scheme: final_probed_scheme = "http"; logger.info(f"Assuming HTTP for {target_url_input_cli}.") # Default to HTTP if HTTPS fails

            # Reconstruct URL with scheme and path if present
            if '/' in target_url_input_cli:
                domain_part_cli, *path_parts_cli = target_url_input_cli.split('/', 1)
                path_str_cli = "/" + path_parts_cli[0] if path_parts_cli else ""
                target_url_input_cli = f"{final_probed_scheme}://{domain_part_cli}{path_str_cli}"
            else: target_url_input_cli = f"{final_probed_scheme}://{target_url_input_cli}"

        # Final check for valid netloc
        final_parsed_cli_url_check = urlparse(target_url_input_cli)
        if not final_parsed_cli_url_check.netloc: logger.error(f"Invalid URL after scheme processing: '{target_url_input_cli}'. Could not determine host. Try full URL like 'https://example.com'."); target_url_input_cli = ""

    # Output directory
    output_dir_domain_part_cli = urlparse(target_url_input_cli).netloc.replace(':', '_').replace('.', '_') or "kairos_scan_results"
    output_dir_default_cli_val = os.path.join(os.getcwd(), f"kairos_reports_{output_dir_domain_part_cli}")
    output_dir_cli_val = input(f"Output directory for reports (default: {output_dir_default_cli_val}): ").strip() or output_dir_default_cli_val

    # Report formats
    formats_input_cli_str = input("Report formats (json,txt,html,all - default: all): ").strip().lower() or "all"
    formats_to_save_cli_list = [fmt.strip() for fmt in formats_input_cli_str.split(',') if fmt.strip()]
    if "all" in formats_to_save_cli_list or not formats_to_save_cli_list: formats_to_save_cli_list = ["json", "txt", "html"]

    # Log level
    log_level_input_cli_str = input(f"Log level ({', '.join([lvl for lvl in logging._nameToLevel if isinstance(lvl, str)])} - default: INFO): ").strip().upper() or "INFO"
    if log_level_input_cli_str in logging._nameToLevel:
        logger.setLevel(logging._nameToLevel[log_level_input_cli_str])
        console_handler.setLevel(logging._nameToLevel[log_level_input_cli_str]) # Also set for console handler
        logger.info(f"Log level set to {log_level_input_cli_str}.")
    else:
        logger.warning(f"Invalid log level '{log_level_input_cli_str}'. Input must be a single valid log level (e.g., INFO, DEBUG). Defaulting to INFO.")
        logger.setLevel(logging.INFO); console_handler.setLevel(logging.INFO)


    scanner_instance = SiteScanner(target_url_input_cli)
    async with scanner_instance:
        await scanner_instance.run_full_scan()

    scanner_instance.save_reports(output_dir_cli_val, formats=formats_to_save_cli_list)
    print("\n================================================================================================")
    logger.info("KAIROS has completed its mission. Stay curious, stay ethical.")
    print("================================================================================================")

if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        logger.info("\nScan aborted by user command (Ctrl+C). Exiting KAIROS.")
    except ValueError as ve_main_cli: # For errors like invalid URL during SiteScanner init
        logger.critical(f"KAIROS Initialization Error: {ve_main_cli}")
    except Exception as e_global_main_cli:
        logger.critical(f"A critical unhandled error occurred in KAIROS execution: {type(e_global_main_cli).__name__} - {e_global_main_cli}", exc_info=True)
