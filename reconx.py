import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import sqlite3
import csv
import datetime
import re
import os
import json

try:
    import whois
except ImportError:
    whois = None

try:
    import requests
except ImportError:
    requests = None

BG_DARK   = "#0f0f1a"
BG_PANEL  = "#1a1a2e"
BG_CARD   = "#16213e"
BG_ENTRY  = "#0f3460"
FG_WHITE  = "#e0e0e0"
FG_DIM    = "#8888aa"
ACCENT    = "#e94560"
ACCENT2   = "#00b4d8"
SUCCESS   = "#4ade80"
WARNING   = "#facc15"
DANGER    = "#f87171"
FONT_MAIN = ("Consolas", 10)
FONT_HEAD = ("Consolas", 11, "bold")
FONT_TITL = ("Consolas", 14, "bold")

NO_DATA   = "  No data available for this target."

class TargetValidator:

    DOMAIN_RE = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    IP_RE = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )

    def __init__(self, raw_input: str):
        self.raw   = raw_input.strip()
        self.clean = self._normalise(self.raw)

    def _normalise(self, value: str) -> str:
        for prefix in ("https://", "http://"):
            if value.lower().startswith(prefix):
                value = value[len(prefix):]
        if value.lower().startswith("www."):
            value = value[4:]
        value = value.split("/")[0].split("?")[0].strip()
        return value

    def validate(self) -> str:
        if not self.clean:
            raise ValueError("Target cannot be empty.")
        if len(self.clean) > 253:
            raise ValueError("Target exceeds maximum length of 253 characters.")
        if self.is_ip() or self.is_domain():
            return self.clean
        raise ValueError(
            f"'{self.clean}' is not a valid domain name or IPv4 address."
        )

    def is_ip(self) -> bool:
        return bool(self.IP_RE.match(self.clean))

    def is_domain(self) -> bool:
        return bool(self.DOMAIN_RE.match(self.clean))

class WHOISLookup:

    NO_DATA_RESULT = {
        "registrar"       : "No data",
        "creation_date"   : "No data",
        "expiration_date" : "No data",
        "updated_date"    : "No data",
        "name_servers"    : "No data",
        "status"          : "No data",
        "emails"          : "No data",
        "org"             : "No data",
        "country"         : "No data",
        "dnssec"          : "No data",
    }

    def __init__(self, target: str):
        self.target  = target
        self.results = {}
        self.error   = None

    def lookup(self) -> dict:
        if whois is None:
            self.error   = "python-whois not installed. Run: pip install python-whois"
            self.results = dict(self.NO_DATA_RESULT)
            return self.results
        try:
            w            = whois.whois(self.target)
            self.results = {
                "registrar"       : self._fmt(w.registrar),
                "creation_date"   : self._fmt(w.creation_date),
                "expiration_date" : self._fmt(w.expiration_date),
                "updated_date"    : self._fmt(w.updated_date),
                "name_servers"    : self._fmt(w.name_servers),
                "status"          : self._fmt(w.status),
                "emails"          : self._fmt(w.emails),
                "org"             : self._fmt(w.org),
                "country"         : self._fmt(w.country),
                "dnssec"          : self._fmt(getattr(w, "dnssec", None)),
            }
            self.results = {
                k: (v if v and v not in ("None", "") else "No data")
                for k, v in self.results.items()
            }
        except Exception as exc:
            self.error   = str(exc)
            self.results = dict(self.NO_DATA_RESULT)
        return self.results

    @staticmethod
    def _fmt(value) -> str:
        if value is None:
            return "No data"
        if isinstance(value, list):
            items = [str(v).strip() for v in value if v]
            return ", ".join(dict.fromkeys(items)) if items else "No data"
        cleaned = str(value).strip()
        return cleaned if cleaned else "No data"

class DNSEnumerator:

    RECORD_TYPES = ["A", "MX", "NS", "TXT", "CNAME"]

    def __init__(self, target: str):
        self.target  = target
        self.results = {rt: ["No data"] for rt in self.RECORD_TYPES}
        self.error   = None

    def enumerate(self) -> dict:
        self._resolve_a()
        self._resolve_extra()
        return self.results

    def _resolve_a(self):
        try:
            infos = socket.getaddrinfo(self.target, None)
            ips   = list({info[4][0] for info in infos})
            self.results["A"] = ips if ips else ["No data"]
        except socket.gaierror as exc:
            self.results["A"] = [f"No data (DNS error: {exc})"]

    def _resolve_extra(self):
        try:
            import dns.resolver  # type: ignore
            for rtype in ["MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(self.target, rtype)
                    records = [str(r) for r in answers]
                    self.results[rtype] = records if records else ["No data"]
                except Exception:
                    self.results[rtype] = ["No data"]
        except ImportError:
            for rtype in ["MX", "NS", "TXT", "CNAME"]:
                self.results[rtype] = ["No data (dnspython not installed)"]

class SubdomainScanner:

    WORDLIST = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin",
        "portal", "vpn", "remote", "dev", "staging", "test", "api",
        "cdn", "static", "assets", "img", "images", "media", "blog",
        "shop", "store", "app", "mobile", "m", "ns1", "ns2", "dns",
        "mx", "mx1", "mx2", "autodiscover", "autoconfig", "cpanel",
        "whm", "sftp", "ssh", "git", "gitlab", "jenkins",
        "jira", "confluence", "intranet", "internal", "secure",
        "beta", "preview", "uat", "qa", "support", "help", "docs",
        "wiki", "status", "monitor", "dashboard", "panel", "login",
    ]

    def __init__(self, domain: str, timeout: float = 1.0, callback=None):
        self.domain   = domain
        self.timeout  = timeout
        self.callback = callback
        self.found    = []
        self.total    = len(self.WORDLIST)

    def scan(self) -> list:
        self.found = []
        for idx, word in enumerate(self.WORDLIST):
            if self.callback:
                self.callback(idx + 1, self.total)
            candidate = f"{word}.{self.domain}"
            if self._is_alive(candidate):
                self.found.append(candidate)
        return self.found

    def _is_alive(self, host: str) -> bool:
        for port in (80, 443):
            try:
                with socket.create_connection((host, port), timeout=self.timeout):
                    return True
            except (socket.timeout, socket.error, OSError):
                continue
        return False

class PortScanner:

    COMMON_PORTS = {
        21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",
        53: "DNS",    80: "HTTP",    110: "POP3",   143: "IMAP",
        443: "HTTPS", 445: "SMB",    3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }

    def __init__(self, target: str, timeout: float = 1.0, callback=None):
        self.target     = target
        self.timeout    = timeout
        self.callback   = callback
        self.open_ports = []
        self.total      = len(self.COMMON_PORTS)
        self.error      = None

    def scan(self) -> list:
        self.open_ports = []
        try:
            socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            self.error = f"Cannot resolve target: {exc}"
            return []

        for idx, (port, service) in enumerate(self.COMMON_PORTS.items()):
            if self.callback:
                self.callback(idx + 1, self.total)
            result = self._probe(port, service)
            if result:
                self.open_ports.append(result)
        return self.open_ports

    def _probe(self, port: int, service: str):
        try:
            with socket.create_connection(
                    (self.target, port), timeout=self.timeout) as s:
                banner = ""
                try:
                    s.settimeout(0.5)
                    banner = s.recv(256).decode(errors="ignore").strip()
                except Exception:
                    pass
                return {
                    "port"   : port,
                    "service": service,
                    "banner" : banner if banner else "No banner",
                }
        except (socket.timeout, socket.error, OSError):
            return None

class HTTPHeaderAnalyser:

    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("HIGH",   "HSTS not set — vulnerable to downgrade attacks."),
        "Content-Security-Policy"  : ("HIGH",   "CSP not set — XSS risk increased."),
        "X-Frame-Options"          : ("MEDIUM", "X-Frame-Options missing — clickjacking possible."),
        "X-Content-Type-Options"   : ("MEDIUM", "X-Content-Type-Options missing — MIME sniffing risk."),
        "Referrer-Policy"          : ("LOW",    "Referrer-Policy not set — may leak sensitive URLs."),
        "Permissions-Policy"       : ("LOW",    "Permissions-Policy missing — browser features unrestricted."),
        "X-XSS-Protection"         : ("LOW",    "X-XSS-Protection header absent."),
        "Cache-Control"            : ("LOW",    "Cache-Control not set — sensitive data may be cached."),
    }

    def __init__(self, target: str, timeout: int = 5):
        self.target   = target
        self.timeout  = timeout
        self.headers  = {}
        self.findings = []
        self.url_used = "No data"
        self.status   = "No data"
        self.server   = "No data"

    def analyse(self) -> dict:
        if requests is None:
            self.findings.append({
                "severity": "HIGH",
                "detail"  : "requests library not installed — HTTP analysis skipped."
            })
            return self._package()

        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            try:
                resp = requests.get(
                    url, timeout=self.timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "ReconX/1.0"}
                )
                self.url_used = resp.url or "No data"
                self.status   = str(resp.status_code)
                self.headers  = dict(resp.headers) if resp.headers else {}
                self.server   = resp.headers.get("Server", "No data")
                self._check_security_headers()
                return self._package()
            except Exception:
                continue

        self.url_used = f"No data — {self.target} unreachable"
        self.findings.append({
            "severity": "INFO",
            "detail"  : f"No data — target {self.target} was unreachable on HTTP and HTTPS."
        })
        return self._package()

    def _check_security_headers(self):
        if not self.headers:
            self.findings.append({
                "severity": "INFO",
                "detail"  : "No data — no headers returned by the server."
            })
            return
        for header, (severity, desc) in self.SECURITY_HEADERS.items():
            if header not in self.headers:
                self.findings.append({"severity": severity, "detail": desc})

    def _package(self) -> dict:
        return {
            "url"     : self.url_used,
            "status"  : self.status,
            "server"  : self.server,
            "headers" : self.headers if self.headers else {"info": "No data"},
            "findings": self.findings,
        }

class IPGeoLocator:

    API_URL = "http://ip-api.com/json/{ip}?fields=66846719"

    NO_DATA_RESULT = {
        "ip"          : "No data",
        "country"     : "No data",
        "country_code": "No data",
        "region"      : "No data",
        "city"        : "No data",
        "zip"         : "No data",
        "lat"         : "No data",
        "lon"         : "No data",
        "timezone"    : "No data",
        "isp"         : "No data",
        "org"         : "No data",
        "asn"         : "No data",
        "mobile"      : "No data",
        "proxy"       : "No data",
        "hosting"     : "No data",
    }

    def __init__(self, target: str):
        self.target  = target
        self.ip      = ""
        self.results = {}
        self.error   = None

    def locate(self) -> dict:
        if requests is None:
            self.error   = "requests library not installed."
            self.results = dict(self.NO_DATA_RESULT)
            return self.results

        try:
            self.ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            self.error   = f"DNS resolution failed: {exc}"
            self.results = dict(self.NO_DATA_RESULT)
            self.results["ip"] = f"No data ({exc})"
            return self.results

        try:
            resp = requests.get(
                self.API_URL.format(ip=self.ip),
                timeout=5,
                headers={"User-Agent": "ReconX/1.0"}
            )
            data = resp.json()
            if data.get("status") == "success":
                self.results = {
                    "ip"          : self.ip,
                    "country"     : data.get("country")     or "No data",
                    "country_code": data.get("countryCode") or "No data",
                    "region"      : data.get("regionName")  or "No data",
                    "city"        : data.get("city")        or "No data",
                    "zip"         : data.get("zip")         or "No data",
                    "lat"         : data.get("lat")         or "No data",
                    "lon"         : data.get("lon")         or "No data",
                    "timezone"    : data.get("timezone")    or "No data",
                    "isp"         : data.get("isp")         or "No data",
                    "org"         : data.get("org")         or "No data",
                    "asn"         : data.get("as")          or "No data",
                    "mobile"      : data.get("mobile",  "No data"),
                    "proxy"       : data.get("proxy",   "No data"),
                    "hosting"     : data.get("hosting", "No data"),
                }
            else:
                self.error   = data.get("message", "No data returned by ip-api.com")
                self.results = dict(self.NO_DATA_RESULT)
                self.results["ip"] = self.ip
        except Exception as exc:
            self.error   = str(exc)
            self.results = dict(self.NO_DATA_RESULT)
        return self.results

class DatabaseManager:

    def __init__(self, db_path: str = "reconx_results.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    target    TEXT    NOT NULL,
                    timestamp TEXT    NOT NULL,
                    modules   TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id   INTEGER NOT NULL,
                    module    TEXT    NOT NULL,
                    severity  TEXT    NOT NULL,
                    detail    TEXT    NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS raw_results (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    module  TEXT    NOT NULL,
                    data    TEXT    NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            conn.commit()

    def save_scan(self, target: str, modules: list) -> int:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, timestamp, modules) VALUES (?,?,?)",
                (target, ts, ", ".join(modules))
            )
            conn.commit()
            return cur.lastrowid

    def save_findings(self, scan_id: int, findings: list):
        with sqlite3.connect(self.db_path) as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, module, severity, detail) "
                    "VALUES (?,?,?,?)",
                    (scan_id, f.get("module", "Unknown"),
                     f.get("severity", "INFO"), f.get("detail", "No data"))
                )
            conn.commit()

    def save_raw(self, scan_id: int, module: str, data: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO raw_results (scan_id, module, data) VALUES (?,?,?)",
                (scan_id, module, json.dumps(data, default=str))
            )
            conn.commit()

    def get_history(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_findings_for_scan(self, scan_id: int) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY severity",
                (scan_id,)
            ).fetchall()
            return [dict(r) for r in rows]

class ReconReportExporter:

    def __init__(self, target: str, scan_data: dict, findings: list):
        self.target    = target
        self.scan_data = scan_data
        self.findings  = findings
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.datestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_csv(self, filepath: str = "") -> str:
        if not filepath:
            filepath = f"ReconX_{self.target}_{self.datestamp}.csv"
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ReconX OSINT Report"])
            writer.writerow(["Target", self.target])
            writer.writerow(["Date",   self.timestamp])
            writer.writerow([])
            writer.writerow(["Module", "Severity", "Finding"])
            if self.findings:
                for finding in self.findings:
                    writer.writerow([
                        finding.get("module",   "No data"),
                        finding.get("severity", "No data"),
                        finding.get("detail",   "No data"),
                    ])
            else:
                writer.writerow(["All Modules", "INFO",
                                 "No findings — no data was extracted."])
        return filepath

    def export_txt(self, filepath: str = "") -> str:
        if not filepath:
            filepath = f"ReconX_{self.target}_{self.datestamp}.txt"
        sep = "=" * 70
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"{sep}\n  RECONX — OSINT RECONNAISSANCE REPORT\n{sep}\n")
            f.write(f"  Target    : {self.target}\n")
            f.write(f"  Generated : {self.timestamp}\n")
            f.write(f"  Tool      : ReconX v1.0\n{sep}\n\n")

            for module, data in self.scan_data.items():
                f.write(f"\n[{module.upper()}]\n" + "-" * 50 + "\n")
                if isinstance(data, dict):
                    if not data:
                        f.write("  No data\n")
                    else:
                        for k, v in data.items():
                            if k == "findings":
                                continue
                            f.write(f"  {k:<22}: {v if v else 'No data'}\n")
                elif isinstance(data, list):
                    if not data:
                        f.write("  No data\n")
                    else:
                        for item in data:
                            f.write(f"  • {item}\n")
                else:
                    f.write(f"  {data if data else 'No data'}\n")

            f.write(f"\n\n{sep}\n  SECURITY FINDINGS\n{sep}\n")
            if not self.findings:
                f.write("  No data — no findings were generated.\n")
            else:
                sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
                for finding in sorted(
                        self.findings,
                        key=lambda x: sev_order.get(x.get("severity", "INFO"), 99)):
                    f.write(
                        f"  [{finding.get('severity','INFO'):6}] "
                        f"[{finding.get('module','?'):20}] "
                        f"{finding.get('detail','No data')}\n"
                    )
            f.write(f"\n{sep}\n  END OF REPORT\n{sep}\n")
        return filepath

class GUIApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ReconX — OSINT Reconnaissance Tool")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1280x760")
        self.root.minsize(1100, 680)

        self.db              = DatabaseManager()
        self.scan_data       = {}
        self.all_findings    = []
        self.current_scan_id = None
        self._stop_flag      = False

        self.target_var   = tk.StringVar()
        self.status_var   = tk.StringVar(value="Ready.")
        self.progress_var = tk.DoubleVar(value=0.0)

        self.mod_vars = {
            "WHOIS"       : tk.BooleanVar(value=True),
            "DNS"         : tk.BooleanVar(value=True),
            "Subdomains"  : tk.BooleanVar(value=True),
            "Ports"       : tk.BooleanVar(value=True),
            "HTTP Headers": tk.BooleanVar(value=True),
            "Geolocation" : tk.BooleanVar(value=True),
        }

        self._apply_style()
        self._build_ui()

    def _apply_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",
                         background=BG_PANEL, borderwidth=0)
        style.configure("TNotebook.Tab",
                         background=BG_CARD, foreground=FG_DIM,
                         font=FONT_MAIN, padding=(10, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_ENTRY)],
                  foreground=[("selected", ACCENT)])
        style.configure("TProgressbar",
                         troughcolor=BG_CARD, background=ACCENT,
                         thickness=6)
        style.configure("Treeview",
                         background=BG_CARD, foreground=FG_WHITE,
                         fieldbackground=BG_CARD, font=FONT_MAIN,
                         rowheight=22)
        style.configure("Treeview.Heading",
                         background=BG_ENTRY, foreground=ACCENT,
                         font=FONT_HEAD)
        style.map("Treeview", background=[("selected", BG_ENTRY)])

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=BG_DARK)
        outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        left = tk.Frame(outer, bg=BG_PANEL, width=240)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        left.pack_propagate(False)
        self._build_left_panel(left)

        right = tk.Frame(outer, bg=BG_DARK)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_notebook(right)

        status_bar = tk.Frame(self.root, bg=BG_CARD, height=26)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(status_bar, textvariable=self.status_var,
                 bg=BG_CARD, fg=ACCENT2, font=FONT_MAIN,
                 anchor="w").pack(side=tk.LEFT, padx=10)

    def _build_left_panel(self, parent):
        tk.Label(parent, text="⬡ ReconX",
                 bg=BG_PANEL, fg=ACCENT,
                 font=("Consolas", 16, "bold")).pack(pady=(14, 2))
        tk.Label(parent, text="OSINT Reconnaissance",
                 bg=BG_PANEL, fg=FG_DIM,
                 font=("Consolas", 8)).pack(pady=(0, 14))
        self._sep(parent)

        tk.Label(parent, text="TARGET", bg=BG_PANEL, fg=FG_DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=14)
        self.target_entry = tk.Entry(
            parent, textvariable=self.target_var,
            bg=BG_ENTRY, fg=FG_WHITE, insertbackground=FG_WHITE,
            font=FONT_MAIN, relief=tk.FLAT, bd=4
        )
        self.target_entry.pack(fill=tk.X, padx=14, pady=(2, 10))
        self._sep(parent)

        tk.Label(parent, text="MODULES", bg=BG_PANEL, fg=FG_DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=14, pady=(6, 2))
        for name, var in self.mod_vars.items():
            tk.Checkbutton(
                parent, text=name, variable=var,
                bg=BG_PANEL, fg=FG_WHITE, selectcolor=BG_ENTRY,
                activebackground=BG_PANEL, activeforeground=ACCENT,
                font=FONT_MAIN
            ).pack(anchor="w", padx=16, pady=1)
        self._sep(parent)

        buttons = [
            ("▶  Start Scan",  ACCENT,    self._start_scan),
            ("💾  Save to DB", ACCENT2,   self._save_to_db),
            ("📄  Export CSV", "#4ade80", self._export_csv),
            ("📝  Export TXT", "#facc15", self._export_txt),
            ("🗑  Clear",      FG_DIM,    self._clear_all),
        ]
        for label, colour, cmd in buttons:
            tk.Button(
                parent, text=label, command=cmd,
                bg=BG_CARD, fg=colour,
                activebackground=BG_ENTRY, activeforeground=colour,
                font=FONT_MAIN, relief=tk.FLAT, bd=0,
                cursor="hand2", pady=5
            ).pack(fill=tk.X, padx=14, pady=3)
        self._sep(parent)

        tk.Label(parent, text="PROGRESS", bg=BG_PANEL, fg=FG_DIM,
                 font=("Consolas", 8)).pack(anchor="w", padx=14, pady=(4, 1))
        self.progress_bar = ttk.Progressbar(
            parent, variable=self.progress_var,
            maximum=100, mode="determinate", style="TProgressbar"
        )
        self.progress_bar.pack(fill=tk.X, padx=14, pady=(0, 8))

    def _build_notebook(self, parent):
        self.notebook = ttk.Notebook(parent, style="TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tabs = {}
        tab_names = [
            "Overview", "WHOIS", "DNS", "Subdomains",
            "Ports", "HTTP Headers", "Geolocation"
        ]
        for name in tab_names:
            frame = tk.Frame(self.notebook, bg=BG_DARK)
            self.notebook.add(frame, text=name)
            self.tabs[name] = frame

        self._build_overview_tab()
        self._build_text_tab("WHOIS")
        self._build_text_tab("DNS")
        self._build_text_tab("Subdomains")
        self._build_ports_tab()
        self._build_text_tab("HTTP Headers")
        self._build_text_tab("Geolocation")

    def _build_overview_tab(self):
        frame = self.tabs["Overview"]
        tk.Label(frame, text="SCAN OVERVIEW",
                 bg=BG_DARK, fg=ACCENT, font=FONT_TITL).pack(pady=(16, 4))

        info_frame = tk.Frame(frame, bg=BG_CARD)
        info_frame.pack(fill=tk.X, padx=16, pady=6)

        self.overview_labels = {}
        for i, (k, v) in enumerate([
            ("Target", "—"), ("Scan Time", "—"),
            ("Modules Run", "—"), ("Total Findings", "—"),
        ]):
            tk.Label(info_frame, text=f"{k}:", bg=BG_CARD,
                     fg=FG_DIM, font=FONT_MAIN, width=16,
                     anchor="e").grid(row=i, column=0, padx=10, pady=4, sticky="e")
            lbl = tk.Label(info_frame, text=v, bg=BG_CARD,
                           fg=FG_WHITE, font=FONT_MAIN, anchor="w")
            lbl.grid(row=i, column=1, padx=10, pady=4, sticky="w")
            self.overview_labels[k] = lbl

        tk.Label(frame, text="MODULE STATUS",
                 bg=BG_DARK, fg=ACCENT2, font=FONT_HEAD).pack(pady=(10, 2))
        self.overview_text = self._make_text(frame)

    def _build_text_tab(self, name: str):
        frame  = self.tabs[name]
        tk.Label(frame, text=name.upper(), bg=BG_DARK,
                 fg=ACCENT, font=FONT_HEAD).pack(pady=(10, 4))
        widget = self._make_text(frame)
        setattr(self, name.lower().replace(" ", "_") + "_text", widget)

    def _build_ports_tab(self):
        frame = self.tabs["Ports"]
        tk.Label(frame, text="PORT SCAN", bg=BG_DARK,
                 fg=ACCENT, font=FONT_HEAD).pack(pady=(10, 4))
        cols = ("Port", "Service", "Banner")
        self.ports_tree = ttk.Treeview(frame, columns=cols,
                                        show="headings", style="Treeview")
        for col in cols:
            self.ports_tree.heading(col, text=col)
            self.ports_tree.column(col, width=220 if col == "Banner" else 110)
        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                            command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=sb.set)
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH,
                             expand=True, padx=(10, 0), pady=6)
        sb.pack(side=tk.LEFT, fill=tk.Y, pady=6)

    def _make_text(self, parent) -> tk.Text:
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        sb = tk.Scrollbar(frame, bg=BG_CARD)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        t = tk.Text(
            frame, bg=BG_CARD, fg=FG_WHITE,
            insertbackground=FG_WHITE, font=FONT_MAIN,
            relief=tk.FLAT, wrap=tk.WORD,
            yscrollcommand=sb.set, state=tk.DISABLED
        )
        t.pack(fill=tk.BOTH, expand=True)
        sb.config(command=t.yview)
        t.tag_configure("heading", foreground=ACCENT,  font=FONT_HEAD)
        t.tag_configure("key",     foreground=ACCENT2)
        t.tag_configure("value",   foreground=FG_WHITE)
        t.tag_configure("found",   foreground=SUCCESS)
        t.tag_configure("warn",    foreground=WARNING)
        t.tag_configure("danger",  foreground=DANGER)
        t.tag_configure("nodata",  foreground=FG_DIM)
        return t

    @staticmethod
    def _sep(parent):
        tk.Frame(parent, bg=ACCENT, height=1).pack(fill=tk.X, padx=14, pady=6)

    def _write(self, widget: tk.Text, text: str, tag: str = ""):
        widget.configure(state=tk.NORMAL)
        if tag:
            widget.insert(tk.END, text, tag)
        else:
            widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)
        widget.see(tk.END)

    def _clear_text(self, widget: tk.Text):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.configure(state=tk.DISABLED)

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_progress(self, value: float):
        self.root.after(0, lambda: self.progress_var.set(value))

    def _start_scan(self):
        raw = self.target_var.get()
        try:
            validator = TargetValidator(raw)
            target    = validator.validate()
        except ValueError as e:
            messagebox.showerror("Invalid Target", str(e))
            return

        self._clear_all(confirm=False)
        self.scan_data    = {}
        self.all_findings = []
        self._stop_flag   = False

        threading.Thread(
            target=self._run_scan,
            args=(target, validator.is_ip()),
            daemon=True
        ).start()

    def _run_scan(self, target: str, is_ip: bool):
        self._set_status(f"Scanning {target} ...")
        selected    = [m for m, v in self.mod_vars.items() if v.get()]
        total_steps = len(selected)
        step        = 0

        def prog(cur, tot):
            pct = ((step / total_steps) + (cur / tot / total_steps)) * 100
            self._set_progress(pct)

        if self.mod_vars["WHOIS"].get():
            self._set_status("Running WHOIS lookup …")
            w      = WHOISLookup(target)
            result = w.lookup()
            self.scan_data["WHOIS"] = result
            self.root.after(0, self._display_whois, result, w.error)
            step += 1; self._set_progress((step / total_steps) * 100)

        if self.mod_vars["DNS"].get():
            if is_ip:
                self.root.after(0, self._display_dns, {})
            else:
                self._set_status("Enumerating DNS records …")
                d      = DNSEnumerator(target)
                result = d.enumerate()
                self.scan_data["DNS"] = result
                self.root.after(0, self._display_dns, result)
            step += 1; self._set_progress((step / total_steps) * 100)

        if self.mod_vars["Subdomains"].get():
            if is_ip:
                self.root.after(0, self._display_subdomains, None)
            else:
                self._set_status("Scanning subdomains …")
                s     = SubdomainScanner(target, callback=lambda c, t: prog(c, t))
                found = s.scan()
                self.scan_data["Subdomains"] = found
                self.root.after(0, self._display_subdomains, found)
            step += 1; self._set_progress((step / total_steps) * 100)

        if self.mod_vars["Ports"].get():
            self._set_status("Scanning ports …")
            resolve = target
            if not is_ip:
                try:
                    resolve = socket.gethostbyname(target)
                except Exception:
                    resolve = target
            p          = PortScanner(resolve, callback=lambda c, t: prog(c, t))
            open_ports = p.scan()
            self.scan_data["Ports"] = open_ports
            self.root.after(0, self._display_ports, open_ports, p.error)
            step += 1; self._set_progress((step / total_steps) * 100)

        if self.mod_vars["HTTP Headers"].get():
            self._set_status("Analysing HTTP headers …")
            h      = HTTPHeaderAnalyser(target)
            result = h.analyse()
            self.scan_data["HTTP Headers"] = result
            self.all_findings += [
                dict(f, module="HTTP Headers")
                for f in result.get("findings", [])
            ]
            self.root.after(0, self._display_http, result)
            step += 1; self._set_progress((step / total_steps) * 100)

        if self.mod_vars["Geolocation"].get():
            self._set_status("Geolocating IP …")
            g      = IPGeoLocator(target)
            result = g.locate()
            self.scan_data["Geolocation"] = result
            self.root.after(0, self._display_geo, result, g.error)
            step += 1; self._set_progress((step / total_steps) * 100)

        self.root.after(0, self._update_overview, target, selected)
        self._set_progress(100)
        self._set_status(f"Scan complete — {target}")

    def _display_whois(self, data: dict, error):
        w = self.whois_text
        self._clear_text(w)
        if not data:
            self._write(w, f"\n{NO_DATA}\n", "nodata")
            if error:
                self._write(w, f"\n  Error: {error}\n", "danger")
            return
        if error:
            self._write(w, f"  Note: {error}\n\n", "warn")
        for k, v in data.items():
            self._write(w, f"  {k:<22}: ", "key")
            self._write(w, f"{v}\n", "nodata" if v == "No data" else "value")

    def _display_dns(self, data: dict):
        w = self.dns_text
        self._clear_text(w)
        if not data:
            self._write(w, f"\n{NO_DATA}\n", "nodata")
            self._write(w,
                "\n  DNS enumeration is not available for raw IP addresses.\n",
                "warn")
            return
        for rtype, records in data.items():
            self._write(w, f"\n  {rtype} Records\n", "heading")
            for r in records:
                tag = "nodata" if "No data" in r else "found"
                self._write(w, f"    • {r}\n", tag)

    def _display_subdomains(self, found):
        w = self.subdomains_text
        self._clear_text(w)
        if found is None:
            self._write(w, f"\n{NO_DATA}\n", "nodata")
            self._write(w,
                "\n  Subdomain scanning requires a domain name, not a raw IP.\n",
                "warn")
            return
        if not found:
            self._write(w, f"\n{NO_DATA}\n", "nodata")
            self._write(w,
                "\n  No live subdomains responded from the built-in wordlist.\n",
                "warn")
            return
        self._write(w, f"  {len(found)} subdomain(s) discovered:\n\n", "heading")
        for sd in found:
            self._write(w, f"    ✔ {sd}\n", "found")

    def _display_ports(self, open_ports: list, error=None):
        for row in self.ports_tree.get_children():
            self.ports_tree.delete(row)
        if error:
            self.ports_tree.insert(
                "", tk.END, values=("—", "No data", f"Error: {error}"))
            return
        if not open_ports:
            self.ports_tree.insert(
                "", tk.END, values=("—", "No data", "No open ports detected"))
            return
        for p in open_ports:
            self.ports_tree.insert(
                "", tk.END, values=(p["port"], p["service"], p["banner"]))

    def _display_http(self, data: dict):
        w = self.http_headers_text
        self._clear_text(w)
        self._write(w, f"  URL    : {data.get('url',    'No data')}\n", "key")
        self._write(w, f"  Status : {data.get('status', 'No data')}\n", "key")
        self._write(w, f"  Server : {data.get('server', 'No data')}\n\n", "key")

        headers = data.get("headers", {})
        if not headers or headers == {"info": "No data"}:
            self._write(w, f"  Headers: No data\n", "nodata")
        else:
            self._write(w, "  RESPONSE HEADERS\n", "heading")
            for k, v in headers.items():
                self._write(w, f"    {k}: ", "key")
                self._write(w, f"{v}\n", "value")

        findings = data.get("findings", [])
        if findings:
            self._write(w, "\n  SECURITY NOTES\n", "heading")
            for f in findings:
                sev = f.get("severity", "INFO")
                tag = {"HIGH": "danger", "MEDIUM": "warn",
                       "LOW": "found", "INFO": "nodata"}.get(sev, "nodata")
                self._write(w, f"  [{sev}] {f.get('detail', 'No data')}\n", tag)

    def _display_geo(self, data: dict, error):
        w = self.geolocation_text
        self._clear_text(w)
        if not data or all(str(v) == "No data" for v in data.values()):
            self._write(w, f"\n{NO_DATA}\n", "nodata")
            if error:
                self._write(w, f"\n  Error: {error}\n", "danger")
            return
        if error:
            self._write(w, f"  Note: {error}\n\n", "warn")
        for k, v in data.items():
            tag = "nodata" if str(v) == "No data" else (
                "warn" if k in ("proxy", "hosting") and v is True else "value"
            )
            self._write(w, f"  {k:<16}: ", "key")
            self._write(w, f"{v}\n", tag)

    def _update_overview(self, target: str, modules: list):
        self.overview_labels["Target"].config(text=target)
        self.overview_labels["Scan Time"].config(
            text=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.overview_labels["Modules Run"].config(text=", ".join(modules))
        self.overview_labels["Total Findings"].config(
            text=str(len(self.all_findings)))

        self._clear_text(self.overview_text)
        for module in modules:
            data = self.scan_data.get(module)
            if data is None:
                status, tag = "No data", "nodata"
            elif isinstance(data, list) and not data:
                status, tag = "No data returned", "nodata"
            elif isinstance(data, dict) and all(
                    str(v) == "No data"
                    for k, v in data.items() if k != "findings"):
                status, tag = "No data returned", "nodata"
            else:
                status, tag = "Data retrieved ✔", "found"
            self._write(self.overview_text, f"  {module:<16}: ", "key")
            self._write(self.overview_text, f"{status}\n", tag)

    def _save_to_db(self):
        target = self.target_var.get().strip()
        if not target or not self.scan_data:
            messagebox.showwarning("No Data", "Run a scan first before saving.")
            return
        modules = [m for m, v in self.mod_vars.items() if v.get()]
        sid     = self.db.save_scan(target, modules)
        self.db.save_findings(sid, self.all_findings)
        for module, data in self.scan_data.items():
            self.db.save_raw(
                sid, module,
                data if isinstance(data, dict) else {"data": data}
            )
        self.current_scan_id = sid
        messagebox.showinfo("Saved", f"Scan saved to database (ID: {sid}).")

    def _export_csv(self):
        if not self.scan_data:
            messagebox.showwarning("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"ReconX_{self.target_var.get()}.csv"
        )
        if not path:
            return
        exp     = ReconReportExporter(
            self.target_var.get(), self.scan_data, self.all_findings)
        written = exp.export_csv(path)
        messagebox.showinfo("Exported", f"CSV saved to:\n{written}")

    def _export_txt(self):
        if not self.scan_data:
            messagebox.showwarning("No Data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"ReconX_{self.target_var.get()}.txt"
        )
        if not path:
            return
        exp     = ReconReportExporter(
            self.target_var.get(), self.scan_data, self.all_findings)
        written = exp.export_txt(path)
        messagebox.showinfo("Exported", f"TXT report saved to:\n{written}")

    def _clear_all(self, confirm: bool = True):
        if confirm:
            if not messagebox.askyesno("Clear", "Clear all results?"):
                return

        for attr in ["whois_text", "dns_text", "subdomains_text",
                     "http_headers_text", "geolocation_text", "overview_text"]:
            widget = getattr(self, attr, None)
            if widget:
                self._clear_text(widget)

        for row in self.ports_tree.get_children():
            self.ports_tree.delete(row)

        for lbl in self.overview_labels.values():
            lbl.config(text="—", fg=FG_WHITE)

        self.scan_data    = {}
        self.all_findings = []
        self.progress_var.set(0)
        self._set_status("Cleared.")

def main():
    root = tk.Tk()
    app  = GUIApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()