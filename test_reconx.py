import unittest
import sys
import os
import types
import sqlite3
import tempfile

def _mock_tkinter():
    for mod in ['tkinter', 'tkinter.ttk',
                'tkinter.messagebox', 'tkinter.filedialog']:
        if mod not in sys.modules:
            sys.modules[mod] = types.ModuleType(mod)

    tk = sys.modules['tkinter']

    def _noop(*a, **k): return None
    def _noop_self(s, *a, **k): return None

    for name in ['Tk','Frame','Label','Button','Entry',
                 'Checkbutton','Text','Scrollbar']:
        cls = type(name, (), {
            '__init__' : _noop_self,
            'pack'     : _noop_self,
            'configure': _noop_self,
            'config'   : _noop_self,
            'grid'     : _noop_self,
            'pack_propagate': _noop_self,
            'insert'   : _noop_self,
            'delete'   : _noop_self,
            'see'      : _noop_self,
            'tag_configure': _noop_self,
            'get_children' : lambda s: [],
            'get'      : lambda s, *a: '',
            'set'      : _noop_self,
            'after'    : _noop_self,
            'mainloop' : _noop_self,
            'title'    : _noop_self,
            'geometry' : _noop_self,
            'minsize'  : _noop_self,
        })
        setattr(tk, name, cls)

    for name in ['StringVar', 'BooleanVar', 'DoubleVar']:
        default = '' if 'String' in name else (True if 'Bool' in name else 0.0)
        cls = type(name, (), {
            '__init__': lambda s, value=default, **k: setattr(s, '_v', value),
            'get'     : lambda s: s._v,
            'set'     : lambda s, v: setattr(s, '_v', v),
        })
        setattr(tk, name, cls)

    for const, val in [('END','end'),('BOTH','both'),('LEFT','left'),
                       ('RIGHT','right'),('Y','y'),('X','x'),
                       ('FLAT','flat'),('WORD','word'),
                       ('NORMAL','normal'),('DISABLED','disabled'),
                       ('BOTTOM','bottom')]:
        setattr(tk, const, val)

    ttk = sys.modules['tkinter.ttk']
    for name in ['Style','Notebook','Progressbar','Treeview','Scrollbar']:
        cls = type(name, (), {
            '__init__' : _noop_self,
            'pack'     : _noop_self,
            'configure': _noop_self,
            'config'   : _noop_self,
            'theme_use': _noop_self,
            'map'      : _noop_self,
            'add'      : _noop_self,
            'heading'  : _noop_self,
            'column'   : _noop_self,
            'insert'   : _noop_self,
            'delete'   : _noop_self,
            'get_children': lambda s: [],
            'tag_configure': _noop_self,
        })
        setattr(ttk, name, cls)

    mb = sys.modules['tkinter.messagebox']
    mb.showerror   = _noop
    mb.showwarning = _noop
    mb.showinfo    = _noop
    mb.askyesno    = lambda *a, **k: True

    fd = sys.modules['tkinter.filedialog']
    fd.asksaveasfilename = lambda **k: ''

_mock_tkinter()

def _find_reconx_dir():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        if os.path.exists(os.path.join(current, "reconx.py")):
            return current
        current = os.path.dirname(current)
    raise FileNotFoundError(
        "Could not find reconx.py. Place reconx.py anywhere above this file."
    )

sys.path.insert(0, _find_reconx_dir())
from reconx import (
    TargetValidator,
    WHOISLookup,
    DNSEnumerator,
    SubdomainScanner,
    PortScanner,
    HTTPHeaderAnalyser,
    IPGeoLocator,
    DatabaseManager,
    ReconReportExporter,
)

SEP  = "-" * 60
PASS = "  [PASS]"
FAIL = "  [FAIL]"


def print_result(test_name, passed, detail=""):
    status = PASS if passed else FAIL
    line   = f"{status} {test_name}"
    if detail:
        line += f"  ({detail})"
    print(line)

class TestTargetValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 1 — TargetValidator")
        print(SEP)

    def test_01_valid_domain_accepted(self):
        v      = TargetValidator("example.com")
        passed = v.validate() == "example.com"
        print_result("Valid domain accepted", passed)
        self.assertTrue(passed)

    def test_02_https_prefix_stripped(self):
        v      = TargetValidator("https://example.com")
        passed = v.clean == "example.com"
        print_result("https:// prefix stripped", passed, f"got '{v.clean}'")
        self.assertTrue(passed)

    def test_03_http_prefix_and_path_stripped(self):
        v      = TargetValidator("http://example.com/page?q=1")
        passed = v.clean == "example.com"
        print_result("http:// prefix and path stripped", passed, f"got '{v.clean}'")
        self.assertTrue(passed)

    def test_04_www_prefix_stripped(self):
        v      = TargetValidator("www.example.com")
        passed = v.clean == "example.com"
        print_result("www. prefix stripped", passed, f"got '{v.clean}'")
        self.assertTrue(passed)

    def test_05_valid_ipv4_recognised(self):
        v      = TargetValidator("192.168.1.1")
        passed = v.is_ip() is True
        print_result("Valid IPv4 recognised by is_ip()", passed)
        self.assertTrue(passed)

    def test_06_invalid_ip_rejected(self):
        v      = TargetValidator("999.999.999.999")
        passed = v.is_ip() is False
        print_result("Out-of-range IP rejected by is_ip()", passed)
        self.assertTrue(passed)

    def test_07_empty_input_raises_valueerror(self):
        v      = TargetValidator("   ")
        raised = False
        try:
            v.validate()
        except ValueError:
            raised = True
        print_result("Empty input raises ValueError", raised)
        self.assertTrue(raised)

    def test_08_oversized_input_raises_valueerror(self):
        v      = TargetValidator("a" * 254 + ".com")
        raised = False
        try:
            v.validate()
        except ValueError:
            raised = True
        print_result("Input >253 chars raises ValueError", raised)
        self.assertTrue(raised)

    def test_09_garbage_input_raises_valueerror(self):
        v      = TargetValidator("not!!a@@valid##target")
        raised = False
        try:
            v.validate()
        except ValueError:
            raised = True
        print_result("Garbage input raises ValueError", raised)
        self.assertTrue(raised)

    def test_10_is_domain_true_for_domain(self):
        v      = TargetValidator("google.com")
        passed = v.is_domain() is True
        print_result("is_domain() returns True for valid domain", passed)
        self.assertTrue(passed)

    def test_11_is_domain_false_for_ip(self):
        v      = TargetValidator("8.8.8.8")
        passed = v.is_domain() is False
        print_result("is_domain() returns False for IP address", passed)
        self.assertTrue(passed)

    def test_12_subdomain_accepted_as_valid(self):
        v      = TargetValidator("sub.example.com")
        passed = v.is_domain() is True
        print_result("Subdomain recognised as valid domain", passed)
        self.assertTrue(passed)

class TestWHOISLookup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 2 — WHOISLookup")
        print(SEP)

    def test_01_lookup_returns_dict(self):
        w      = WHOISLookup("example.com")
        result = w.lookup()
        passed = isinstance(result, dict)
        print_result("lookup() returns a dict", passed)
        self.assertTrue(passed)

    def test_02_result_has_all_required_keys(self):
        w      = WHOISLookup("example.com")
        result = w.lookup()
        keys   = ["registrar", "creation_date", "expiration_date",
                  "name_servers", "status", "org", "country"]
        passed = all(k in result for k in keys)
        print_result("Result contains all required keys", passed)
        self.assertTrue(passed)

    def test_03_all_no_data_when_library_missing(self):
        import reconx
        original, reconx.whois = reconx.whois, None
        w      = WHOISLookup("example.com")
        result = w.lookup()
        passed = all(v == "No data" for v in result.values())
        reconx.whois = original
        print_result("All fields 'No data' when library unavailable", passed)
        self.assertTrue(passed)

    def test_04_error_set_when_library_missing(self):
        import reconx
        original, reconx.whois = reconx.whois, None
        w = WHOISLookup("example.com")
        w.lookup()
        passed = w.error is not None
        reconx.whois = original
        print_result("Error attribute set when library unavailable", passed,
                     str(w.error)[:40])
        self.assertTrue(passed)

    def test_05_fmt_none_returns_no_data(self):
        passed = WHOISLookup._fmt(None) == "No data"
        print_result("_fmt(None) returns 'No data'", passed)
        self.assertTrue(passed)

    def test_06_fmt_list_deduplicates(self):
        result = WHOISLookup._fmt(["ns1.x.com", "ns1.x.com", "ns2.x.com"])
        passed = result.count("ns1.x.com") == 1
        print_result("_fmt() deduplicates repeated list values", passed,
                     f"'{result}'")
        self.assertTrue(passed)

    def test_07_fmt_empty_string_returns_no_data(self):
        passed = WHOISLookup._fmt("") == "No data"
        print_result("_fmt('') returns 'No data'", passed)
        self.assertTrue(passed)

    def test_08_fmt_valid_string_unchanged(self):
        passed = WHOISLookup._fmt("GoDaddy LLC") == "GoDaddy LLC"
        print_result("_fmt() returns valid string unchanged", passed)
        self.assertTrue(passed)

class TestDNSEnumerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 3 — DNSEnumerator")
        print(SEP)

    def test_01_enumerate_returns_dict(self):
        d      = DNSEnumerator("example.com")
        result = d.enumerate()
        passed = isinstance(result, dict)
        print_result("enumerate() returns a dict", passed)
        self.assertTrue(passed)

    def test_02_result_has_all_five_record_types(self):
        d      = DNSEnumerator("example.com")
        result = d.enumerate()
        passed = all(rt in result for rt in ["A", "MX", "NS", "TXT", "CNAME"])
        print_result("Result has A / MX / NS / TXT / CNAME keys", passed)
        self.assertTrue(passed)

    def test_03_a_record_result_is_list(self):
        d      = DNSEnumerator("example.com")
        result = d.enumerate()
        passed = isinstance(result["A"], list)
        print_result("A record value is a list", passed)
        self.assertTrue(passed)

    def test_04_invalid_domain_gives_no_data(self):
        d      = DNSEnumerator("thisdomain.doesnotexist99999.invalid")
        result = d.enumerate()
        passed = any("No data" in r for r in result["A"])
        print_result("Invalid domain A record returns 'No data'", passed,
                     str(result["A"])[:50])
        self.assertTrue(passed)

    def test_05_default_values_are_no_data(self):
        d      = DNSEnumerator("example.com")
        passed = all(d.results[rt] == ["No data"] for rt in d.RECORD_TYPES)
        print_result("Default results initialised to ['No data']", passed)
        self.assertTrue(passed)

    def test_06_record_types_constant_correct(self):
        passed = DNSEnumerator.RECORD_TYPES == ["A", "MX", "NS", "TXT", "CNAME"]
        print_result("RECORD_TYPES constant is correct", passed)
        self.assertTrue(passed)

class TestScanners(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 4 — SubdomainScanner & PortScanner")
        print(SEP)

    def test_01_wordlist_not_empty(self):
        passed = len(SubdomainScanner.WORDLIST) > 0
        print_result("SubdomainScanner wordlist is not empty", passed,
                     f"{len(SubdomainScanner.WORDLIST)} entries")
        self.assertTrue(passed)

    def test_02_wordlist_contains_www(self):
        passed = "www" in SubdomainScanner.WORDLIST
        print_result("Wordlist contains 'www'", passed)
        self.assertTrue(passed)

    def test_03_scan_returns_list(self):
        s      = SubdomainScanner("invalid-xyz.com", timeout=0.1)
        result = s.scan()
        passed = isinstance(result, list)
        print_result("SubdomainScanner.scan() returns a list", passed)
        self.assertTrue(passed)

    def test_04_dead_host_not_alive(self):
        s      = SubdomainScanner("example.com", timeout=0.1)
        passed = s._is_alive("definitelynotahost.invalid") is False
        print_result("_is_alive() returns False for unreachable host", passed)
        self.assertTrue(passed)

    def test_05_callback_called_for_every_word(self):
        calls = []
        s     = SubdomainScanner("invalid-xyz.com", timeout=0.1,
                                  callback=lambda c, t: calls.append(c))
        s.scan()
        passed = len(calls) == len(SubdomainScanner.WORDLIST)
        print_result("Callback fired for every wordlist entry", passed,
                     f"{len(calls)} calls")
        self.assertTrue(passed)

    def test_06_portscanner_common_ports_populated(self):
        passed = len(PortScanner.COMMON_PORTS) > 0
        print_result("PortScanner.COMMON_PORTS is populated", passed,
                     f"{len(PortScanner.COMMON_PORTS)} ports")
        self.assertTrue(passed)

    def test_07_portscanner_includes_http_80(self):
        passed = 80 in PortScanner.COMMON_PORTS
        print_result("COMMON_PORTS includes port 80 (HTTP)", passed)
        self.assertTrue(passed)

    def test_08_portscanner_includes_https_443(self):
        passed = 443 in PortScanner.COMMON_PORTS
        print_result("COMMON_PORTS includes port 443 (HTTPS)", passed)
        self.assertTrue(passed)

    def test_09_unresolvable_target_returns_empty(self):
        p      = PortScanner("thishost.doesnotexist.invalid", timeout=0.1)
        result = p.scan()
        passed = result == [] and p.error is not None
        print_result("Unresolvable target returns [] with error set", passed,
                     str(p.error)[:40])
        self.assertTrue(passed)

    def test_10_probe_closed_port_returns_none(self):
        p      = PortScanner("127.0.0.1", timeout=0.1)
        result = p._probe(19999, "TEST")
        passed = result is None
        print_result("_probe() returns None for closed port", passed)
        self.assertTrue(passed)

    def test_11_portscanner_error_none_on_init(self):
        p      = PortScanner("example.com")
        passed = p.error is None
        print_result("PortScanner.error is None on initialisation", passed)
        self.assertTrue(passed)

class TestHTTPAndGeo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 5 — HTTPHeaderAnalyser & IPGeoLocator")
        print(SEP)

    def test_01_analyse_returns_dict(self):
        h      = HTTPHeaderAnalyser("example.com")
        result = h.analyse()
        passed = isinstance(result, dict)
        print_result("HTTPHeaderAnalyser.analyse() returns dict", passed)
        self.assertTrue(passed)

    def test_02_result_has_five_required_keys(self):
        h      = HTTPHeaderAnalyser("example.com")
        result = h.analyse()
        passed = all(k in result for k in
                     ["url", "status", "server", "headers", "findings"])
        print_result("Result has url/status/server/headers/findings", passed)
        self.assertTrue(passed)

    def test_03_no_data_status_when_requests_missing(self):
        import reconx
        original, reconx.requests = reconx.requests, None
        h      = HTTPHeaderAnalyser("example.com")
        result = h.analyse()
        passed = result["status"] == "No data"
        reconx.requests = original
        print_result("Status is 'No data' when requests unavailable", passed)
        self.assertTrue(passed)

    def test_04_findings_populated_when_requests_missing(self):
        import reconx
        original, reconx.requests = reconx.requests, None
        h      = HTTPHeaderAnalyser("example.com")
        result = h.analyse()
        passed = isinstance(result["findings"], list) and len(result["findings"]) > 0
        reconx.requests = original
        print_result("Findings populated when requests unavailable", passed)
        self.assertTrue(passed)

    def test_05_security_headers_has_eight_entries(self):
        passed = len(HTTPHeaderAnalyser.SECURITY_HEADERS) >= 8
        print_result("SECURITY_HEADERS contains 8+ entries", passed,
                     f"{len(HTTPHeaderAnalyser.SECURITY_HEADERS)}")
        self.assertTrue(passed)

    def test_06_hsts_flagged_as_high(self):
        sev    = HTTPHeaderAnalyser.SECURITY_HEADERS[
                    "Strict-Transport-Security"][0]
        passed = sev == "HIGH"
        print_result("HSTS missing is HIGH severity", passed)
        self.assertTrue(passed)

    def test_07_csp_flagged_as_high(self):
        sev    = HTTPHeaderAnalyser.SECURITY_HEADERS[
                    "Content-Security-Policy"][0]
        passed = sev == "HIGH"
        print_result("CSP missing is HIGH severity", passed)
        self.assertTrue(passed)

    def test_08_empty_headers_triggers_info_finding(self):
        h         = HTTPHeaderAnalyser("example.com")
        h.headers = {}
        h._check_security_headers()
        passed = any(f["severity"] == "INFO" for f in h.findings)
        print_result("Empty headers set triggers INFO finding", passed)
        self.assertTrue(passed)

    def test_09_package_returns_exact_keys(self):
        h      = HTTPHeaderAnalyser("example.com")
        result = h._package()
        passed = set(result.keys()) == {
            "url", "status", "server", "headers", "findings"}
        print_result("_package() returns exactly 5 required keys", passed)
        self.assertTrue(passed)

    def test_10_geolocator_returns_dict(self):
        g      = IPGeoLocator("example.com")
        result = g.locate()
        passed = isinstance(result, dict)
        print_result("IPGeoLocator.locate() returns dict", passed)
        self.assertTrue(passed)

    def test_11_all_no_data_when_requests_missing(self):
        import reconx
        original, reconx.requests = reconx.requests, None
        g      = IPGeoLocator("example.com")
        result = g.locate()
        passed = all(v == "No data" for v in result.values())
        reconx.requests = original
        print_result("All geo fields 'No data' when requests unavailable", passed)
        self.assertTrue(passed)

    def test_12_invalid_domain_sets_error(self):
        g = IPGeoLocator("thisdomainisnotreal999.invalid")
        g.locate()
        passed = g.error is not None
        print_result("Invalid domain sets error after locate()", passed,
                     str(g.error)[:40])
        self.assertTrue(passed)

class TestDatabaseAndExporter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print(f"\n{SEP}")
        print("  TEST CLASS 6 — DatabaseManager & ReconReportExporter")
        print(SEP)
        cls.tmp  = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp.close()
        cls.db   = DatabaseManager(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.tmp.name)
        except Exception:
            pass

    def test_01_database_file_created(self):
        passed = os.path.exists(self.tmp.name)
        print_result("SQLite database file created on disk", passed)
        self.assertTrue(passed)

    def test_02_all_three_tables_exist(self):
        with sqlite3.connect(self.tmp.name) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        passed = {"scans", "findings", "raw_results"}.issubset(tables)
        print_result("scans / findings / raw_results tables exist", passed,
                     str(tables))
        self.assertTrue(passed)

    def test_03_save_scan_returns_positive_int(self):
        sid    = self.db.save_scan("example.com", ["WHOIS", "DNS"])
        passed = isinstance(sid, int) and sid > 0
        print_result("save_scan() returns positive integer ID", passed,
                     f"id={sid}")
        self.assertTrue(passed)

    def test_04_multiple_scans_get_unique_ids(self):
        sid1   = self.db.save_scan("a.com", ["WHOIS"])
        sid2   = self.db.save_scan("b.com", ["DNS"])
        passed = sid1 != sid2
        print_result("Consecutive scans receive unique IDs", passed,
                     f"ids={sid1},{sid2}")
        self.assertTrue(passed)

    def test_05_save_findings_persists_correctly(self):
        sid = self.db.save_scan("test.com", ["Ports"])
        self.db.save_findings(sid, [
            {"module": "Ports", "severity": "HIGH", "detail": "Port 21 open"}
        ])
        findings = self.db.get_findings_for_scan(sid)
        passed   = (len(findings) == 1 and
                    findings[0]["detail"] == "Port 21 open")
        print_result("save_findings() persists and retrieves correctly", passed)
        self.assertTrue(passed)

    def test_06_save_raw_persists_json(self):
        sid = self.db.save_scan("raw.com", ["HTTP Headers"])
        self.db.save_raw(sid, "HTTP Headers", {"status": "200", "server": "nginx"})
        with sqlite3.connect(self.tmp.name) as conn:
            rows = conn.execute(
                "SELECT data FROM raw_results WHERE scan_id=?", (sid,)
            ).fetchall()
        passed = len(rows) == 1 and "nginx" in rows[0][0]
        print_result("save_raw() persists JSON data correctly", passed)
        self.assertTrue(passed)

    def test_07_get_history_returns_list(self):
        passed = isinstance(self.db.get_history(), list)
        print_result("get_history() returns a list", passed)
        self.assertTrue(passed)

    def test_08_get_history_ordered_most_recent_first(self):
        self.db.save_scan("first.com",  ["WHOIS"])
        self.db.save_scan("second.com", ["DNS"])
        hist   = self.db.get_history()
        passed = hist[0]["id"] > hist[1]["id"]
        print_result("get_history() ordered most-recent first", passed,
                     f"top_id={hist[0]['id']}")
        self.assertTrue(passed)

    def test_09_get_findings_empty_for_new_scan(self):
        sid    = self.db.save_scan("empty.com", ["Ports"])
        result = self.db.get_findings_for_scan(sid)
        passed = result == []
        print_result("get_findings_for_scan() returns [] for new scan", passed)
        self.assertTrue(passed)

    def test_10_csv_export_creates_file(self):
        exp  = ReconReportExporter(
            "example.com",
            {"Ports": [{"port": 22, "service": "SSH", "banner": "OpenSSH"}]},
            [{"module": "Ports", "severity": "HIGH", "detail": "Port 22 open"}]
        )
        path = tempfile.mktemp(suffix=".csv")
        exp.export_csv(path)
        passed = os.path.exists(path)
        print_result("export_csv() creates CSV file on disk", passed)
        if os.path.exists(path): os.unlink(path)
        self.assertTrue(passed)

    def test_11_csv_contains_target_name(self):
        exp  = ReconReportExporter(
            "mytarget.com", {"WHOIS": {"registrar": "GoDaddy"}},
            [{"module": "WHOIS", "severity": "LOW", "detail": "Country: US"}]
        )
        path = tempfile.mktemp(suffix=".csv")
        exp.export_csv(path)
        content = open(path, encoding="utf-8").read()
        passed  = "mytarget.com" in content
        print_result("CSV contains target name", passed)
        if os.path.exists(path): os.unlink(path)
        self.assertTrue(passed)

    def test_12_txt_export_creates_file(self):
        exp  = ReconReportExporter(
            "example.com",
            {"HTTP Headers": {"status": "200"}},
            [{"module": "HTTP Headers", "severity": "HIGH", "detail": "HSTS missing"}]
        )
        path = tempfile.mktemp(suffix=".txt")
        exp.export_txt(path)
        passed = os.path.exists(path)
        print_result("export_txt() creates TXT file on disk", passed)
        if os.path.exists(path): os.unlink(path)
        self.assertTrue(passed)

    def test_13_txt_contains_end_of_report(self):
        exp  = ReconReportExporter("example.com", {}, [])
        path = tempfile.mktemp(suffix=".txt")
        exp.export_txt(path)
        content = open(path, encoding="utf-8").read()
        passed  = "END OF REPORT" in content
        print_result("TXT report contains END OF REPORT footer", passed)
        if os.path.exists(path): os.unlink(path)
        self.assertTrue(passed)

    def test_14_csv_placeholder_when_no_findings(self):
        exp  = ReconReportExporter("example.com", {}, [])
        path = tempfile.mktemp(suffix=".csv")
        exp.export_csv(path)
        content = open(path, encoding="utf-8").read()
        passed  = "No data" in content or "No findings" in content
        print_result("CSV shows placeholder row when no findings exist", passed)
        if os.path.exists(path): os.unlink(path)
        self.assertTrue(passed)

if __name__ == "__main__":
    print("=" * 60)
    print("  ReconX — Unit Test Suite")
    print("  Author  : Animesh Pradhan | SUID: 240309")
    print("  Module  : Programming & Algorithms 2")
    print("  College : Softwarica / Coventry University")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    for cls in [
        TestTargetValidator,
        TestWHOISLookup,
        TestDNSEnumerator,
        TestScanners,
        TestHTTPAndGeo,
        TestDatabaseAndExporter,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(
        verbosity=0, stream=open(os.devnull, "w"))
    result = runner.run(suite)

    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed

    print(f"\n{'=' * 60}")
    print(f"  TOTAL  : {total} tests")
    print(f"  PASSED : {passed}")
    print(f"  FAILED : {failed}")

    if result.failures:
        print("\n  FAILURES:")
        for test, _ in result.failures:
            print(f"    ✘ {test}")
    if result.errors:
        print("\n  ERRORS:")
        for test, _ in result.errors:
            print(f"    ✘ {test}")

    print("=" * 60)