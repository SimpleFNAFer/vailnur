#!/usr/bin/env python3
"""
Generate DVWA (~600 requests) and HackerOne (~5500 requests) CSRF datasets
matching the mitch dataset format exactly.
"""

import json
import csv
import os
import re

# ─── Feature extraction ───────────────────────────────────────────────────────

KEYWORDS = [
    "create", "add", "set", "delete", "update", "remove", "friend",
    "setting", "password", "token", "change", "action", "pay", "login",
    "logout", "post", "comment", "follow", "subscribe", "sign", "view",
]

UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
INT_RE = re.compile(r'^\d+$')
BOOL_VALS = {"true", "false", "on", "off", "1", "0"}


def extract_features(entry):
    req = entry["req"]
    method = req["method"].upper()
    url = req["url"]
    params = req["params"]

    # Parse path from url
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.lower()
    except Exception:
        path = url.lower()

    # Build flat param string (all keys + all values concatenated)
    all_param_tokens = []
    flat_vals = []
    for k, vals in params.items():
        all_param_tokens.append(k.lower())
        for v in vals:
            all_param_tokens.append(str(v).lower())
            flat_vals.append((k, str(v)))
    param_str = " ".join(all_param_tokens)

    num_params = sum(len(v) for v in params.values())
    num_bools = sum(
        1 for _, v in flat_vals if v.lower() in BOOL_VALS
    )
    num_ids = sum(
        1 for _, v in flat_vals
        if INT_RE.match(v) or UUID_RE.match(v)
    )
    num_blobs = sum(1 for _, v in flat_vals if len(v) > 100)

    req_len = sum(
        len(k) + len(v) - 1
        for k, v in flat_vals
    )

    row = {
        "reqId": req["reqId"],
        "flag": entry["flag"],
        "numOfParams": num_params,
        "numOfBools": num_bools,
        "numOfIds": num_ids,
        "numOfBlobs": num_blobs,
        "reqLen": req_len,
    }

    for kw in KEYWORDS:
        row[f"{kw}InPath"] = 1 if kw in path else 0
        row[f"{kw}InParams"] = 1 if kw in param_str else 0

    row["isPUT"] = 1 if method == "PUT" else 0
    row["isDELETE"] = 1 if method == "DELETE" else 0
    row["isPOST"] = 1 if method == "POST" else 0
    row["isGET"] = 1 if method == "GET" else 0
    row["isOPTIONS"] = 1 if method == "OPTIONS" else 0

    return row


CSV_COLUMNS = [
    "reqId", "flag", "numOfParams", "numOfBools", "numOfIds", "numOfBlobs", "reqLen",
    "createInPath", "createInParams", "addInPath", "addInParams",
    "setInPath", "setInParams", "deleteInPath", "deleteInParams",
    "updateInPath", "updateInParams", "removeInPath", "removeInParams",
    "friendInPath", "friendInParams", "settingInPath", "settingInParams",
    "passwordInPath", "passwordInParams", "tokenInPath", "tokenInParams",
    "changeInPath", "changeInParams", "actionInPath", "actionInParams",
    "payInPath", "payInParams", "loginInPath", "loginInParams",
    "logoutInPath", "logoutInParams", "postInPath", "postInParams",
    "commentInPath", "commentInParams", "followInPath", "followInParams",
    "subscribeInPath", "subscribeInParams", "signInPath", "signInParams",
    "viewInPath", "viewInParams",
    "isPUT", "isDELETE", "isPOST", "isGET", "isOPTIONS",
]


def write_dataset(out_dir, dataset_json):
    os.makedirs(out_dir, exist_ok=True)

    # Write compact JSON
    with open(os.path.join(out_dir, "dataset.json"), "w") as f:
        json.dump(dataset_json, f, separators=(",", ":"))

    # Write prettified JSON
    with open(os.path.join(out_dir, "dataset_prettified.json"), "w") as f:
        json.dump(dataset_json, f, indent=4)

    # Extract all entries for CSV
    all_entries = [e for site in dataset_json for e in site["data"]]
    rows = [extract_features(e) for e in all_entries]

    with open(os.path.join(out_dir, "features_matrix.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    return len(all_entries), rows


# ─── ID counter ───────────────────────────────────────────────────────────────

class IdGen:
    def __init__(self, start=1):
        self._n = start

    def next(self):
        v = str(self._n)
        self._n += 1
        return v


def make_req(id_gen, method, url, params, flag, comment=""):
    return {
        "comment": comment,
        "flag": flag,
        "req": {
            "method": method,
            "params": params,
            "reqId": id_gen.next(),
            "url": url,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# DVWA DATASET
# ═══════════════════════════════════════════════════════════════════════════════

BASE = "http://localhost/dvwa"
SEC_LEVELS = ["low", "medium", "high", "impossible"]


def build_dvwa(id_gen):
    entries = []
    E = entries.append

    # ── Static / navigation GETs (safe) ──────────────────────────────────────

    static_pages = [
        "/index.php", "/setup.php", "/instructions.php", "/about.php",
        "/phpinfo.php", "/logout.php", "/login.php",
    ]
    for page in static_pages:
        for _ in range(2):
            E(make_req(id_gen, "GET", f"{BASE}{page}", {}, "n"))

    # Static assets
    static_assets = [
        "/dvwa/css/main.css", "/dvwa/css/login.css",
        "/dvwa/js/dvwaPage.js", "/dvwa/js/add_event_listeners.js",
        "/favicon.ico",
        "/dvwa/images/login_logo.png", "/dvwa/images/RandomStorm.png",
        "/dvwa/images/logo.png",
    ]
    for asset in static_assets:
        E(make_req(id_gen, "GET", f"http://localhost{asset}", {}, "n"))

    # ── Vulnerability pages — GET (safe read) ────────────────────────────────

    vuln_pages = [
        "csrf", "brute", "exec", "fi", "sqli", "sqli_blind",
        "upload", "xss_r", "xss_s", "xss_d", "weak_id",
        "open_redirect", "captcha", "javascript", "csp",
    ]

    for vuln in vuln_pages:
        for level in SEC_LEVELS:
            E(make_req(
                id_gen, "GET",
                f"{BASE}/vulnerabilities/{vuln}/",
                {"security": [level]}, "n",
                f"view {vuln} page at {level} security",
            ))

    # ── Read-only GET params (safe) ───────────────────────────────────────────

    # SQLi id= param browsing
    for i in range(1, 21):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/sqli/",
            {"id": [str(i)], "Submit": ["Submit"]}, "n",
        ))
    for i in range(1, 11):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/sqli_blind/",
            {"id": [str(i)], "Submit": ["Submit"]}, "n",
        ))

    # XSS reflected name= param
    xss_names = ["Alice", "Bob", "test", "<script>alert(1)</script>",
                 "admin", "user123", "John Doe", "']--"]
    for name in xss_names:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/xss_r/",
            {"name": [name]}, "n",
        ))

    # File inclusion page= param
    for page in ["include.php", "file1.php", "file2.php", "file3.php",
                 "../../../etc/passwd", "../../../../../../etc/passwd"]:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/fi/",
            {"page": [page]}, "n",
        ))

    # Open redirect
    for redir in [
        "http://example.com", "/dvwa/index.php",
        "https://evil.com", "//evil.com/path",
    ]:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/open_redirect/",
            {"redirect": [redir]}, "n",
        ))

    # Weak session ID view
    for _ in range(4):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/weak_id/",
            {}, "n",
        ))

    # CSP bypass view
    for _ in range(3):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/csp/",
            {}, "n",
        ))

    # IDS pages
    for i in range(1, 6):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/ids/index.php",
            {"page": [str(i)]}, "n",
        ))

    # OPTIONS preflight
    for endpoint in [
        f"{BASE}/login.php",
        f"{BASE}/vulnerabilities/csrf/",
        f"{BASE}/vulnerabilities/exec/",
        f"{BASE}/security.php",
        f"{BASE}/setup.php",
        f"{BASE}/vulnerabilities/upload/",
        f"{BASE}/vulnerabilities/xss_s/",
    ]:
        E(make_req(id_gen, "OPTIONS", endpoint, {}, "n"))

    # ── CSRF-vulnerable requests ──────────────────────────────────────────────

    # POST login with many username/password combos
    login_combos = [
        ("admin", "password"), ("admin", "admin"), ("admin", "1234"),
        ("admin", "letmein"), ("user", "user"), ("gordonb", "abc123"),
        ("pablo", "letmein"), ("smithy", "password"), ("1337", "charley"),
        ("admin", ""), ("test", "test"), ("root", "root"),
    ]
    for uname, pwd in login_combos:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/login.php",
            {
                "username": [uname],
                "password": [pwd],
                "Login": ["Login"],
                "user_token": [""],
            },
            "y", "login attempt",
        ))

    # GET CSRF vuln password change (low security — pure GET CSRF)
    passwords = [
        "newpass123", "P@ssw0rd!", "letmein", "qwerty123",
        "Sup3rS3cr3t!", "admin123", "changeme", "password1",
        "hunter2", "monkey123", "123456abc", "mitch2024",
    ]
    for pwd in passwords:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/csrf/",
            {
                "password_new": [pwd],
                "password_conf": [pwd],
                "Change": ["Change"],
            },
            "y", "csrf password change via GET (low security)",
        ))

    # POST CSRF vuln password change
    for pwd in passwords:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/csrf/",
            {
                "password_new": [pwd],
                "password_conf": [pwd],
                "Change": ["Change"],
                "user_token": [""],
            },
            "y", "csrf password change via POST",
        ))

    # POST change_password endpoint with empty token (token bypass)
    for pwd in passwords[:6]:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/csrf/change_password",
            {
                "password_new": [pwd],
                "password_conf": [pwd],
                "token": [""],
            },
            "y", "csrf change_password with bypassed token",
        ))

    # POST security.php level change
    for level in SEC_LEVELS:
        for _ in range(4):
            E(make_req(
                id_gen, "POST",
                f"{BASE}/security.php",
                {"seclev_submit": ["Change"], "security": [level], "user_token": [""]},
                "y", f"change security level to {level}",
            ))

    # POST xss_s stored XSS messages
    xss_messages = [
        ("Alice", "Hello world!"),
        ("Bob", "<script>alert('XSS')</script>"),
        ("Eve", "<img src=x onerror=alert(1)>"),
        ("test_user", "Normal message here"),
        ("hacker", "<svg onload=alert(document.cookie)>"),
        ("admin", "Testing stored XSS"),
        ("malicious", "'; DROP TABLE users; --"),
        ("user1", "Just a normal comment"),
        ("x", "A" * 200),
        ("pentester", "<body onload=alert('XSS')>"),
        ("visitor", "Check out http://evil.com"),
        ("anon", "<iframe src=javascript:alert(1)>"),
    ]
    for name, msg in xss_messages:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/xss_s/",
            {
                "txtName": [name],
                "mtxMessage": [msg],
                "btnSign": ["Sign Guestbook"],
            },
            "y", "stored XSS submission",
        ))

    # POST exec command injection
    exec_payloads = [
        "127.0.0.1", "8.8.8.8", "localhost",
        "127.0.0.1; ls", "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | whoami", "127.0.0.1; id",
        "; cat /etc/shadow", "192.168.1.1",
        "$(whoami)", "`id`", "127.0.0.1\ncat /etc/passwd",
    ]
    for payload in exec_payloads:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/exec/",
            {"ip": [payload], "Submit": ["Submit"]},
            "y", "command execution",
        ))

    # POST setup.php create DB
    for i in range(5):
        E(make_req(
            id_gen, "POST",
            f"{BASE}/setup.php",
            {"create_db": ["Create / Reset Database"]},
            "y", "setup database creation",
        ))

    # POST upload
    file_names = [
        "shell.php", "exploit.php", "malware.jpg.php",
        "legit.png", "document.pdf", "test.txt",
        "backdoor.phtml", "..%2F..%2Fetc%2Fpasswd",
    ]
    for fname in file_names:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/upload/",
            {
                "MAX_FILE_SIZE": ["100000"],
                "uploaded": [fname],
                "Upload": ["Upload"],
            },
            "y", "file upload",
        ))

    # POST brute force login
    for uname, pwd in login_combos[:8]:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/brute/",
            {
                "username": [uname],
                "password": [pwd],
                "Login": ["Login"],
            },
            "y", "brute force login",
        ))

    # POST captcha bypass
    for answer in ["", "skip", "bypass", "0", "1"]:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/captcha/",
            {
                "step": ["1"],
                "password_new": ["newpassword"],
                "password_conf": ["newpassword"],
                "recaptcha_response_field": [answer],
                "Change": ["Change"],
            },
            "y", "captcha bypass attempt",
        ))

    # POST javascript vuln with token/phrase
    js_phrases = [
        "success", "ChangeMe", "ZAP", "PHPIDS", "alert(1)",
        "test", "bypass", "token123",
    ]
    for phrase in js_phrases:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/javascript/",
            {
                "token": [""],
                "phrase": [phrase],
                "send": ["Submit"],
            },
            "y", "javascript challenge with empty token",
        ))

    # PUT / DELETE REST-like endpoints (CSRF-vulnerable)
    put_del_endpoints = [
        (f"{BASE}/api/user/1", "PUT", {"username": ["newname"], "email": ["new@example.com"]}),
        (f"{BASE}/api/user/1", "DELETE", {}),
        (f"{BASE}/api/password", "PUT", {"password": ["newpassword"], "user_token": [""]}),
        (f"{BASE}/api/settings", "PUT", {"security": ["low"], "user_token": [""]}),
        (f"{BASE}/api/session", "DELETE", {}),
        (f"{BASE}/api/admin/user/2", "DELETE", {}),
        (f"{BASE}/api/admin/settings", "PUT", {"debug": ["true"]}),
    ]
    for url, method, params in put_del_endpoints:
        E(make_req(id_gen, method, url, params, "y", f"{method} state-changing endpoint"))

    # Additional safe GETs to reach ~400 safe total — repeat vuln pages without params
    extra_safe_urls = [
        f"{BASE}/vulnerabilities/csrf/",
        f"{BASE}/vulnerabilities/xss_s/",
        f"{BASE}/vulnerabilities/exec/",
        f"{BASE}/vulnerabilities/upload/",
        f"{BASE}/vulnerabilities/brute/",
        f"{BASE}/vulnerabilities/captcha/",
        f"{BASE}/vulnerabilities/javascript/",
        f"{BASE}/vulnerabilities/csp/",
        f"{BASE}/vulnerabilities/xss_d/",
        f"{BASE}/vulnerabilities/weak_id/",
    ]
    # Repeat to pad safe count
    for url in extra_safe_urls:
        for _ in range(5):
            E(make_req(id_gen, "GET", url, {}, "n"))

    # More varied safe GETs - pagination
    for page in range(1, 21):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/index.php",
            {"page": [str(page)]}, "n",
        ))

    # More safe GET with search params
    for q in ["admin", "test", "user", "sql", "xss", "csrf", "exec", "upload",
              "brute", "captcha", "dvwa", "php", "injection", "payload"]:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/search.php",
            {"q": [q]}, "n",
        ))

    # More safe view requests — view each vuln page multiple times with different security levels
    for vuln in vuln_pages:
        for level in SEC_LEVELS:
            E(make_req(
                id_gen, "GET",
                f"{BASE}/vulnerabilities/{vuln}/",
                {"security": [level], "view": ["source"]}, "n",
                f"view source for {vuln} at {level}",
            ))

    # Safe GET: browsing help / about / instructions
    for _ in range(6):
        E(make_req(id_gen, "GET", f"{BASE}/instructions.php", {}, "n"))
    for _ in range(6):
        E(make_req(id_gen, "GET", f"{BASE}/about.php", {}, "n"))

    # Safe: more static asset requests
    extra_assets = [
        "/dvwa/css/dvwa.css", "/dvwa/css/bootstrap.css",
        "/dvwa/js/jquery.js", "/dvwa/js/bootstrap.js",
        "/dvwa/images/RandomStorm.png", "/dvwa/images/logo.png",
        "/dvwa/fonts/glyphicons.woff", "/dvwa/fonts/glyphicons.ttf",
    ]
    for asset in extra_assets:
        for _ in range(3):
            E(make_req(id_gen, "GET", f"http://localhost{asset}", {}, "n"))

    # Safe: phpinfo at different levels
    for level in SEC_LEVELS:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/phpinfo.php",
            {"security": [level]}, "n",
        ))

    # Safe: view user account pages
    for uid in range(1, 11):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/weak_id/",
            {"user_id": [str(uid)]}, "n",
        ))

    # Safe: more sqli browsing
    for i in range(21, 41):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/sqli/",
            {"id": [str(i)], "Submit": ["Submit"]}, "n",
        ))

    # Safe: more open_redirect GETs
    redir_targets = [
        "/dvwa/index.php", "/dvwa/about.php",
        "https://www.google.com", "http://example.com",
        "/dvwa/login.php", "/dvwa/logout.php",
        "http://192.168.1.1/", "https://www.bing.com",
    ]
    for redir in redir_targets:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/open_redirect/",
            {"redirect": [redir]}, "n",
        ))

    # Safe: CSP page views
    for i in range(8):
        E(make_req(id_gen, "GET", f"{BASE}/vulnerabilities/csp/", {"id": [str(i + 1)]}, "n"))

    # Safe: XSS DOM page views
    for input_val in ["hello", "world", "test", "alert", "script", "img", "body"]:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/xss_d/",
            {"default": [input_val]}, "n",
        ))

    # More OPTIONS preflights
    for endpoint in [
        f"{BASE}/vulnerabilities/sqli/",
        f"{BASE}/vulnerabilities/fi/",
        f"{BASE}/vulnerabilities/xss_r/",
        f"{BASE}/vulnerabilities/xss_d/",
        f"{BASE}/vulnerabilities/sqli_blind/",
        f"{BASE}/vulnerabilities/weak_id/",
        f"{BASE}/vulnerabilities/open_redirect/",
        f"{BASE}/vulnerabilities/javascript/",
        f"{BASE}/vulnerabilities/csp/",
    ]:
        E(make_req(id_gen, "OPTIONS", endpoint, {}, "n"))

    # More CSRF variants to hit ~170 CSRF total — varied token bypass patterns
    token_patterns = ["", "invalid", "null", "undefined", "0" * 32, "aaaa",
                      "expired_token_abc123", "tampered_xyz", "replay_token_old"]
    for tok in token_patterns:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/csrf/",
            {
                "password_new": ["hacked1"],
                "password_conf": ["hacked1"],
                "Change": ["Change"],
                "user_token": [tok],
            },
            "y", "csrf with manipulated token",
        ))

    # More login POSTs to boost numbers
    extra_creds = [
        ("admin2", "admin2"), ("superuser", "super123"),
        ("dbuser", "dbpass"), ("operator", "ops123"),
        ("manager", "manager1"), ("guest", "guest"),
        ("demouser", "demo1234"), ("readonly", "readonly"),
        ("pentester", "pentest!"), ("auditor", "audit2024"),
    ]
    for uname, pwd in extra_creds:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/login.php",
            {
                "username": [uname],
                "password": [pwd],
                "Login": ["Login"],
                "user_token": [""],
            },
            "y", "login attempt",
        ))

    # More XSS stored variants
    extra_xss = [
        ("trusted_user", "Normal harmless post"),
        ("script_kid", "<script src='https://evil.com/xss.js'></script>"),
        ("advanced", "<details open ontoggle=alert(1)>"),
        ("basic_user", "Just checking in!"),
        ("forum_mod", "Please keep it civil"),
        ("newbie", "First post here!"),
        ("troll", "<marquee onstart=alert(document.cookie)>"),
        ("researcher", "Testing DVWA guestbook"),
    ]
    for name, msg in extra_xss:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/xss_s/",
            {"txtName": [name], "mtxMessage": [msg], "btnSign": ["Sign Guestbook"]},
            "y", "stored XSS submission",
        ))

    # More command exec variants
    extra_exec = [
        "10.0.0.1", "172.16.0.1", "0.0.0.0",
        "127.0.0.1; cat /etc/hostname",
        "127.0.0.1 && ls -la /",
        "1.1.1.1 | id",
        "8.8.4.4",
    ]
    for payload in extra_exec:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/exec/",
            {"ip": [payload], "Submit": ["Submit"]},
            "y", "command execution extra",
        ))

    # More security level changes
    for level in SEC_LEVELS:
        for _ in range(3):
            E(make_req(
                id_gen, "POST",
                f"{BASE}/security.php",
                {"seclev_submit": ["Change"], "security": [level], "user_token": ["old_tok"]},
                "y", f"security level change variant {level}",
            ))

    # More setup.php DB resets
    for _ in range(5):
        E(make_req(
            id_gen, "POST",
            f"{BASE}/setup.php",
            {"create_db": ["Create / Reset Database"]},
            "y", "database reset",
        ))

    # More file uploads
    more_files = [
        "webshell.php5", "cmd.php3", "reverse.php7",
        "image.gif.php", "normal.txt", "report.docx",
    ]
    for fname in more_files:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/upload/",
            {"MAX_FILE_SIZE": ["100000"], "uploaded": [fname], "Upload": ["Upload"]},
            "y", "file upload extra",
        ))

    # More brute force attempts
    extra_brute = [
        ("admin", "iloveyou"), ("gordonb", "password"),
        ("pablo", "pablo"), ("smithy", "12345"),
        ("1337", "1337"), ("test", "admin"),
    ]
    for uname, pwd in extra_brute:
        E(make_req(
            id_gen, "POST",
            f"{BASE}/vulnerabilities/brute/",
            {"username": [uname], "password": [pwd], "Login": ["Login"]},
            "y", "brute force extra",
        ))

    # GET CSRF password change variants (low security)
    extra_pass_get = [
        "Abc123!", "T3stP@ss", "LetMeIn99", "Winter2024!",
        "Spring2024!", "P4ssw0rd", "Admin@123", "Secure!ty",
    ]
    for pwd in extra_pass_get:
        E(make_req(
            id_gen, "GET",
            f"{BASE}/vulnerabilities/csrf/",
            {"password_new": [pwd], "password_conf": [pwd], "Change": ["Change"]},
            "y", "GET csrf password change extra",
        ))

    # POST captcha extra
    for step in ["1", "2"]:
        for answer in ["wrong", "00000", "bypass2", "skip_all"]:
            E(make_req(
                id_gen, "POST",
                f"{BASE}/vulnerabilities/captcha/",
                {
                    "step": [step], "password_new": ["testpass"],
                    "password_conf": ["testpass"],
                    "recaptcha_response_field": [answer],
                    "Change": ["Change"],
                },
                "y", f"captcha bypass step {step}",
            ))

    # Additional PUT/DELETE
    more_rest = [
        (f"{BASE}/api/user/2", "PUT", {"role": ["admin"], "user_token": [""]}),
        (f"{BASE}/api/user/3", "DELETE", {"user_token": [""]}),
        (f"{BASE}/api/admin/flag", "PUT", {"flag": ["true"]}),
        (f"{BASE}/api/admin/maintenance", "POST", {"mode": ["on"]}),
        (f"{BASE}/api/captcha/bypass", "POST", {"bypass": ["true"]}),
    ]
    for url, method, params in more_rest:
        E(make_req(id_gen, method, url, params, "y", f"{method} REST extra"))

    # Safe: more IDS browse pages
    for i in range(6, 21):
        E(make_req(
            id_gen, "GET",
            f"{BASE}/ids/index.php",
            {"page": [str(i)]}, "n",
        ))

    return [{
        "website": "dvwa",
        "data": entries,
    }]


# ═══════════════════════════════════════════════════════════════════════════════
# HACKERONE DATASET
# ═══════════════════════════════════════════════════════════════════════════════

PROGRAMS = [
    # (name, base_url, api_style)
    ("shopify",           "https://shopify.com",                "rest"),
    ("twitter_x",         "https://twitter.com",                "rest"),
    ("gitlab",            "https://gitlab.com",                 "rest"),
    ("uber",              "https://api.uber.com",               "rest"),
    ("hackerone_platform","https://hackerone.com",              "rest"),
    ("yahoo_mail",        "https://mail.yahoo.com",             "rest"),
    ("wordpress_vip",     "https://wpvip.com",                  "rest"),
    ("github",            "https://github.com",                 "rest"),
    ("dropbox",           "https://dropbox.com",                "rest"),
    ("slack",             "https://slack.com",                  "rest"),
    ("stripe",            "https://dashboard.stripe.com",       "rest"),
    ("paypal",            "https://paypal.com",                 "rest"),
    ("airbnb",            "https://airbnb.com",                 "rest"),
    ("pinterest",         "https://pinterest.com",              "rest"),
    ("discord",           "https://discord.com",                "rest"),
    ("microsoft_office365","https://office365.microsoft.com",   "rest"),
    ("google_workspace",  "https://workspace.google.com",       "rest"),
    ("netflix",           "https://netflix.com",                "rest"),
    ("spotify",           "https://spotify.com",                "rest"),
    ("linkedin",          "https://linkedin.com",               "rest"),
    ("mailchimp",         "https://mailchimp.com",              "rest"),
    ("zendesk",           "https://zendesk.com",                "rest"),
    ("atlassian_jira",    "https://jira.atlassian.com",         "rest"),
    ("trello",            "https://trello.com",                 "rest"),
    ("okta",              "https://okta.com",                   "rest"),
    ("twilio",            "https://twilio.com",                 "rest"),
    ("sendgrid",          "https://sendgrid.com",               "rest"),
    ("coinbase",          "https://coinbase.com",               "rest"),
    ("binance",           "https://binance.com",                "rest"),
    ("robinhood",         "https://robinhood.com",              "rest"),
    ("wise_transferwise", "https://wise.com",                   "rest"),
    ("revolut",           "https://revolut.com",                "rest"),
    ("cash_app",          "https://cash.app",                   "rest"),
    ("snapchat",          "https://snapchat.com",               "rest"),
    ("tumblr",            "https://tumblr.com",                 "rest"),
    ("vimeo",             "https://vimeo.com",                  "rest"),
    ("automattic",        "https://automattic.com",             "rest"),
    ("basecamp",          "https://basecamp.com",               "rest"),
    ("asana",             "https://asana.com",                  "rest"),
    ("notion",            "https://notion.so",                  "rest"),
    ("cloudflare",        "https://cloudflare.com",             "rest"),
    ("digitalocean",      "https://digitalocean.com",           "rest"),
    ("heroku",            "https://heroku.com",                 "rest"),
    ("aws_console",       "https://console.aws.amazon.com",     "rest"),
    ("azure_portal",      "https://portal.azure.com",           "rest"),
]


def gen_program_entries(id_gen, name, base, _style):
    """Generate ~120 entries (55% safe, 45% CSRF) for a single program."""
    entries = []
    E = entries.append

    def safe(method, path, params, comment=""):
        E(make_req(id_gen, method, f"{base}{path}", params, "n", comment))

    def csrf(method, path, params, comment=""):
        E(make_req(id_gen, method, f"{base}{path}", params, "y", comment))

    # Common token key per platform
    tok = "authenticity_token"
    if name in ("github", "gitlab", "stripe", "shopify"):
        tok = "authenticity_token"
    elif name in ("wordpress_vip", "automattic"):
        tok = "_wpnonce"
    elif name in ("coinbase", "binance", "robinhood", "wise_transferwise",
                  "revolut", "cash_app"):
        tok = "csrf_token"
    else:
        tok = "_token"

    # ── Safe GETs ─────────────────────────────────────────────────────────────

    safe("GET", "/", {}, "homepage")
    safe("GET", "/dashboard", {}, "user dashboard")
    safe("GET", "/profile", {}, "view own profile")
    safe("GET", "/settings", {}, "settings page")
    safe("GET", "/notifications", {}, "notifications list")
    safe("GET", "/search", {"q": ["test"], "page": ["1"]}, "search")
    safe("GET", "/search", {"q": ["admin"], "limit": ["20"]}, "search admin")
    safe("GET", "/help", {}, "help center")
    safe("GET", "/about", {}, "about page")
    safe("GET", "/privacy", {}, "privacy policy")

    # API read endpoints
    safe("GET", "/api/v1/user", {}, "get current user")
    safe("GET", "/api/v1/user/profile", {"user_id": ["12345"]}, "get user profile")
    safe("GET", "/api/v1/users", {"page": ["1"], "per_page": ["25"]}, "list users")
    safe("GET", "/api/v1/notifications", {"unread": ["true"]}, "get notifications")
    safe("GET", "/api/v1/settings", {}, "get settings")

    # Content read
    safe("GET", "/api/v1/posts", {"page": ["1"]}, "list posts")
    safe("GET", "/api/v1/posts/67890", {}, "view single post")
    safe("GET", "/api/v1/comments", {"post_id": ["67890"]}, "list comments")
    safe("GET", "/api/v1/feed", {"limit": ["50"]}, "activity feed")
    safe("GET", "/api/v1/timeline", {"count": ["20"]}, "timeline")

    # OPTIONS preflight
    safe("OPTIONS", "/api/v1/user", {}, "preflight user")
    safe("OPTIONS", "/api/v1/posts", {}, "preflight posts")
    safe("OPTIONS", "/api/v1/settings", {}, "preflight settings")
    safe("OPTIONS", "/api/v1/auth/login", {}, "preflight login")

    # Social/follow reads
    safe("GET", "/api/v1/followers", {"user_id": ["12345"]}, "get followers")
    safe("GET", "/api/v1/following", {"user_id": ["12345"]}, "get following")
    safe("GET", "/api/v1/friends", {}, "friend list")
    safe("GET", "/api/v1/subscriptions", {}, "subscription list")

    # Auth reads
    safe("GET", "/api/v1/tokens", {}, "list API tokens")
    safe("GET", "/api/v1/oauth/applications", {}, "OAuth apps")
    safe("GET", "/api/v1/mfa/status", {}, "MFA status")
    safe("GET", "/api/v1/ssh-keys", {}, "SSH keys list")

    # Admin reads
    safe("GET", "/api/v1/teams", {}, "list teams")
    safe("GET", "/api/v1/projects", {"page": ["1"]}, "list projects")
    safe("GET", "/api/v1/integrations", {}, "integrations list")
    safe("GET", "/api/v1/audit-log", {"limit": ["100"]}, "audit log")

    # Platform-specific safe GETs
    if name in ("stripe", "paypal", "coinbase", "binance", "robinhood",
                "wise_transferwise", "revolut", "cash_app"):
        safe("GET", "/api/v1/balance", {}, "account balance")
        safe("GET", "/api/v1/transactions", {"limit": ["25"]}, "transactions list")
        safe("GET", "/api/v1/payment-methods", {}, "payment methods")
        safe("GET", "/api/v1/invoices", {"status": ["paid"]}, "invoices")
        safe("GET", "/api/v1/cards", {}, "cards list")
    elif name in ("cloudflare", "digitalocean", "heroku", "aws_console", "azure_portal"):
        safe("GET", "/api/v1/zones", {}, "list DNS zones")
        safe("GET", "/api/v1/firewall/rules", {}, "firewall rules")
        safe("GET", "/api/v1/deployments", {"limit": ["20"]}, "deployments")
        safe("GET", "/api/v1/functions", {}, "serverless functions")
        safe("GET", "/api/v1/webhooks", {}, "webhooks")
    else:
        safe("GET", "/api/v1/analytics", {"from": ["2024-01-01"]}, "analytics")
        safe("GET", "/api/v1/reports", {}, "reports")

    # Extra varied safe GETs
    for i in range(1, 16):
        safe("GET", f"/api/v1/posts/{i * 1000 + 42}", {}, f"view post {i}")

    # Additional safe browsing
    safe("GET", "/api/v1/user/activity",   {"page": ["1"]}, "activity history")
    safe("GET", "/api/v1/user/sessions",   {}, "active sessions")
    safe("GET", "/api/v1/user/preferences",{}, "user preferences")
    safe("GET", "/api/v1/user/connected-apps", {}, "connected apps")
    safe("GET", "/api/v1/security/log",    {"limit": ["50"]}, "security log")
    safe("GET", "/api/v1/search",          {"q": ["report"], "type": ["post"]}, "search posts")
    safe("GET", "/api/v1/tags",            {}, "tag list")
    safe("GET", "/api/v1/trending",        {"period": ["week"]}, "trending content")
    safe("GET", "/api/v1/discover",        {}, "discovery feed")
    safe("GET", "/sitemap.xml",            {}, "sitemap")
    safe("GET", "/robots.txt",             {}, "robots.txt")
    safe("OPTIONS", "/api/v1/follow",      {}, "preflight follow")
    safe("OPTIONS", "/api/v1/messages",    {}, "preflight messages")
    safe("OPTIONS", "/api/v1/tokens",      {}, "preflight tokens")

    for i in range(1, 6):
        safe("GET", f"/api/v1/comments/{i * 111}", {}, f"view comment {i}")
    for i in range(1, 6):
        safe("GET", f"/api/v1/users/{i * 222}", {}, f"view user profile {i}")

    if name in ("stripe", "paypal", "coinbase", "binance", "robinhood",
                "wise_transferwise", "revolut", "cash_app"):
        safe("GET", "/api/v1/exchange-rates", {"base": ["USD"]}, "exchange rates")
        safe("GET", "/api/v1/price-alerts",   {}, "price alerts")
        safe("GET", "/api/v1/portfolio",       {}, "portfolio view")
    elif name in ("cloudflare", "digitalocean", "heroku", "aws_console", "azure_portal"):
        safe("GET", "/api/v1/logs",           {"since": ["1h"]}, "service logs")
        safe("GET", "/api/v1/metrics",        {"metric": ["cpu"]}, "metrics")
        safe("GET", "/api/v1/billing/usage",  {}, "billing usage")

    # ── CSRF POSTs / PUTs / DELETEs ──────────────────────────────────────────

    # Account changes
    csrf("POST", "/api/v1/user/email",
         {"email": ["attacker@evil.com"], tok: [""]}, "change email")
    csrf("POST", "/api/v1/user/email",
         {"email": ["newemail@domain.com"], tok: [""]}, "change email variant")
    csrf("POST", "/api/v1/user/password",
         {"current_password": ["oldpass"], "new_password": ["newpass123"], tok: [""]},
         "change password")
    csrf("POST", "/api/v1/user/password",
         {"new_password": ["P@ssw0rd!"], "confirm_password": ["P@ssw0rd!"], tok: [""]},
         "change password no current")
    csrf("POST", "/api/v1/user/profile",
         {"username": ["new_username"], "bio": ["hacked"], tok: [""]},
         "update profile")
    csrf("PUT",  "/api/v1/user/profile",
         {"display_name": ["Attacker"], "email": ["x@evil.com"], tok: [""]},
         "PUT update profile")
    csrf("POST", "/api/v1/user/username",
         {"username": ["attacker_name"], tok: [""]}, "change username")
    csrf("POST", "/api/v1/user/recovery-email",
         {"recovery_email": ["backup@evil.com"], tok: [""]}, "add recovery email")
    csrf("POST", "/api/v1/user/phone",
         {"phone": ["+15550001234"], tok: [""]}, "add phone number")

    # Auth / tokens
    csrf("POST", "/api/v1/ssh-keys",
         {"title": ["evil-key"], "key": ["ssh-rsa AAAA..."], tok: [""]},
         "add SSH key")
    csrf("DELETE", "/api/v1/oauth/tokens/98765",
         {tok: [""]}, "revoke OAuth token")
    csrf("POST", "/api/v1/tokens",
         {"name": ["evil-token"], "scopes": ["admin"], tok: [""]},
         "create API token")
    csrf("POST", "/api/v1/mfa/disable",
         {"code": [""], tok: [""]}, "disable MFA")
    csrf("POST", "/api/v1/mfa/backup-codes/generate",
         {tok: [""]}, "regenerate backup codes")
    csrf("POST", "/api/v1/oauth/authorize",
         {"client_id": ["evil_app"], "scope": ["read write"], tok: [""]},
         "OAuth authorize evil app")

    # Social actions
    csrf("POST", "/api/v1/follow",
         {"user_id": ["99999"], tok: [""]}, "follow user")
    csrf("DELETE", "/api/v1/follow/99999",
         {tok: [""]}, "unfollow user")
    csrf("POST", "/api/v1/subscribe",
         {"channel_id": ["12345"], tok: [""]}, "subscribe channel")
    csrf("DELETE", "/api/v1/subscribe/12345",
         {tok: [""]}, "unsubscribe")
    csrf("POST", "/api/v1/friends/add",
         {"user_id": ["55555"], tok: [""]}, "add friend")
    csrf("POST", "/api/v1/messages",
         {"to": ["victim@example.com"], "body": ["phishing message"], tok: [""]},
         "send message")
    csrf("POST", "/api/v1/block",
         {"user_id": ["77777"], tok: [""]}, "block user")

    # Content mutations
    csrf("POST", "/api/v1/posts",
         {"title": ["Spam post"], "body": ["Buy cheap pills!"], tok: [""]},
         "create post")
    csrf("PUT",  "/api/v1/posts/67890",
         {"title": ["Hacked"], "body": ["This account was hacked"], tok: [""]},
         "update post")
    csrf("DELETE", "/api/v1/posts/67890",
         {tok: [""]}, "delete post")
    csrf("POST", "/api/v1/posts/67890/publish",
         {tok: [""]}, "publish post")
    csrf("POST", "/api/v1/comments",
         {"post_id": ["67890"], "body": ["CSRF comment"], tok: [""]},
         "submit comment")
    csrf("DELETE", "/api/v1/comments/11111",
         {tok: [""]}, "delete comment")
    csrf("POST", "/api/v1/upload",
         {"filename": ["shell.php"], "content_type": ["image/jpeg"], tok: [""]},
         "upload file")

    # Extra account / auth CSRF
    csrf("POST", "/api/v1/user/avatar",
         {"url": ["https://evil.com/avatar.png"], tok: [""]}, "change avatar")
    csrf("POST", "/api/v1/user/timezone",
         {"timezone": ["UTC"], "locale": ["en_US"], tok: [""]}, "update timezone")
    csrf("POST", "/api/v1/user/close-account",
         {"reason": ["no reason"], tok: [""]}, "close account")
    csrf("POST", "/api/v1/sessions/revoke-all",
         {tok: [""]}, "revoke all sessions")
    csrf("POST", "/api/v1/oauth/revoke",
         {"token": ["access_token_abc"], tok: [""]}, "revoke access token")
    csrf("DELETE", "/api/v1/ssh-keys/key_99",
         {tok: [""]}, "delete SSH key")

    # Extra social CSRF
    csrf("POST", "/api/v1/report",
         {"target_id": ["12345"], "reason": ["spam"], tok: [""]}, "report user")
    csrf("POST", "/api/v1/like",
         {"post_id": ["67890"], tok: [""]}, "like post")
    csrf("DELETE", "/api/v1/like/67890",
         {tok: [""]}, "unlike post")
    csrf("POST", "/api/v1/repost",
         {"post_id": ["67890"], "comment": [""], tok: [""]}, "repost")
    csrf("DELETE", "/api/v1/messages/conv_555",
         {tok: [""]}, "delete message thread")

    # Extra content CSRF
    csrf("PUT",  "/api/v1/posts/67890/visibility",
         {"visibility": ["public"], tok: [""]}, "change post visibility")
    csrf("POST", "/api/v1/posts/67890/pin",
         {tok: [""]}, "pin post")
    csrf("DELETE", "/api/v1/comments/22222",
         {tok: [""]}, "delete comment 2")
    csrf("POST", "/api/v1/articles",
         {"title": ["Injected Article"], "content": ["Malicious content"], tok: [""]},
         "create article")

    # Admin actions
    csrf("POST", "/api/v1/teams/members",
         {"user_id": ["66666"], "role": ["admin"], tok: [""]},
         "add team member")
    csrf("PUT",  "/api/v1/teams/members/66666",
         {"role": ["owner"], tok: [""]}, "change member role")
    csrf("DELETE", "/api/v1/projects/44444",
         {tok: [""]}, "delete project")
    csrf("POST", "/api/v1/integrations",
         {"type": ["webhook"], "url": ["https://evil.com/hook"], tok: [""]},
         "install malicious integration")
    csrf("PUT",  "/api/v1/settings",
         {"two_factor_enabled": ["false"], "login_notifications": ["false"], tok: [""]},
         "disable security settings")
    csrf("POST", "/api/v1/settings/notifications",
         {"email_notifications": ["false"], tok: [""]}, "disable notifications")

    # Extra admin CSRF
    csrf("POST", "/api/v1/invitations",
         {"email": ["attacker@evil.com"], "role": ["admin"], tok: [""]},
         "invite attacker as admin")
    csrf("PUT",  "/api/v1/teams/settings",
         {"public": ["true"], "join_policy": ["open"], tok: [""]},
         "make team public")
    csrf("DELETE", "/api/v1/integrations/webhook_111",
         {tok: [""]}, "remove integration")
    csrf("POST", "/api/v1/export",
         {"format": ["csv"], "include": ["all"], tok: [""]}, "export all data")

    # Platform-specific CSRF
    if name in ("stripe", "paypal", "coinbase", "binance", "robinhood",
                "wise_transferwise", "revolut", "cash_app"):
        csrf("POST", "/api/v1/payment-methods",
             {"type": ["bank_account"], "account_number": ["12345678"],
              "routing_number": ["021000021"], tok: [""]},
             "add payment method")
        csrf("POST", "/api/v1/transfers",
             {"to": ["attacker@evil.com"], "amount": ["1000"], "currency": ["USD"], tok: [""]},
             "initiate transfer")
        csrf("POST", "/api/v1/promotions/apply",
             {"code": ["FREEMONEY"], tok: [""]}, "apply promo code")
        csrf("PUT",  "/api/v1/billing",
             {"plan": ["free"], tok: [""]}, "downgrade billing plan")
        csrf("DELETE", "/api/v1/payment-methods/cc_12345",
             {tok: [""]}, "delete payment method")
    elif name in ("cloudflare", "digitalocean", "heroku", "aws_console", "azure_portal"):
        csrf("POST", "/api/v1/webhooks",
             {"url": ["https://evil.com/hook"], "events": ["*"], tok: [""]},
             "create webhook")
        csrf("PUT",  "/api/v1/zones/example.com/dns",
             {"type": ["A"], "name": ["@"], "content": ["1.2.3.4"], tok: [""]},
             "update DNS record")
        csrf("POST", "/api/v1/firewall/rules",
             {"action": ["allow"], "ip": ["0.0.0.0/0"], tok: [""]},
             "add permissive firewall rule")
        csrf("POST", "/api/v1/functions/deploy",
             {"name": ["evil-function"], "code": ["rm -rf /"], tok: [""]},
             "deploy malicious function")
        csrf("DELETE", "/api/v1/firewall/rules/rule_99",
             {tok: [""]}, "delete firewall rule")
    else:
        csrf("POST", "/api/v1/webhooks",
             {"url": ["https://evil.com/hook"], "secret": [""], tok: [""]},
             "create webhook")
        csrf("PUT",  "/api/v1/billing/plan",
             {"plan_id": ["free"], tok: [""]}, "change billing plan")

    return entries


def build_hackerone(id_gen):
    sites = []
    for name, base, style in PROGRAMS:
        entries = gen_program_entries(id_gen, name, base, style)
        sites.append({"website": name, "data": entries})
    return sites


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    dvwa_dir = "/home/nasy/github.com/SimpleFNAFer/dplm/assets/dwvm"
    h1_dir   = "/home/nasy/github.com/SimpleFNAFer/dplm/assets/hackerone"

    id_gen = IdGen(start=1)

    print("Generating DVWA dataset...")
    dvwa_data = build_dvwa(id_gen)
    dvwa_total, dvwa_rows = write_dataset(dvwa_dir, dvwa_data)

    dvwa_csrf = sum(1 for r in dvwa_rows if r["flag"] == "y")
    dvwa_safe = dvwa_total - dvwa_csrf

    print("Generating HackerOne dataset...")
    h1_data = build_hackerone(id_gen)
    h1_total, h1_rows = write_dataset(h1_dir, h1_data)

    h1_csrf = sum(1 for r in h1_rows if r["flag"] == "y")
    h1_safe = h1_total - h1_csrf

    # ── Verify ─────────────────────────────────────────────────────────────────

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"\nDVWA ({dvwa_dir}):")
    print(f"  Total requests : {dvwa_total}")
    print(f"  CSRF (flag=y)  : {dvwa_csrf}")
    print(f"  Safe (flag=n)  : {dvwa_safe}")

    # Re-read CSV to verify
    import csv as _csv
    with open(f"{dvwa_dir}/features_matrix.csv") as f:
        csv_rows_dvwa = list(_csv.reader(f))
    csv_data_rows = len(csv_rows_dvwa) - 1  # minus header
    print(f"  CSV data rows  : {csv_data_rows} (JSON={dvwa_total}) "
          f"{'MATCH' if csv_data_rows == dvwa_total else 'MISMATCH'}")
    print(f"  CSV columns    : {len(csv_rows_dvwa[0])} "
          f"{'OK' if len(csv_rows_dvwa[0]) == 54 else 'WRONG (expected 54)'}")

    print(f"\nHackerOne ({h1_dir}):")
    print(f"  Programs       : {len(h1_data)}")
    print(f"  Total requests : {h1_total}")
    print(f"  CSRF (flag=y)  : {h1_csrf}")
    print(f"  Safe (flag=n)  : {h1_safe}")

    with open(f"{h1_dir}/features_matrix.csv") as f:
        csv_rows_h1 = list(_csv.reader(f))
    csv_data_rows_h1 = len(csv_rows_h1) - 1
    print(f"  CSV data rows  : {csv_data_rows_h1} (JSON={h1_total}) "
          f"{'MATCH' if csv_data_rows_h1 == h1_total else 'MISMATCH'}")
    print(f"  CSV columns    : {len(csv_rows_h1[0])} "
          f"{'OK' if len(csv_rows_h1[0]) == 54 else 'WRONG (expected 54)'}")

    # Per-program breakdown
    print("\n  Per-program breakdown:")
    for site in h1_data:
        n = len(site["data"])
        c = sum(1 for e in site["data"] if e["flag"] == "y")
        s = n - c
        print(f"    {site['website']:25s}: {n:4d} total  {c:3d} CSRF  {s:3d} safe")


if __name__ == "__main__":
    main()
