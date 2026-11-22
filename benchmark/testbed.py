"""Baseera Sec internal synthetic verification testbed.

Contains intentionally vulnerable and hardened test endpoints; this is not the
official OWASP Benchmark suite and does not establish real-world accuracy.
"""
import os
import re
import html
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

app = FastAPI(title="Baseera Sec Synthetic Verification Testbed", version="1.0.0")

# ==============================================================================
# Category 1: SQL Injection (CWE-89)
# ==============================================================================

# TP 1: String concatenation vulnerable
@app.get("/benchmark/cwe89/case01")
def sqli_case01(name: str = ""):
    if "'" in name or "--" in name:
        return HTMLResponse("<h3>Database Query Error</h3><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near ''' at line 1</p>", status_code=200)
    return HTMLResponse(f"<p>User profile found: {name}</p>")

# TP 2: Numeric parameter vulnerable (testphp.vulnweb style)
@app.get("/benchmark/cwe89/case02")
def sqli_case02(artist: str = "1"):
    if "'" in artist or "OR" in artist.upper():
        return HTMLResponse("<p>Error: Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in /var/www/artists.php on line 62</p>", status_code=200)
    return HTMLResponse(f"<div>Artist ID: {artist} - Picasso Art Works</div>")

# TP 3: Boolean differential blind SQLi
@app.get("/benchmark/cwe89/case03")
def sqli_case03(cat: str = "1"):
    if "AND 1=2" in cat:
        return HTMLResponse("<div>Empty Result</div>") # Stipped content
    # Normal content
    return HTMLResponse("<div>Category 1 Products: <ul><li>Laptop Pro 16 ($1800)</li><li>Wireless Headset ($200)</li><li>Mechanical Keyboard ($120)</li><li>4K UHD Monitor ($450)</li><li>Ergonomic Mouse ($80)</li><li>USB-C Docking Station ($150)</li></ul></div>")

# TP 4: PostgreSQL syntax error
@app.get("/benchmark/cwe89/case04")
def sqli_case04(id: str = "1"):
    if "'" in id:
        return HTMLResponse("<div>PostgreSQL ERROR: syntax error at or near \"'\" at character 45</div>", status_code=200)
    return HTMLResponse(f"<div>Record #{id} retrieved successfully.</div>")

# TP 5: SQLite operational error
@app.get("/benchmark/cwe89/case05")
def sqli_case05(search: str = ""):
    if "'" in search or '"' in search:
        return HTMLResponse("<div>sqlite3.OperationalError: near \"'\": syntax error</div>", status_code=200)
    return HTMLResponse(f"<div>Search results for: {search}</div>")

# TN 1: Secure Parameterized Query
@app.get("/benchmark/cwe89/case06_secure")
def sqli_case06_secure(name: str = ""):
    # Safely handled through prepared statement
    return HTMLResponse(f"<p>Safe user search: {html.escape(name)} (0 records found)</p>")

# TN 2: Integer Casting Protection
@app.get("/benchmark/cwe89/case07_secure")
def sqli_case07_secure(artist: str = "1"):
    clean_id = re.sub(r"[^0-9]", "", artist) or "1"
    return HTMLResponse(f"<div>Artist ID: {clean_id} - Safe Rendered</div>")

# TN 3: Whitelist Allowed Categories
@app.get("/benchmark/cwe89/case08_secure")
def sqli_case08_secure(cat: str = "1"):
    allowed = ["1", "2", "3", "4"]
    val = cat if cat in allowed else "1"
    return HTMLResponse(f"<div>Category {val} - Validated via Whitelist</div>")

# TN 4: Safe ORM
@app.get("/benchmark/cwe89/case09_secure")
def sqli_case09_secure(id: str = "1"):
    return HTMLResponse(f"<div>ORM Query for id={html.escape(id)} safely parameterized.</div>")

# TN 5: Strict Input Validation
@app.get("/benchmark/cwe89/case10_secure")
def sqli_case10_secure(search: str = ""):
    return HTMLResponse(f"<div>Safe token search: {html.escape(search)}</div>")


# ==============================================================================
# Category 2: Cross-Site Scripting (XSS - CWE-79)
# ==============================================================================

# TP 1: Unencoded Reflected parameter
@app.get("/benchmark/cwe79/case01")
def xss_case01(q: str = ""):
    return HTMLResponse(f"<div>Search result for: {q}</div>")

# TP 2: Reflected inside HTML input attribute
@app.get("/benchmark/cwe79/case02")
def xss_case02(username: str = ""):
    return HTMLResponse(f"<form><input name='u' value='{username}'></form>")

# TP 3: Reflected in JavaScript context
@app.get("/benchmark/cwe79/case03")
def xss_case03(msg: str = ""):
    return HTMLResponse(f"<script>let clientMsg = '{msg}';</script>")

# TP 4: Unsanitized comment preview
@app.get("/benchmark/cwe79/case04")
def xss_case04(comment: str = ""):
    return HTMLResponse(f"<article class='comment-body'>{comment}</article>")

# TP 5: Vulnerable error echo
@app.get("/benchmark/cwe79/case05")
def xss_case05(err: str = ""):
    return HTMLResponse(f"<div class='alert-error'>Invalid input: {err}</div>")

# TN 1: Properly HTML Escaped
@app.get("/benchmark/cwe79/case06_secure")
def xss_case06_secure(q: str = ""):
    return HTMLResponse(f"<div>Search result: {html.escape(q)}</div>")

# TN 2: Attribute Encoded
@app.get("/benchmark/cwe79/case07_secure")
def xss_case07_secure(username: str = ""):
    return HTMLResponse(f"<form><input name='u' value='{html.escape(username, quote=True)}'></form>")

# TN 3: JSON Safe Serialization
@app.get("/benchmark/cwe79/case08_secure")
def xss_case08_secure(msg: str = ""):
    return HTMLResponse(f"<div>Safe notification: {html.escape(msg)}</div>")

# TN 4: Content Security Policy + Escaping
@app.get("/benchmark/cwe79/case09_secure")
def xss_case09_secure(comment: str = ""):
    response = HTMLResponse(f"<article>{html.escape(comment)}</article>")
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# TN 5: Strictly Alphanumeric
@app.get("/benchmark/cwe79/case10_secure")
def xss_case10_secure(err: str = ""):
    clean = re.sub(r"[^a-zA-Z0-9 ]", "", err)
    return HTMLResponse(f"<div>Clean error: {clean}</div>")


# ==============================================================================
# Category 3: OS Command Injection (CMDi - CWE-78)
# ==============================================================================

# TP 1: Semicolon command injection
@app.get("/benchmark/cwe78/case01")
def cmdi_case01(host: str = "127.0.0.1"):
    if "baseera_cmdi_proven" in host or "id" in host:
        return PlainTextResponse("PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nuid=1000(bench_user) gid=1000(bench_group) groups=1000\nbaseera_cmdi_proven")
    return PlainTextResponse(f"PING {host} (127.0.0.1) 56(84) bytes: 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms")

# TP 2: Pipe operator command injection
@app.get("/benchmark/cwe78/case02")
def cmdi_case02(ip: str = "127.0.0.1"):
    if "|" in ip or "&" in ip or ";" in ip:
        return PlainTextResponse("Output:\nuid=0(root) gid=0(root) groups=0(root)\nbaseera_cmdi_proven")
    return PlainTextResponse("Host status: active")

# TP 3: Direct command execution parameter
@app.get("/benchmark/cwe78/case03")
def cmdi_case03(cmd: str = "ls"):
    if "baseera_cmdi_proven" in cmd or "id" in cmd:
        return PlainTextResponse("Executed:\nuid=1001(web) gid=1001(web)\nbaseera_cmdi_proven")
    return PlainTextResponse("Directory listing completed.")

# TN 1: Secure Array Execution
@app.get("/benchmark/cwe78/case04_secure")
def cmdi_case04_secure(host: str = "127.0.0.1"):
    clean_ip = re.sub(r"[^0-9\.]", "", host)
    return PlainTextResponse(f"PING {clean_ip} status: OK")

# TN 2: Whitelist IP validation
@app.get("/benchmark/cwe78/case05_secure")
def cmdi_case05_secure(ip: str = "127.0.0.1"):
    return PlainTextResponse("Validated host: 127.0.0.1")


# ==============================================================================
# Category 4: Path Traversal & LFI (CWE-22)
# ==============================================================================

# TP 1: Unsanitized /etc/passwd disclosure
@app.get("/benchmark/cwe22/case01")
def traversal_case01(file: str = "index.html"):
    if "passwd" in file:
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nbench:x:1000:1000:Benchmark:/home/bench:/bin/bash")
    return PlainTextResponse("Welcome to Baseera Documentation Index.")

# TP 2: Page template traversal
@app.get("/benchmark/cwe22/case02")
def traversal_case02(page: str = "home"):
    if "passwd" in page or "win.ini" in page:
        return PlainTextResponse("[fonts]\n[extensions]\nroot:x:0:0:root:/root:/bin/bash")
    return PlainTextResponse("Content for page: " + page)

# TN 1: Safe os.path.basename
@app.get("/benchmark/cwe22/case03_secure")
def traversal_case03_secure(file: str = "index.html"):
    safe_name = os.path.basename(file)
    return PlainTextResponse(f"Safe File Render: {safe_name}")

# TN 2: Whitelisted file map
@app.get("/benchmark/cwe22/case04_secure")
def traversal_case04_secure(page: str = "home"):
    allowed = {"home": "Home Page Content", "about": "About Page Content"}
    return PlainTextResponse(allowed.get(page, "Home Page Content"))


# ==============================================================================
# Category 5: Server-Side Request Forgery (SSRF - CWE-918)
# ==============================================================================

# TP 1: Unrestricted URL fetch reflecting AWS metadata
@app.get("/benchmark/cwe918/case01")
def ssrf_case01(url: str = ""):
    if "169.254.169.254" in url:
        return PlainTextResponse("ami-id: ami-0c55b159cbfafe1f0\ninstance-id: i-0123456789abcdef0\nsecurity-credentials: BaseeraSecRole")
    if "127.0.0.1" in url or "localhost" in url:
        return PlainTextResponse('{"status": "ok", "service": "Baseera Sec Internal API", "port": 8765}')
    return PlainTextResponse("Proxy fetched: " + url)

# TN 1: Domain Whitelist enforcement
@app.get("/benchmark/cwe918/case02_secure")
def ssrf_case02_secure(url: str = ""):
    if "example.com" in url:
        return PlainTextResponse("Fetched verified safe domain: example.com")
    return PlainTextResponse("Access Denied: Domain not in allowlist", status_code=403)


# ==============================================================================
# Category 6: Security Misconfigurations (CWE-16 / CORS / Clickjacking)
# ==============================================================================

# TP 1: Vulnerable CORS wildcard with credentials
@app.get("/benchmark/cwe16/cors_vuln")
def cors_vuln(request: Request):
    origin = request.headers.get("origin", "*")
    response = HTMLResponse("<div>User Dashboard with Secret Financial Data</div>")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# TP 2: Clickjacking Vulnerable (No X-Frame-Options or frame-ancestors)
@app.get("/benchmark/cwe16/clickjacking_vuln")
def clickjacking_vuln():
    return HTMLResponse("<div>Transfer Funds Confirmation Button (Embeddable in Iframe)</div>")

# TN 1: Hardened Headers (Protected against CORS & Clickjacking)
@app.get("/benchmark/cwe16/hardened_secure")
def hardened_secure():
    response = HTMLResponse("<div>Hardened Bank Portal</div>")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Backward Compatibility Route Aliases
@app.get("/benchmark/misc/case01_cors")
def misc_case01_cors(request: Request):
    return cors_vuln(request)

@app.get("/benchmark/misc/case02_env/.env")
def misc_case02_env():
    return PlainTextResponse("DB_PASSWORD=secret_prod_database_pw_9921\nAPP_KEY=baseera_secret_key_12345")

@app.get("/benchmark/misc/case03_secure")
def misc_case03_secure():
    return hardened_secure()
