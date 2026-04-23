import os 
import re 
from datetime import datetime, timezone
from pathlib import Path    

from flask import Flask, request, make_response 
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import ujson as json
except Exception:
    import json 

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

APP_NAME = "simple-web-honeypot"
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

BANNER = os.getenv("HONEYPOT_BANNER", "Apache/2.4.41 (Ubuntu)")
MAX_BODY_LOG = int(os.getenv("MAX_BODY_LOG", "2048"))

SIGS = {
    "sqli": re.compile(r"(?i)\b(select|union|sleep\(|or\s+1\s*=\s*1|'\s*or\s*'1'='1)"),
    "xss": re.compile(r"(?i)(<script|onerror=|javascript:|<img\s+src|<svg)"),
    "path_traversal": re.compile(r"(\.\./|/etc/passwd|/proc/self/environ)"),
    "rfi_lfi": re.compile(r"(?i)(http(s)?://|php://|file://)"),
    "cmd_injection": re.compile(r"(?i)(;|&&|\|\|)\s*(cat|ls|id|whoami|curl|wget)"),
    "wp_probe": re.compile(r"(?i)(/wp-login\.php|/wp-admin|/xmlrpc\.php)"),
    "php_probe": re.compile(r"(?i)\.php($|\?|/)"),
    "admin_probe": re.compile(r"(?i)/admin($|/|\?)"),
    "env_probe": re.compile(r"(?i)/\.env($|/|\?)"),
    "git_probe": re.compile(r"(?i)/\.git/"),
}

def log_event(data: dict):
    ts_day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_path = LOG_DIR / f"honeypot-{ts_day}.jsonl"
    line = json.dumps(data, ensure_ascii=False)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def detect_signatures(path, query_str, body_text, headers):
    text = f"{path} {query_str} {body_text} {headers.get('User-Agent', '')}"
    matches = []
    for name, rx in SIGS.items():
        if rx.search(text):
            matches.append(name)
    return sorted(set(matches))

def common_response(status=200, body="", headers=None):
    resp = make_response(body, status)
    if "Content-Type" not in resp.headers:
        resp.headers["Content-Type"] = "text/html; charset=UTF-8"
    if "Server" not in resp.headers:
        resp.headers["Server"] = BANNER
    if headers:
        for k, v in headers.items():
            resp.headers[k] = v
    return resp

def capture_request(label: str, extra: dict = None, status = 200, body="", headers=None):
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "-")
    ref = request.headers.get("Referer", "-")
    method = request.method

    path_disp = request.path
    query_str = request.query_string.decode("utf-8", errors="ignore")
    if query_str:
        full_path = f"{path_disp}?{query_str}"
    else:
        full_path = path_disp
    
    body_raw = ""
    try:
        body_raw = request.get_data(as_text=True, cache=False) or ""
        if len(body_raw) > MAX_BODY_LOG:
            body_raw = body_raw[:MAX_BODY_LOG] + "...[truncated]"
    except Exception:
        body_raw = "[unreadable]"

    sigs = detect_signatures(request.path, query_str, body_raw, request.headers)

    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "app": APP_NAME,
        "label": label,
        "src_ip": ip,
        "method": method,
        "path": request.path,
        "query": query_str,
        "full_path": full_path,
        "user_agent": ua,
        "referer": ref,
        "headers": {
            "accept": request.headers.get("Accept"),
            "content_type": request.headers.get("Content-Type"),
            "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        },
        "body_sample": body_raw,
        "signatures": sigs,
        "status": status,
    }
    if extra:
        event.update(extra)

    log_event(event)
    return common_response(status=status, body=body, headers=headers)

# ---- Endpoints ----

@app.route("/", methods=["GET"])
def index():
    body = "<h1>Welcome</h1><p>Server is running.</p>"
    return capture_request("root", status=200, body=body)

@app.route("/healthz", methods=["GET"])
def health():
    return capture_request("healthz", status=200, body="OK")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        body = """
        <h2>Login</h2>
        <form method="POST">
            <input name="username" placeholder="user"><br>
            <input name="password" type="password" placeholder="pass"><br>
            <button type="submit">Sign In</button>
        </form>
        """
        return capture_request("login_form", status=200, body=body)
    
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    body = "Invalid username or password."
    extra = {"auth_attempt": True, "username": username[:64], "password_len": len(password)}

    sigs = detect_signatures(request.path, request.query_string.decode("utf-8", "ignore"), request.get_data(as_text=True), request.headers)
    if "sqli" in sigs:
        body = "SQLSTATE[42000]: Syntax error or access violation"
        return capture_request("login_sql_error", extra=extra, status=500, body=body)
    return capture_request("login_failed", extra=extra, status=401, body=body)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "GET":
        body = "<h2>Admin Panel</h2><p>Authentication required.</p>"
        return capture_request("admin_probe", status=401, body=body, headers={"WWW-Authenticate": 'Basic realm="admin"'})
    return capture_request("admin_post", status=403, body="Forbidden")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        body = """
        <h3>Upload</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <button type="submit">Upload</button>
        </form>
        """
        return capture_request("upload_form", status=200, body=body)
    files = list(request.files.keys())
    extra = {"files": files, "uploaded_count": len(files)}
    return capture_request("upload_ok", extra=extra, status=200, body="File uploaded")

@app.route("/api/search", methods=["GET"])
def api_search():
    q = request.args.get("q", "")
    if SIGS["sqli"].search(q):
        return capture_request("api_search_sqli", status=500, body="database error: near 'SELECT'")
    if SIGS["xss"].search(q):
        return capture_request("api_search_xss", status=400, body="Invalid query parameter")
    return capture_request("api_search", status=200, body=f'{{"results": [],"q": "{q}"}}', headers={"Content-Type": "application/json"})

@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    body = "Invalid username"
    return capture_request("wp_login", status=200, body=body)

@app.route("/xmlrpc.php", methods=["POST", "GET"])
def xmlrpc():
    return capture_request("xmlrpc_probe", status=200, body="XML-RPC server accepts POST  requests only")

@app.route("/.git/config", methods=["GET"])
def git_config():
    return capture_request("git_config_probe", status=403, body="Forbidden")

@app.route("/.env", methods=["GET"])
def dot_env():
    return capture_request("env_probe", status=403, body="Forbidden")

@app.errorhandler(404)
def not_found(e):
    return capture_request("not_found", status=404, body="Not Found")

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
