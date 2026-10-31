#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Try importing jwt; notify if missing
try:
    import jwt
except ImportError:
    jwt = None

VERSION = "2.3.3"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
AUTH_FILE = os.path.join(BASE_DIR, "auth.json")
LOGS_FILE = os.path.join(BASE_DIR, "logs.json")
ALIAS_FILE = os.path.join(BASE_DIR, "alias.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
SERVER_PID_FILE = os.path.join(BASE_DIR, "server.pid")

DEFAULT_API_URL = "https://urltooljson--togoze7nqe8c.replit.app/api/get-url"
HEALTHZ_URL = "https://urltooljson--togoze7nqe8c.replit.app/api/healthz"
UPSTREAM_PROXY_DEFAULT = "http://localhost:5000"

# --- HELPER FUNCTIONS ---

def ask(prompt_text):
    try:
        return input(prompt_text).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(1)

def output_result(data, is_json):
    if is_json:
        print(json.dumps(data, indent=2))
    else:
        if isinstance(data, (dict, list)):
            print(json.dumps(data, indent=2))
        else:
            print(data)

def handle_error(msg, global_opts):
    if getattr(global_opts, 'html_errors', False):
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Error - xdg-tool</title>
  <style>
    body {{ font-family: sans-serif; background: #f8d7da; color: #721c24; padding: 2rem; }}
    .error-box {{ background: #fff; border: 1px solid #f5c6cb; padding: 1.5rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="error-box">
    <h1>xdg-tool Error</h1>
    <p>{msg}</p>
  </div>
</body>
</html>"""
        print(html)
    else:
        print(f"Error: {msg}")

    if getattr(global_opts, 'stacktrace', False):
        raise RuntimeError(msg)

def check_logged_in(force=False, global_opts=None):
    if force or getattr(global_opts, 'force', False):
        return {"loggedIn": True}

    if not os.path.exists(AUTH_FILE):
        msg = "Not registered."
        handle_error(msg, global_opts)
        sys.exit(1)

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    if not auth.get("loggedIn"):
        msg = "Not logged in. Please run 'xdg-tool auth login' first."
        handle_error(msg, global_opts)
        sys.exit(1)
    return auth

def record_log(cmd_str, output, success):
    logs = []
    if os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    log_entry = {
        "id": os.urandom(4).hex(),
        "command": cmd_str,
        "output": output.strip(),
        "success": success,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    logs.append(log_entry)

    with open(LOGS_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def generate_jwt(payload, secret):
    if jwt:
        return jwt.encode(payload, secret, algorithm="HS256")
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hashlib.sha256(f"{header}.{body}.{secret}".encode()).hexdigest()
    return f"{header}.{body}.{signature}"

def verify_jwt(token_str, secret):
    if jwt:
        return jwt.decode(token_str, secret, algorithms=["HS256"])
    parts = token_str.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    header_b64, body_b64, sig = parts
    padding = '=' * (-len(body_b64) % 4)
    body_data = json.loads(base64.urlsafe_b64decode(body_b64 + padding).decode())
    expected_sig = hashlib.sha256(f"{header_b64}.{body_b64}.{secret}".encode()).hexdigest()
    if sig != expected_sig:
        raise ValueError("Signature verification failed")
    return body_data

# --- SERVER & PROXY IMPLEMENTATION ---

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class ProxyHandler(BaseHTTPRequestHandler):
    upstream_url = UPSTREAM_PROXY_DEFAULT
    start_time = time.time()

    def do_PROXY(self):
        if self.path.startswith("/api/"):
            target = f"{self.upstream_url}{self.path}"
            print(f"[Proxy] Forwarding {self.command} {self.path} to {target}")

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            headers = {k: v for k, v in self.headers.items()}

            req = urllib.request.Request(target, data=body, headers=headers, method=self.command)
            try:
                with urllib.request.urlopen(req) as response:
                    self.send_response(response.status)
                    for k, v in response.headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(response.read())
            except urllib.error.HTTPError as e:
                self.send_response(e.code)
                for k, v in e.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(e.read())
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                err_resp = json.dumps({"error": "Upstream Proxy Error", "details": str(e)})
                self.wfile.write(err_resp.encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        res_data = {
            "status": "running",
            "version": VERSION,
            "uptime": time.time() - self.start_time,
            "proxyRouteSupported": "/api/*"
        }
        self.wfile.write(json.dumps(res_data).encode())

    def do_GET(self): self.do_PROXY()
    def do_POST(self): self.do_PROXY()
    def do_PUT(self): self.do_PROXY()
    def do_DELETE(self): self.do_PROXY()
    def do_PATCH(self): self.do_PROXY()

def start_server(args, global_opts):
    port = int(args.port or args.bind or 5000)
    address = args.address or "0.0.0.0"
    upstream = args.upstream or UPSTREAM_PROXY_DEFAULT

    ProxyHandler.upstream_url = upstream
    server_address = (address, port)

    try:
        httpd = ThreadedHTTPServer(server_address, ProxyHandler)
        print(f"xdg-tool local server running on http://{address}:{port}")
        print(f"Upstream proxy route enabled at http://{address}:{port}/api/ -> {upstream}")

        with open(SERVER_PID_FILE, "w") as f:
            json.dump({"pid": os.getpid(), "port": port, "address": address, "upstream": upstream}, f)

        httpd.serve_forever()
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)

def check_server_status(args, global_opts):
    port = args.port or 5000
    url = f"http://localhost:{port}/"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Server is running successfully.")
            print(json.dumps(data, indent=2))
    except Exception:
        print("Error: Connection refused. Server is not running or unreachable.")
        sys.exit(1)

def stop_server(args, global_opts):
    port = args.port or 5000
    if os.path.exists(SERVER_PID_FILE):
        try:
            with open(SERVER_PID_FILE, "r") as f:
                info = json.load(f)
            os.kill(info["pid"], 15)
            os.remove(SERVER_PID_FILE)
            print(f"Server stopped (PID: {info['pid']}).")
        except Exception:
            print("Could not gracefully stop server via PID file. Attempting port kill...")

    try:
        subprocess.run(f"fuser -k {port}/tcp", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        print(f"Successfully cleared port {port}.")
    except Exception:
        print(f"No active process found running on port {port}.")

# --- COMMAND HANDLERS ---

def cmd_info(args, global_opts):
    info_data = {
        "version": VERSION,
        "upstreamProxyDefault": UPSTREAM_PROXY_DEFAULT,
        "defaultApiUrl": DEFAULT_API_URL,
        "configPath": CONFIG_FILE,
        "authPath": AUTH_FILE
    }
    if global_opts.json:
        output_result(info_data, True)
    else:
        print("--- xdg-tool Information ---")
        print(f"Version                 : {VERSION}")
        print(f"Upstream Proxy Default  : {UPSTREAM_PROXY_DEFAULT}")
        print(f"Default API URL         : {DEFAULT_API_URL}")
        print(f"Config File Path        : {CONFIG_FILE}")
        print(f"Auth File Path          : {AUTH_FILE}")

def cmd_account(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        print("Account status: Not registered.")
        return
    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    info = {
        "registered": True,
        "loggedIn": auth.get("loggedIn", False),
        "createdAt": auth.get("createdAt", "N/A"),
        "lastLogin": auth.get("lastLogin", "N/A"),
        "tokenSnippet": f"{auth['token'][:15]}..." if auth.get("token") else "None"
    }

    if global_opts.json:
        output_result(info, True)
    else:
        print("--- Account Information ---")
        print(f"Status       : {'Logged In' if auth.get('loggedIn') else 'Logged Out'}")
        print(f"Created At   : {info['createdAt']}")
        print(f"Last Login   : {info['lastLogin']}")
        print(f"Token Prefix : {info['tokenSnippet']}")

def auth_register(args, global_opts):
    if os.path.exists(AUTH_FILE):
        handle_error("Already registered. Use 'xdg-tool auth reset' or 'xdg-tool auth remove'.", global_opts)
        return

    pin1 = ask("Enter new PIN: ")
    pin2 = ask("Confirm new PIN: ")

    if pin1 != pin2:
        handle_error("PINs do not match.", global_opts)
        return

    secret = os.urandom(32).hex()
    with open(SECRET_FILE, "w") as f:
        f.write(secret)

    pin_hash = hashlib.sha256(pin1.encode()).hexdigest()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    token = generate_jwt({"user": "local", "exp": int(time.time()) + 7*86400}, secret)

    auth_data = {
        "pinHash": pin_hash,
        "token": token,
        "loggedIn": False,
        "createdAt": now,
        "lastLogin": None,
        "updatedAt": now
    }

    with open(AUTH_FILE, "w") as f:
        json.dump(auth_data, f, indent=2)

    if global_opts.json:
        output_result({"success": True, "message": "Registration successful."}, True)
    else:
        print("Registration successful.")

def auth_login(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Register first.", global_opts)
        return

    pin = ask("Enter PIN: ")
    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    if hashlib.sha256(pin.encode()).hexdigest() != auth["pinHash"]:
        handle_error("invalid pin", global_opts)
        return

    auth["loggedIn"] = True
    auth["lastLogin"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with open(AUTH_FILE, "w") as f:
        json.dump(auth, f, indent=2)

    if global_opts.json:
        output_result({"success": True, "message": "Login successful.", "token": auth["token"]}, True)
    else:
        print("Login successful.")
        print("JWT Token:")
        print(auth["token"])

def auth_logout(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Not registered.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    auth["loggedIn"] = False
    with open(AUTH_FILE, "w") as f:
        json.dump(auth, f, indent=2)

    if global_opts.json:
        output_result({"success": True, "message": "Logged out successfully."}, True)
    else:
        print("Logged out successfully.")

def auth_status(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Not registered.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    status_str = "Logged In" if auth.get("loggedIn") else "Logged Out"
    if global_opts.json:
        output_result({"loggedIn": auth.get("loggedIn"), "status": status_str}, True)
    else:
        print(status_str)

def auth_token(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("No token.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    if global_opts.json:
        output_result({"token": auth.get("token")}, True)
    else:
        print(auth.get("token"))

def auth_verify(args, global_opts):
    if not os.path.exists(AUTH_FILE) or not os.path.exists(SECRET_FILE):
        handle_error("No authentication data.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)
    with open(SECRET_FILE, "r") as f:
        secret = f.read().strip()

    try:
        decoded = verify_jwt(auth["token"], secret)
        if global_opts.json:
            output_result({"verified": True, "decoded": decoded}, True)
        else:
            print("Token verified successfully.")
            print(decoded)
    except Exception:
        handle_error("Invalid or expired token.", global_opts)

def auth_reset_pin(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Not registered.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    current_pin = ask("Enter current PIN: ")
    if hashlib.sha256(current_pin.encode()).hexdigest() != auth["pinHash"]:
        handle_error("invalid pin", global_opts)
        return

    pin1 = ask("Enter new PIN: ")
    pin2 = ask("Confirm new PIN: ")

    if pin1 != pin2:
        handle_error("PINs do not match.", global_opts)
        return

    secret = os.urandom(32).hex()
    with open(SECRET_FILE, "w") as f:
        f.write(secret)

    pin_hash = hashlib.sha256(pin1.encode()).hexdigest()
    token = generate_jwt({"user": "local", "exp": int(time.time()) + 7*86400}, secret)

    auth["pinHash"] = pin_hash
    auth["token"] = token
    auth["loggedIn"] = True
    auth["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with open(AUTH_FILE, "w") as f:
        json.dump(auth, f, indent=2)

    if global_opts.json:
        output_result({"success": True, "message": "PIN and session reset successfully."}, True)
    else:
        print("PIN and session reset successfully.")

def auth_switch(args, global_opts):
    print("--- Switch Session / PIN ---")
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, "r") as f:
            auth = json.load(f)
        pin = ask("Enter current PIN to switch: ")
        if hashlib.sha256(pin.encode()).hexdigest() != auth["pinHash"]:
            handle_error("invalid pin", global_opts)
            return
    auth_reset_pin(args, global_opts)

def auth_remove(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Not registered.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    if not getattr(args, 'force', False):
        pin = ask("Enter PIN to remove account: ")
        if hashlib.sha256(pin.encode()).hexdigest() != auth["pinHash"]:
            handle_error("invalid pin", global_opts)
            return

        confirmation = ask("Type REMOVE to continue: ")
        if confirmation != "REMOVE":
            handle_error("Removal cancelled.", global_opts)
            return

    if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
    if os.path.exists(SECRET_FILE): os.remove(SECRET_FILE)

    if global_opts.json:
        output_result({"success": True, "message": "Account and authentication data removed successfully."}, True)
    else:
        print("Account and authentication data removed successfully.")

def auth_list(args, global_opts):
    if not os.path.exists(AUTH_FILE):
        handle_error("Not registered.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)

    meta = {
        "loggedIn": auth.get("loggedIn"),
        "createdAt": auth.get("createdAt", "N/A"),
        "lastLogin": auth.get("lastLogin", "N/A"),
        "updatedAt": auth.get("updatedAt", "N/A")
    }

    if global_opts.json:
        output_result(meta, True)
    else:
        print("--- Authentication Metadata ---")
        print(f"Status     : {'Logged In' if meta['loggedIn'] else 'Logged Out'}")
        print(f"Created At : {meta['createdAt']}")
        print(f"Last Login : {meta['lastLogin']}")
        print(f"Updated At : {meta['updatedAt']}")

def auth_whoami(args, global_opts):
    if not os.path.exists(AUTH_FILE) or not os.path.exists(SECRET_FILE):
        handle_error("No authentication data found.", global_opts)
        return

    with open(AUTH_FILE, "r") as f:
        auth = json.load(f)
    with open(SECRET_FILE, "r") as f:
        secret = f.read().strip()

    try:
        decoded = verify_jwt(auth["token"], secret)
        exp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(decoded.get("exp", 0))) if decoded.get("exp") else "N/A"
        info = {
            "user": decoded.get("user"),
            "session": "Active" if auth.get("loggedIn") else "Inactive",
            "expiresAt": exp_str
        }
        if global_opts.json:
            output_result(info, True)
        else:
            print("--- Who Am I ---")
            print(f"User       : {info['user']}")
            print(f"Session    : {info['session']}")
            print(f"Expires At : {info['expiresAt']}")
    except Exception:
        handle_error("Invalid or expired token session.", global_opts)

def cmd_execute(args, global_opts):
    command_to_run = args.cmd_arg or args.command
    if not command_to_run:
        command_to_run = ask("Enter command to execute: ")

    if not command_to_run:
        print("No command provided.")
        return

    print(f"Executing via bash -c: {command_to_run}")

    proc = subprocess.Popen(["bash", "-c", command_to_run], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate()

    output = stdout + (f"\nStderr: {stderr}" if stderr else "")
    success = (proc.returncode == 0)

    if stdout: print(stdout, end="")
    if stderr: print(stderr, end="")

    if not success:
        print(f"Execution error: Command returned exit code {proc.returncode}")

    record_log(command_to_run, output, success)

    if global_opts.json:
        output_result({"success": success, "command": command_to_run, "output": output}, True)

def logs_list(args, global_opts):
    if not os.path.exists(LOGS_FILE):
        print("No logs found.")
        return
    with open(LOGS_FILE, "r") as f:
        logs = json.load(f)
    if global_opts.json:
        output_result(logs, True)
    else:
        for l in logs:
            print(f"[{l['id']}] {l['timestamp']} - {'SUCCESS' if l['success'] else 'FAILED'} : {l['command']}")

def logs_view(args, global_opts):
    if not os.path.exists(LOGS_FILE):
        print("No logs found.")
        return
    with open(LOGS_FILE, "r") as f:
        logs = json.load(f)
    log = next((l for l in logs if l["id"] == args.id), None)
    if not log:
        print(f"Log with ID {args.id} not found.")
        return
    if global_opts.json:
        output_result(log, True)
    else:
        print(f"--- Log ID: {log['id']} ---")
        print(f"Timestamp : {log['timestamp']}")
        print(f"Command   : {log['command']}")
        print(f"Success   : {log['success']}")
        print(f"Output    :\n{log['output']}")

def logs_exec(args, global_opts):
    if not os.path.exists(LOGS_FILE):
        print("No logs found.")
        return
    with open(LOGS_FILE, "r") as f:
        logs = json.load(f)
    log = next((l for l in logs if l["id"] == args.id), None)
    if not log:
        print(f"Log with ID {args.id} not found.")
        return
    print(f"Re-executing: {log['command']}")
    args.cmd_arg = log['command']
    args.command = None
    cmd_execute(args, global_opts)

def logs_delete(args, global_opts):
    if not os.path.exists(LOGS_FILE):
        print("No logs found.")
        return
    with open(LOGS_FILE, "r") as f:
        logs = json.load(f)
    initial_len = len(logs)
    logs = [l for l in logs if l["id"] != args.id]
    if len(logs) == initial_len:
        print(f"Log ID {args.id} not found.")
        return
    with open(LOGS_FILE, "w") as f:
        json.dump(logs, f, indent=2)
    print(f"Log {args.id} deleted successfully.")

def logs_reset(args, global_opts):
    if os.path.exists(LOGS_FILE):
        os.remove(LOGS_FILE)
    print("All logs cleared.")

def alias_list(args, global_opts):
    if not os.path.exists(ALIAS_FILE):
        print("No aliases configured.")
        return
    with open(ALIAS_FILE, "r") as f:
        aliases = json.load(f)
    if global_opts.json:
        output_result(aliases, True)
    else:
        print("--- Aliases ---")
        for name, cmd in aliases.items():
            print(f"  {name} => {cmd}")

def alias_set(args, global_opts):
    aliases = {}
    if os.path.exists(ALIAS_FILE):
        try:
            with open(ALIAS_FILE, "r") as f:
                aliases = json.load(f)
        except Exception:
            aliases = {}
    aliases[args.name] = args.command
    with open(ALIAS_FILE, "w") as f:
        json.dump(aliases, f, indent=2)
    print(f"Alias '{args.name}' set successfully.")

def alias_delete(args, global_opts):
    if not os.path.exists(ALIAS_FILE):
        print("No aliases configured.")
        return
    with open(ALIAS_FILE, "r") as f:
        aliases = json.load(f)
    if args.name not in aliases:
        print(f"Alias '{args.name}' not found.")
        return
    del aliases[args.name]
    with open(ALIAS_FILE, "w") as f:
        json.dump(aliases, f, indent=2)
    print(f"Alias '{args.name}' deleted.")

def config_list(args, global_opts):
    if not os.path.exists(CONFIG_FILE):
        print("No configuration set.")
        return
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    if global_opts.json:
        output_result(config, True)
    else:
        print("--- Configuration ---")
        for key, val in config.items():
            print(f"  {key} = {val}")

def config_get(args, global_opts):
    if not os.path.exists(CONFIG_FILE):
        print("Configuration not found.")
        return
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    print(config.get(args.key, f"Key '{args.key}' not found."))

def config_set(args, global_opts):
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
        except Exception:
            config = {}
    config[args.key] = args.value
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Configuration {args.key} = {args.value} updated.")

def config_delete(args, global_opts):
    if not os.path.exists(CONFIG_FILE):
        print("Configuration not found.")
        return
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    if args.key not in config:
        print(f"Configuration key '{args.key}' not found.")
        return
    del config[args.key]
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Configuration key '{args.key}' deleted.")

def config_edit(args, global_opts):
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({}, f, indent=2)
    editor = os.getenv("EDITOR", "nano")
    os.system(f'{editor} "{CONFIG_FILE}"')

def cmd_clean_cache(args, global_opts):
    print("Cleaning cache and auth files...")
    if os.path.exists(AUTH_FILE): os.remove(AUTH_FILE)
    if os.path.exists(SECRET_FILE): os.remove(SECRET_FILE)

    if global_opts.json:
        output_result({"success": True, "message": "Cache cleaned successfully."}, True)
    else:
        print("Cache cleaned successfully.")

def cmd_healthz(args, global_opts):
    print(f"Checking Health: {HEALTHZ_URL}")
    try:
        req = urllib.request.Request(HEALTHZ_URL)
        with urllib.request.urlopen(req, timeout=10) as res:
            body = res.read().decode()
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = None

            if getattr(args, 'show_status', False):
                print(f"Status: {res.status}")

            if global_opts.json:
                output_result({"status": res.status, "body": parsed or body}, True)
            else:
                print(f"HTTP Status: {res.status}")
                print(body)
    except Exception as e:
        handle_error(str(e), global_opts)
        print("Failed to check health endpoint.")

def execute_request_and_open(args, global_opts):
    check_logged_in(getattr(args, 'force', False) or global_opts.force, global_opts)

    target_url = getattr(args, 'url', None) or DEFAULT_API_URL
    method = (getattr(args, 'method', None) or getattr(args, 'X', None) or "GET").upper()

    if global_opts.hostname:
        try:
            parsed = urllib.parse.urlparse(target_url)
            target_url = urllib.parse.urlunparse(parsed._replace(netloc=global_opts.hostname))
        except Exception:
            pass

    print(f"Fetching: {target_url} [Method: {method}]")

    headers = {}
    if getattr(args, 'header', None):
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    if getattr(args, 'user', None):
        encoded = base64.b64encode(args.user.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    body_bytes = None
    if getattr(args, 'form', None):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body_bytes = "&".join(args.form).encode()
    elif getattr(args, 'data', None):
        body_bytes = args.data.encode()
    elif getattr(args, 'data_raw', None):
        body_bytes = args.data_raw.encode()
    elif getattr(args, 'data_urlencode', None):
        encoded_parts = []
        for item in args.data_urlencode:
            if "=" in item:
                k, v = item.split("=", 1)
                encoded_parts.append(f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}")
            else:
                encoded_parts.append(urllib.parse.quote_plus(item))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body_bytes = "&".join(encoded_parts).encode()
    elif getattr(args, 'data_binary', None):
        bin_path = args.data_binary
        if os.path.exists(bin_path):
            with open(bin_path, "rb") as bf:
                body_bytes = bf.read()
        else:
            body_bytes = bin_path.encode()

    req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            res_headers = dict(res.headers)
            body_text = res.read().decode()
            json_data = None
            try:
                json_data = json.loads(body_text)
            except Exception:
                pass

            if global_opts.json:
                output_result({"status": res.status, "headers": res_headers, "body": json_data or body_text}, True)
            else:
                headers_str = "\n".join([f"{k}: {v}" for k, v in res_headers.items()])
                print(f"HTTP/1.1 {res.status} OK\n{headers_str}\n\n{body_text}")

            # Robust display_url extraction matching Node.js fallback logic
            display_url_found = None
            if json_data and isinstance(json_data, dict) and json_data.get("display_url"):
                display_url_found = json_data["display_url"]
            else:
                match = re.search(r'"display_url"\s*:\s*"([^"]+)"', body_text)
                if match and match.group(1):
                    display_url_found = match.group(1)

            final_open_url = display_url_found if display_url_found else target_url
            if getattr(args, 'url', None) and args.url != DEFAULT_API_URL:
                final_open_url = args.url

            if getattr(args, 'show_url', False):
                print(f"URL: {final_open_url}")

            if getattr(args, 'show_display_url', False) and display_url_found:
                print(f"Display URL: {display_url_found}")

            if json_data and isinstance(json_data, dict):
                if getattr(args, 'show_name', False) and json_data.get("name") is not None:
                    print(f"Name: {json_data['name']}")
                if getattr(args, 'show_id', False) and json_data.get("id") is not None:
                    print(f"ID: {json_data['id']}")
                if getattr(args, 'show_urls', False) and json_data.get("urls") is not None:
                    print("URLs:", json.dumps(json_data["urls"], indent=2))
                if getattr(args, 'show_success', False) and json_data.get("success") is not None:
                    print(f"Success: {json_data['success']}")

            subprocess.run(["xdg-open", final_open_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    except Exception as e:
        handle_error(str(e), global_opts)
        print("Failed to fetch API.")

def add_request_options(parser):
    parser.add_argument("--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE)")
    parser.add_argument("-X", help="HTTP method alias")
    parser.add_argument("-u", "--url", help="API URL")
    parser.add_argument("-H", "--header", action="append", help="HTTP header")
    parser.add_argument("-f", "--form", action="append", help="Form field")
    parser.add_argument("-d", "--data", help="Request body")
    parser.add_argument("--data-raw", help="Raw request body data")
    parser.add_argument("--data-urlencode", action="append", help="URL-encode request data key=value")
    parser.add_argument("--data-binary", help="Binary request data or file path")
    parser.add_argument("--user", help="HTTP Basic Auth user:password")
    parser.add_argument("--show-url", action="store_true", help="Show final resolved URL")
    parser.add_argument("--show-display-url", action="store_true", help="Show parsed display_url specifically")
    parser.add_argument("--show-name", action="store_true", help="Show JSON name field")
    parser.add_argument("--show-id", action="store_true", help="Show JSON id field")
    parser.add_argument("--show-urls", action="store_true", help="Show JSON urls array/property")
    parser.add_argument("--show-success", action="store_true", help="Show JSON success status")

def main():
    parser = argparse.ArgumentParser(
        prog="xdg-tool",
        description="XDG Tool CLI with execution, logs, alias, config, server tools, and Replit backend integration"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--stacktrace", action="store_true", help="Throw full error stack trace on failure")
    parser.add_argument("--html-errors", action="store_true", help="Output errors in formatted HTML format")
    parser.add_argument("--hostname", help="Override request hostname")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--force", action="store_true", help="Skip login check requirement globally")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

    p_info = subparsers.add_parser("info", help="Display version info and paths")
    p_info.set_defaults(func=cmd_info)

    p_serve = subparsers.add_parser("serve", help="Start proxy server")
    p_serve.add_argument("-a", "--address", default="0.0.0.0")
    p_serve.add_argument("-p", "--port", default="5000")
    p_serve.add_argument("-b", "--bind")
    p_serve.add_argument("-u", "--upstream", default=UPSTREAM_PROXY_DEFAULT)
    p_serve.set_defaults(func=start_server)

    p_sstatus = subparsers.add_parser("server-status", help="Check server status")
    p_sstatus.add_argument("-p", "--port", default="5000")
    p_sstatus.set_defaults(func=check_server_status)

    p_sstop = subparsers.add_parser("server-stop", help="Stop server")
    p_sstop.add_argument("-p", "--port", default="5000")
    p_sstop.set_defaults(func=stop_server)

    p_kport = subparsers.add_parser("kill-port", help="Kill port process")
    p_kport.add_argument("-p", "--port", default="5000")
    p_kport.set_defaults(func=stop_server)

    p_acc = subparsers.add_parser("account", help="Show account info")
    p_acc.set_defaults(func=cmd_account)

    p_auth = subparsers.add_parser("auth", help="Auth management")
    auth_sub = p_auth.add_subparsers(dest="auth_subcommand")

    auth_sub.add_parser("register").set_defaults(func=auth_register)
    auth_sub.add_parser("login").set_defaults(func=auth_login)
    auth_sub.add_parser("logout").set_defaults(func=auth_logout)
    auth_sub.add_parser("status").set_defaults(func=auth_status)
    auth_sub.add_parser("token").set_defaults(func=auth_token)
    auth_sub.add_parser("verify").set_defaults(func=auth_verify)
    auth_sub.add_parser("reset").set_defaults(func=auth_reset_pin)
    auth_sub.add_parser("switch").set_defaults(func=auth_switch)
    p_arem = auth_sub.add_parser("remove")
    p_arem.add_argument("-f", "--force", action="store_true")
    p_arem.set_defaults(func=auth_remove)
    auth_sub.add_parser("list").set_defaults(func=auth_list)
    auth_sub.add_parser("whoami").set_defaults(func=auth_whoami)

    p_exec = subparsers.add_parser("execute", aliases=["exec"], help="Execute shell command")
    p_exec.add_argument("cmd_arg", nargs="?", help="Command to run")
    p_exec.add_argument("-c", "--command", help="Command to run flag")
    p_exec.set_defaults(func=cmd_execute)

    p_logs = subparsers.add_parser("logs", help="Manage command logs")
    logs_sub = p_logs.add_subparsers(dest="logs_subcommand")
    logs_sub.add_parser("list").set_defaults(func=logs_list)
    p_lview = logs_sub.add_parser("view")
    p_lview.add_argument("id")
    p_lview.set_defaults(func=logs_view)
    p_lexec = logs_sub.add_parser("exec")
    p_lexec.add_argument("id")
    p_lexec.set_defaults(func=logs_exec)
    p_ldel = logs_sub.add_parser("delete")
    p_ldel.add_argument("id")
    p_ldel.set_defaults(func=logs_delete)
    logs_sub.add_parser("reset").set_defaults(func=logs_reset)

    p_alias = subparsers.add_parser("alias", help="Manage aliases")
    alias_sub = p_alias.add_subparsers(dest="alias_subcommand")
    alias_sub.add_parser("list").set_defaults(func=alias_list)
    p_aset = alias_sub.add_parser("set")
    p_aset.add_argument("name")
    p_aset.add_argument("command")
    p_aset.set_defaults(func=alias_set)
    p_adel = alias_sub.add_parser("delete")
    p_adel.add_argument("name")
    p_adel.set_defaults(func=alias_delete)

    p_config = subparsers.add_parser("config", help="Manage config")
    config_sub = p_config.add_subparsers(dest="config_subcommand")
    config_sub.add_parser("list").set_defaults(func=config_list)
    p_cget = config_sub.add_parser("get")
    p_cget.add_argument("key")
    p_cget.set_defaults(func=config_get)
    p_cset = config_sub.add_parser("set")
    p_cset.add_argument("key")
    p_cset.add_argument("value")
    p_cset.set_defaults(func=config_set)
    p_cdel = config_sub.add_parser("delete")
    p_cdel.add_argument("key")
    p_cdel.set_defaults(func=config_delete)
    config_sub.add_parser("edit").set_defaults(func=config_edit)

    p_open = subparsers.add_parser("open", help="Open URL or API endpoint")
    add_request_options(p_open)
    p_open.set_defaults(func=execute_request_and_open)

    p_get = subparsers.add_parser("get", help="Fetch and open URL")
    add_request_options(p_get)
    p_get.set_defaults(func=execute_request_and_open)

    p_geturl = subparsers.add_parser("get-url", help="Fetch and open URL")
    add_request_options(p_geturl)
    p_geturl.set_defaults(func=execute_request_and_open)

    p_api = subparsers.add_parser("api", help="Send API request")
    add_request_options(p_api)
    p_api.set_defaults(func=execute_request_and_open)

    p_healthz = subparsers.add_parser("healthz", help="Check health endpoint")
    p_healthz.add_argument("--show-status", action="store_true")
    p_healthz.set_defaults(func=cmd_healthz)

    p_clean = subparsers.add_parser("clean-cache", aliases=["clean"], help="Clean local cache/auth")
    p_clean.set_defaults(func=cmd_clean_cache)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    args.func(args, args)

if __name__ == "__main__":
    main()
