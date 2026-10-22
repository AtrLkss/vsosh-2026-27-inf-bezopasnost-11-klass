from flask import Flask, request, jsonify
from urllib.parse import urlparse
from urllib.request import urlopen
import socket
import ipaddress
import json

app = Flask(__name__)

USERS = {
    "alice": {"role": "user", "theme": "light"},
    "bob": {"role": "user", "theme": "dark"},
    "admin": {"role": "admin", "theme": "dark"},
}

AUDIT_LOG = []

def get_user():
    name = request.headers.get("X-User")
    return USERS.get(name)

def save_audit(user, action, target):
    AUDIT_LOG.append({
        "user": user or "anonymous",
        "action": action,
        "target": target,
    })

def is_http_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def resolve_host(host):
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        return None

def fetch_preview(url):
    if not is_http_url(url):
        return {"error": "Only HTTP(S) URLs are allowed"}

    parsed = urlparse(url)
    target_ip = resolve_host(parsed.hostname)

    if target_ip is None:
        return {"error": "Host cannot be resolved"}

    try:
        response = urlopen(url, timeout=2)
        body = response.read(300)
        save_audit(get_user(), "preview", url)
        return {
            "status": response.status,
            "body": body.decode("utf-8", errors="replace"),
        }
    except Exception as exc:
        return {"error": str(exc)}

@app.route("/profile")
def profile():
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "theme": user["theme"],
        "role": user["role"],
    })

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    result = fetch_preview(url)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)

@app.route("/audit")
def audit():
    user = get_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify(AUDIT_LOG)

@app.route("/health")
def health():
    return jsonify({
        "service": "preview",
        "status": "ok",
        "version": "1.4",
    })

def seed_data():
    AUDIT_LOG.append({
        "user": "system",
        "action": "startup",
        "target": "local",
    })

if __name__ == "__main__":
    seed_data()
    app.run(host="0.0.0.0", port=5000)
