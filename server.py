#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go Page V4 — 域名中继跳转服务
==============================
纯 Python HTTP 服务，无第三方依赖。

路由优先级：
  1. /admin          → 后台管理面板
  2. /admin/api/*    → 管理 API
  3. 主域名中继       → 302 到 {label}.{relayDomain}/go
  4. /go             → 生成 token → 302 到 /?token=xxx
  5. /api/verify-token → token 验证
  6. /api/config     → 前端配置
  7. 静态文件         → index.html / app.js / style.css
"""

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import random
import string
import sys
import time
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# ===== 路径 =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(BASE_DIR, "domains.json")
ADMIN_FILE = os.path.join(BASE_DIR, "admin.html")

# ===== 环境变量 =====
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "") or base64.b64encode(os.urandom(32)).decode()
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "300"))
GATE_SECRET = os.environ.get("GATE_SECRET", "") or base64.b64encode(os.urandom(32)).decode()
GATE_TTL = int(os.environ.get("GATE_TTL", "300"))

# ===== 默认配置 =====
DEFAULT_CONFIG = {
    "version": 1,
    "updated": "",
    "siteName": "独立跳转站",
    "relay": {
        "mainDomains": [],
        "relayDomains": [],
        "labelLength": 4,
    },
    "wildcard": {
        "enabled": True,
        "baseDomain": "",
        "candidateCount": 6,
        "labelLength": 8,
    },
    "probeAssets": ["/logo.png"],
    "probeAssetThreshold": 2,
    "domains": [],
}


# ================================================================
#  域名清洗 — 绝不用 lstrip / rstrip
# ================================================================
def clean_domain(raw):
    """清洗用户输入的域名：去协议、去 *.、去路径、去端口、小写。"""
    s = str(raw).strip().lower()
    # 去协议
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    # 去路径（取第一个 / 之前）
    slash = s.find("/")
    if slash >= 0:
        s = s[:slash]
    # 去端口
    colon = s.rfind(":")
    if colon >= 0:
        s = s[:colon]
    # 去 *. 通配前缀 — 用 startswith 判断，绝不用 lstrip
    if s.startswith("*."):
        s = s[2:]
    return s.strip()


# ================================================================
#  启动自检 — 失败则 exit(1) 拒绝启动
# ================================================================
def run_self_test():
    tests = [
        ("*.fook.pro", "fook.pro"),
        ("https://*.fook.pro/go", "fook.pro"),
        ("http://fook.pro:8080/path", "fook.pro"),
        ("  FOOK.PRO  ", "fook.pro"),
        ("https://example.com/", "example.com"),
        ("*.sub.domain.com", "sub.domain.com"),
        ("http://TEST.COM:443/a/b/c", "test.com"),
        ("fook.pro", "fook.pro"),
    ]
    for raw, expected in tests:
        result = clean_domain(raw)
        if result != expected:
            print(f"[SELF-TEST] FAIL: clean_domain({raw!r}) = {result!r}, expected {expected!r}")
            sys.exit(1)

    # relay URL 构造测试
    label = "abcd"
    domain = clean_domain("*.fook.pro")
    target = f"https://{label}.{domain}/go"
    if "%2A" in target or "%2a" in target:
        print(f"[SELF-TEST] FAIL: relay URL contains %2A: {target}")
        sys.exit(1)
    if "/go/go" in target:
        print(f"[SELF-TEST] FAIL: relay URL contains /go/go: {target}")
        sys.exit(1)

    print("[SELF-TEST] clean_domain: ALL PASSED")


# ================================================================
#  配置读写
# ================================================================
def default_config():
    return copy.deepcopy(DEFAULT_CONFIG)


def normalize_config(data):
    """将任意输入规范化为标准配置格式，所有域名经过 clean_domain。"""
    cfg = default_config()
    src = data if isinstance(data, dict) else {}

    cfg["version"] = int(src.get("version", cfg["version"]) or cfg["version"])
    cfg["updated"] = src.get("updated", cfg["updated"])
    cfg["siteName"] = src.get("siteName") or cfg["siteName"]

    # relay
    relay = src.get("relay", {}) or {}
    cfg["relay"]["mainDomains"] = [
        clean_domain(d) for d in (relay.get("mainDomains") or []) if str(d).strip()
    ]
    cfg["relay"]["relayDomains"] = [
        clean_domain(d) for d in (relay.get("relayDomains") or []) if str(d).strip()
    ]
    cfg["relay"]["labelLength"] = int(relay.get("labelLength", cfg["relay"]["labelLength"]) or cfg["relay"]["labelLength"])

    # wildcard
    wc = src.get("wildcard", {}) or {}
    cfg["wildcard"]["enabled"] = bool(wc.get("enabled", cfg["wildcard"]["enabled"]))
    cfg["wildcard"]["baseDomain"] = clean_domain(wc.get("baseDomain", "") or cfg["wildcard"]["baseDomain"])
    cfg["wildcard"]["candidateCount"] = int(wc.get("candidateCount", cfg["wildcard"]["candidateCount"]) or cfg["wildcard"]["candidateCount"])
    cfg["wildcard"]["labelLength"] = int(wc.get("labelLength", cfg["wildcard"]["labelLength"]) or cfg["wildcard"]["labelLength"])

    # probe
    probe = src.get("probeAssets", cfg["probeAssets"]) or []
    cfg["probeAssets"] = [str(p).strip() for p in probe if str(p).strip()]
    cfg["probeAssetThreshold"] = int(src.get("probeAssetThreshold", cfg["probeAssetThreshold"]) or cfg["probeAssetThreshold"])

    # domains
    cfg["domains"] = src.get("domains", cfg["domains"]) or []
    return cfg


def load_config():
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
            return normalize_config(json.load(f))
    return default_config()


def save_config(data):
    data = normalize_config(data)
    data["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    data["version"] = data.get("version", 0) + 1
    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data


# ================================================================
#  Token 工具
# ================================================================
def random_label(length):
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def generate_token():
    ts = str(int(time.time()))
    sig = hmac.new(TOKEN_SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()[:16]
    raw = ts + ":" + sig
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def verify_token(token_str):
    try:
        padding = 4 - len(token_str) % 4
        if padding != 4:
            token_str += "=" * padding
        raw = base64.urlsafe_b64decode(token_str).decode()
        ts_str, sig = raw.split(":", 1)
        ts = int(ts_str)
        if abs(time.time() - ts) > TOKEN_TTL:
            return False
        expected = hmac.new(TOKEN_SECRET.encode(), ts_str.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def generate_gate_token():
    ts = str(int(time.time()))
    sig = hmac.new(GATE_SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()[:16]
    raw = ts + ":" + sig
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


# ================================================================
#  Nginx Gate 配置生成
# ================================================================
def build_gate_nginx_config(config, site_type="php"):
    probe_assets = config.get("probeAssets", [])
    whitelist_dirs = set()
    whitelist_files = set()
    for path in probe_assets:
        cleaned = path.strip("/")
        parts = cleaned.split("/")
        if len(parts) > 1:
            whitelist_dirs.add(parts[0])
        elif cleaned:
            whitelist_files.add(cleaned)

    is_php = site_type == "php"
    type_label = "PHP (ThinkPHP)" if is_php else "纯静态站"

    lines = [
        "# ===== Nginx Gate 505 配置 =====",
        f"# 站点类型: {type_label}",
        f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "server {",
        "    listen 8080;",
        "    server_name _;",
    ]
    if is_php:
        lines += ["    root /var/www/html/public;", "    index index.php index.html;"]
    else:
        lines += ["    root /usr/share/nginx/html;", "    index index.html;"]

    lines += ["", "    absolute_redirect off;", "", "    # === 探测资源放行 ==="]
    for d in sorted(whitelist_dirs):
        lines += [f"    location /{d}/ {{", "        expires 30d;", "        access_log off;", "    }", ""]
    for f in sorted(whitelist_files):
        lines += [f"    location = /{f} {{ expires 30d; access_log off; }}"]
    lines += ["    location /favicon.ico { access_log off; }", "    location /robots.txt  { access_log off; }", ""]

    if is_php:
        lines += [
            "    # === WebSocket ===",
            "    location /wss {",
            "        proxy_pass http://127.0.0.1:7273;",
            "        proxy_http_version 1.1;",
            '        proxy_set_header Upgrade $http_upgrade;',
            '        proxy_set_header Connection "Upgrade";',
            "    }",
            "",
        ]

    lines += [
        "    # === Gate cookie ===",
        "    location = /_internal_gate {",
        "        internal;",
        '        add_header Set-Cookie "_gate_pass=1; Path=/; Max-Age=86400; HttpOnly" always;',
        "        return 302 /;",
        "    }",
        "",
        "    # === 主入口 ===",
        "    location / {",
        '        set $gate "deny";',
        '        if ($cookie__gate_pass = "1") { set $gate "allow"; }',
        '        if ($arg__gate)               { set $gate "new";   }',
        '        if ($gate = "new")  { rewrite ^ /_internal_gate last; }',
        '        if ($gate = "deny") { return 505; }',
        "",
    ]
    if is_php:
        lines += [
            "        if (!-e $request_filename) {",
            "            rewrite ^(.*)$ /index.php?s=/$1 last;",
            "        }",
        ]
    else:
        lines.append("        try_files $uri $uri/ =404;")
    lines.append("    }")

    if is_php:
        lines += [
            "",
            "    # === PHP-FPM ===",
            "    location ~ \\.php$ {",
            "        fastcgi_pass 127.0.0.1:9000;",
            "        fastcgi_index index.php;",
            "        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
            "        include fastcgi_params;",
            "    }",
        ]
    lines.append("}")
    return "\n".join(lines)


# ================================================================
#  HTTP Handler
# ================================================================
class GoPageHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    # --- 鉴权 ---
    def check_auth(self):
        if not ADMIN_PASS:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            user, passwd = decoded.split(":", 1)
            return user == ADMIN_USER and passwd == ADMIN_PASS
        except Exception:
            return False

    def require_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Go Page V4"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    # --- GET ---
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        config = load_config()
        relay = config.get("relay", {})
        main_domains = relay.get("mainDomains", [])
        relay_domains = relay.get("relayDomains", [])
        label_len = int(relay.get("labelLength", 4))

        # Priority 1: Admin 页面
        if path in ("/admin", "/admin/"):
            if not self.check_auth():
                return self.require_auth()
            self.path = "/admin.html"
            return super().do_GET()

        # Priority 2: Admin API
        if path == "/admin/api/config":
            if not self.check_auth():
                return self.require_auth()
            return self.send_json(config)

        if path == "/admin/api/generate-gate":
            if not self.check_auth():
                return self.require_auth()
            qs = urllib.parse.parse_qs(parsed.query)
            site_type = (qs.get("type") or ["php"])[0]
            if site_type not in ("php", "static"):
                site_type = "php"
            text = build_gate_nginx_config(config, site_type=site_type)
            return self.send_json({"ok": True, "config": text})

        # Priority 3: 主域名中继
        if host in main_domains and relay_domains and path in ("/", "/index.html", "/go", "/go/"):
            relay_domain = random.choice(relay_domains)  # 已被 clean_domain 清洗
            label = random_label(label_len)
            target = f"https://{label}.{relay_domain}/go"
            return self.send_redirect(target)

        # Priority 4: /go 入口（host 不在 mainDomains → 是子域名）
        if path in ("/go", "/go/"):
            token = generate_token()
            return self.send_redirect(f"/?token={token}")

        # Priority 5: token 验证
        if path == "/api/verify-token":
            qs = urllib.parse.parse_qs(parsed.query)
            token = (qs.get("token") or [""])[0]
            if verify_token(token):
                return self.send_json({"ok": True})
            else:
                return self.send_json({"ok": False, "message": "链接已过期或无效"}, status=403)

        # Priority 6: gate token
        if path == "/api/gate-token":
            return self.send_json({"token": generate_gate_token()})

        # Priority 7: 前端配置（公开，给 app.js 用）
        if path == "/api/config":
            return self.send_json(config)

        # Priority 8: 静态文件
        if path in ("/", "/index.html"):
            self.path = "/index.html"
        return super().do_GET()

    # --- POST ---
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/admin/api/config":
            if not self.check_auth():
                return self.require_auth()
            length = int(self.headers.get("Content-Length", "0") or 0)
            payload = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                incoming = json.loads(payload or "{}")
            except json.JSONDecodeError as exc:
                return self.send_json({"ok": False, "message": f"JSON 格式错误: {exc}"}, status=400)
            saved = save_config(incoming)
            return self.send_json({"ok": True, "message": "配置已保存", "config": saved})

        self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        print(f"[v4] {fmt % args}")


# ================================================================
#  启动
# ================================================================
def serve(host=None, port=None):
    host = host or os.environ.get("HOST", "0.0.0.0")
    port = port or int(os.environ.get("PORT", "8787"))
    server = ThreadingHTTPServer((host, port), GoPageHandler)
    print(f"[OK] Go Page V4 已启动: http://{host}:{port}")
    print(f"[OK] 管理后台: http://{host}:{port}/admin")
    print(f"[OK] 落地页: http://{host}:{port}/index.html")
    print(f"[OK] 中继入口: http://{host}:{port}/go")
    if ADMIN_PASS:
        print(f"[OK] 后台鉴权已启用 (用户: {ADMIN_USER})")
    else:
        print("[WARN] 未设置 ADMIN_PASS，后台无鉴权保护")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[STOP] 服务已停止")
    finally:
        server.server_close()


def main():
    # 启动自检
    run_self_test()

    parser = argparse.ArgumentParser(description="Go Page V4 — 域名中继跳转服务")
    sub = parser.add_subparsers(dest="command")
    p_serve = sub.add_parser("serve-admin", help="启动服务")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    if args.command == "serve-admin":
        serve(args.host, args.port)
    elif os.environ.get("PORT") or os.environ.get("RAILWAY_ENVIRONMENT"):
        serve()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
