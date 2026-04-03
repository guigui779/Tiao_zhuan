#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目标站 Gate 门禁中间件
======================
部署在目标站前面，验证来自 go_page 的访问凭证。
没有有效凭证的请求返回 505。

工作方式：
1. 用户从 go_page 跳转过来，URL 带 ?_gate=TOKEN
2. 本中间件验证 TOKEN → 种 Cookie(_gate_pass) → 302 去掉 URL 参数
3. 后续请求靠 Cookie 访问，无需再带参数
4. 直接打开（无参数无 Cookie）→ 505

部署方式：
  方式1 - 独立反向代理（推荐）：
    export GATE_SECRET="和go_page相同的密钥"
    export UPSTREAM="http://127.0.0.1:实际端口"
    python gate_middleware.py

  方式2 - 在 Nginx 中用 auth_request：
    参考底部的 Nginx 配置示例

环境变量：
  GATE_SECRET  - 必须与 go_page 的 GATE_SECRET 相同
  GATE_TTL     - Token 有效期秒数（默认 300）
  COOKIE_TTL   - Cookie 有效期秒数（默认 86400，24小时）
  UPSTREAM     - 目标站实际地址（默认 http://127.0.0.1:3000）
  PORT         - 监听端口（默认 8080）
  HOST         - 监听地址（默认 0.0.0.0）
"""

import os
import sys
import time
import hmac
import hashlib
import base64
import http.cookies
import urllib.parse
import urllib.request
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ========== 配置 ==========
GATE_SECRET = os.environ.get('GATE_SECRET', 'mFf44StGLBt7vkL2HZ0EKPNpHRzNhQ8yI-elmW-4-NE')
GATE_TTL = int(os.environ.get('GATE_TTL', '300'))
COOKIE_TTL = int(os.environ.get('COOKIE_TTL', '86400'))
UPSTREAM = os.environ.get('UPSTREAM', 'http://127.0.0.1:3000')
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', '8080'))
COOKIE_NAME = '_gate_pass'


def verify_gate_token(token_str):
    """验证 go_page 生成的 gate token"""
    try:
        padding = 4 - len(token_str) % 4
        if padding != 4:
            token_str += '=' * padding
        raw = base64.urlsafe_b64decode(token_str).decode()
        ts_str, sig = raw.split(':', 1)
        ts = int(ts_str)
        if abs(time.time() - ts) > GATE_TTL:
            return False
        expected = hmac.new(GATE_SECRET.encode(), ts_str.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def generate_cookie_value():
    """生成 Cookie 值（带签名，防伪造）"""
    ts = str(int(time.time()))
    sig = hmac.new(GATE_SECRET.encode(), ('cookie:' + ts).encode(), hashlib.sha256).hexdigest()[:16]
    raw = ts + ':' + sig
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')


def verify_cookie_value(cookie_val):
    """验证 Cookie 值"""
    try:
        padding = 4 - len(cookie_val) % 4
        if padding != 4:
            cookie_val += '=' * padding
        raw = base64.urlsafe_b64decode(cookie_val).decode()
        ts_str, sig = raw.split(':', 1)
        ts = int(ts_str)
        if abs(time.time() - ts) > COOKIE_TTL:
            return False
        expected = hmac.new(GATE_SECRET.encode(), ('cookie:' + ts_str).encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def get_cookie(headers, name):
    """从请求头解析 Cookie"""
    cookie_header = headers.get('Cookie', '')
    cookies = http.cookies.SimpleCookie()
    try:
        cookies.load(cookie_header)
        if name in cookies:
            return cookies[name].value
    except Exception:
        pass
    return ''


class GateHandler(BaseHTTPRequestHandler):
    """Gate 中间件请求处理器"""

    def check_access(self):
        """检查访问权限，返回 (allowed, gate_token_or_none)"""
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        # 1. 检查 URL 参数中的 _gate token
        gate_token = (qs.get('_gate') or [''])[0]
        if gate_token and verify_gate_token(gate_token):
            return True, gate_token

        # 2. 检查 Cookie
        cookie_val = get_cookie(self.headers, COOKIE_NAME)
        if cookie_val and verify_cookie_value(cookie_val):
            return True, None

        return False, None

    def strip_gate_param(self):
        """从 URL 中去掉 _gate 参数，返回干净的 URL"""
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs.pop('_gate', None)
        new_query = urllib.parse.urlencode(qs, doseq=True)
        clean_path = parsed.path
        if new_query:
            clean_path += '?' + new_query
        return clean_path

    def send_505(self):
        """拒绝访问"""
        body = b'505 Not Allowed'
        self.send_response(505)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def set_gate_cookie_and_redirect(self):
        """种 Cookie 并 302 到干净 URL"""
        cookie_val = generate_cookie_value()
        clean_url = self.strip_gate_param()
        self.send_response(302)
        self.send_header('Location', clean_url)
        self.send_header('Set-Cookie',
                         f'{COOKIE_NAME}={cookie_val}; Path=/; Max-Age={COOKIE_TTL}; HttpOnly; SameSite=Lax')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()

    def proxy_request(self, method='GET', body=None):
        """转发请求到 upstream"""
        target_url = UPSTREAM.rstrip('/') + self.path
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(target_url, data=body, method=method)
        # 转发原始请求头（排除 Host）
        for key, val in self.headers.items():
            if key.lower() not in ('host', 'connection'):
                req.add_header(key, val)

        try:
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            resp_body = resp.read()
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ('transfer-encoding', 'connection'):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            resp_body = e.read() if e.fp else b''
            self.send_response(e.code)
            for key, val in e.headers.items():
                if key.lower() not in ('transfer-encoding', 'connection'):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            body_err = f'502 Bad Gateway: {e}'.encode()
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body_err)))
            self.end_headers()
            self.wfile.write(body_err)

    def handle_request(self, method='GET'):
        allowed, gate_token = self.check_access()

        if not allowed:
            return self.send_505()

        # 如果是通过 _gate 参数进来的，种 Cookie 后 302 去掉参数
        if gate_token:
            return self.set_gate_cookie_and_redirect()

        # Cookie 有效，正常代理
        body = None
        if method in ('POST', 'PUT', 'PATCH'):
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length) if length else None

        self.proxy_request(method, body)

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

    def do_PUT(self):
        self.handle_request('PUT')

    def do_DELETE(self):
        self.handle_request('DELETE')

    def do_PATCH(self):
        self.handle_request('PATCH')

    def do_OPTIONS(self):
        self.handle_request('OPTIONS')

    def do_HEAD(self):
        self.handle_request('HEAD')

    def log_message(self, format, *args):
        print(f'[gate] {self.address_string()} {format % args}')


def main():
    if GATE_SECRET == 'change-me-to-a-random-string':
        print("[WARN] 请设置 GATE_SECRET 环境变量！当前使用默认值不安全。")
        print("  export GATE_SECRET=\"你的随机密钥\"  # 必须和 go_page 一致")
        print()

    server = ThreadingHTTPServer((HOST, PORT), GateHandler)
    print(f"[OK] Gate 门禁中间件已启动")
    print(f"  监听: http://{HOST}:{PORT}")
    print(f"  上游: {UPSTREAM}")
    print(f"  Token 有效期: {GATE_TTL}s")
    print(f"  Cookie 有效期: {COOKIE_TTL}s")
    print()
    print("=== Nginx 参考配置 ===")
    print("""
# 如果你用 Nginx 而不是本脚本，可以用 auth_request 方式：
# 1. 把本脚本部署为内部验证服务（端口 8080）
# 2. Nginx 配置：
#
# server {
#     listen 443 ssl;
#     server_name *.a.hui-od.top;
#
#     # 主要请求走反向代理
#     location / {
#         # 先验证 gate
#         auth_request /auth_gate;
#         auth_request_set $gate_cookie $upstream_http_set_cookie;
#         add_header Set-Cookie $gate_cookie;
#
#         proxy_pass http://实际后端;
#     }
#
#     # gate 验证端点
#     location = /auth_gate {
#         internal;
#         proxy_pass http://127.0.0.1:8080;
#         proxy_pass_request_body off;
#         proxy_set_header Content-Length "";
#         proxy_set_header X-Original-URI $request_uri;
#         proxy_set_header Cookie $http_cookie;
#     }
# }
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[STOP] Gate 中间件已停止')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
