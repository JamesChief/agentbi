#!/usr/bin/env python3
"""agentbi 网页版：静态页 + /api/check + /leaderboard

    python3 serve.py --port 8000

安全要点（别删）：
  * 任意网址抓取 = SSRF 风险。agentbi.is_safe_url 已在检测器层逐跳校验，
    这里额外做 URL 长度/协议校验与限流。
  * /api/check 会对外发起 5~7 个请求，必须限流 + 缓存，否则会被拿来当打手。
"""
import argparse
import html
import ipaddress
import json
import os
import re
import threading
import time
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import agentbi as A

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
BATCH = os.path.join(HERE, "batch.json")

RATE_MAX = 10           # 每 IP 在窗口内的请求数
RATE_WINDOW = 300
CACHE_TTL = 1800
DOMAIN_COOLDOWN = 600   # 同一目标域名多久才真扫一次（别反复打同一个站）
TRUSTED_PROXY_HOPS = 1  # 前面有 1 个可信反代（Caddy/nginx）

_hits = {}
_cache = {}
_domain_at = {}
_lock = threading.Lock()
_sem = threading.Semaphore(6)          # 同时最多 6 个检测（I/O 密集，2 vCPU 够）
_sem_wait = 2                          # 等不到位置就明确报忙，别让用户干等着转圈
_LB = {"mtime": 0.0, "html": ""}       # 榜单渲染结果缓存：每次请求渲染 225 行没必要

URL_RE = re.compile(r"^https?://[^\s<>\"]{4,200}$", re.I)


def rate_ok(ip):
    now = time.time()
    with _lock:
        q = _hits.setdefault(ip, deque())
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_MAX:
            return False
        q.append(now)
        return True


def domain_ok(host):
    """按目标域名冷却：别反复去打同一个站。"""
    now = time.time()
    with _lock:
        if len(_domain_at) > 5000:                      # 防止无限增长
            for h, t in list(_domain_at.items()):
                if now - t > DOMAIN_COOLDOWN:
                    del _domain_at[h]
        t = _domain_at.get(host)
        if t and now - t < DOMAIN_COOLDOWN:
            return False
        _domain_at[host] = now
        return True


def do_check(url):
    now = time.time()
    with _lock:
        hit = _cache.get(url)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1], True
        stale = hit[1] if hit else None
    host = (urlparse(url).hostname or "").lower()
    if not domain_ok(host):
        # 冷却期内：有旧结果就给旧的，没有就明确拒绝，不要偷偷发起抓取
        if stale:
            return stale, True
        return {"error": f"该站点刚被检测过，请 {DOMAIN_COOLDOWN // 60} 分钟后再试"}, False
    if not _sem.acquire(timeout=_sem_wait):
        # 宁可明确报忙，也不要让用户盯着转圈不知道发生了什么
        return {"error": "现在排队检测的人较多，请 30 秒后重试"}, False
    try:
        res = A.run(url, timeout=15, do_probe=True, discover=True)
    finally:
        _sem.release()
    with _lock:
        _cache[url] = (time.time(), res)
    return res, False


def render_leaderboard():
    if not os.path.exists(BATCH):
        return "<p>还没有榜单数据</p>"
    mt = os.path.getmtime(BATCH)
    if _LB["html"] and _LB["mtime"] == mt:
        return _LB["html"]                       # batch.json 没变就不重渲染
    data = json.load(open(BATCH))
    rows = data["rows"]
    ok = [r for r in rows if not r.get("error")]
    reach = [r for r in ok if r.get("home_status") == 200]
    plat = {}
    for r in reach:
        plat.setdefault(r["platform"], []).append(r)

    L = ['<h2>按平台对比</h2>',
         '<table><tr><th>平台</th><th>站数</th><th>UCP</th><th>产品结构化数据</th>'
         '<th>llms.txt</th><th>平均分</th></tr>']
    for p in sorted(plat, key=lambda p: -len(plat[p])):
        g = plat[p]
        n = len(g)
        L.append(f"<tr><td>{html.escape(p)}</td><td>{n}</td>"
                 f"<td>{sum(1 for r in g if r['ucp'])}/{n}</td>"
                 f"<td>{sum(1 for r in g if r['product_jsonld'])}/{n}</td>"
                 f"<td>{sum(1 for r in g if r['llms'])}/{n}</td>"
                 f"<td>{sum(r['score'] for r in g) // n}</td></tr>")
    L.append("</table>")

    # 方法说明：只给数字会被一句"样本太小"打倒，局限必须和表格同屏
    when = data.get("generated_at")
    date = time.strftime("%Y-%m-%d", time.gmtime(when)) if when else "—"
    n403 = sum(1 for r in rows if r.get("home_status") == 403)
    un = [r for r in ok if r.get("home_status") != 200]
    L.append("<h2>方法与局限（引用前请先读）</h2>")
    L.append("<ul class='note'>")
    L.append(f"<li>数据快照 <b>{date}</b>：共扫描 {len(rows)} 家电商站，首页返回 200 的 "
             f"<b>{len(reach)}</b> 家（可评估），{len(un)} 家返回非 200（其中 {n403} 个是 403）。</li>")
    L.append("<li><b>403 是我们的 IP 信誉问题，不是对方站点的配置问题</b>——绝大多数是企业级 WAF "
             "拦截数据中心出口 IP（Walmart / Macy's / Nordstrom / Costco 等都在其中）。"
             "加完整浏览器头部实测无法重现。因此本表覆盖的是<b>没有企业 WAF 的站点</b>，不是全行业。</li>")
    L.append("<li><b>WooCommerce n=8</b>，全部来自 WooCommerce 官方 showcase（可抓取的就这么些）。"
             "这是方向性结论，不是精确比例。</li>")
    L.append("<li>Shopify 店铺的 <code>llms.txt</code> 与 UCP 多为<b>平台自动生成</b>"
             "（多个店铺模板逐字节相同）——它是平台分界线，不是站主努力程度的信号。</li>")
    L.append("<li>评分是<b>启发式</b>的：不做 JS 渲染，也不会真的通过 UCP 下单，"
             "只验证 manifest 是否存在及其版本。</li>")
    L.append("</ul>")

    L.append(f"<h2>明细（可评估 {len(reach)} / 扫描 {len(rows)}）</h2>")
    L.append('<table><tr><th>站点</th><th>平台</th><th>分数</th><th>UCP</th></tr>')
    for r in sorted(reach, key=lambda r: -r["score"]):
        L.append(f"<tr><td>{html.escape(r['site'].replace('https://',''))}</td>"
                 f"<td>{html.escape(r['platform'])}</td><td>{r['score']}</td>"
                 f"<td>{html.escape(r['ucp'] or '—')}</td></tr>")
    L.append("</table>")
    if un:
        L.append(f"<p class='note'>{len(un)} 个站点对探测器返回非 200（多为 WAF 拦截），"
                 f"不代表其 agent 友好度低，未计入榜单。</p>")
    _LB["mtime"], _LB["html"] = mt, "\n".join(L)
    return _LB["html"]


class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB, **kw)

    def client_ip(self):
        """真实客户端 IP。只信任来自本机反代的 X-Forwarded-For，否则该头可伪造、
        限流形同虚设。

        反代的行为是**追加**（Caddy / nginx 的 $proxy_add_x_forwarded_for），
        所以真实 IP 在列表最右侧；按信任跳数从右往左取。
        """
        peer = self.client_address[0]
        try:
            if not ipaddress.ip_address(peer).is_loopback:
                return peer          # 直连，不信任 XFF
        except ValueError:
            return peer
        xff = self.headers.get("X-Forwarded-For")
        if not xff:
            return peer
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if not parts:
            return peer
        try:
            return parts[-TRUSTED_PROXY_HOPS]
        except IndexError:
            return parts[0]

    def end_headers(self):
        # 静态资源走浏览器缓存：HN 流量来的时候少打一次是一点
        if urlparse(self.path).path.endswith((".css", ".js")):
            self.send_header("Cache-Control", "public, max-age=3600")
        super().end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _leaderboard_body(self):
        return (f"<html><head><meta charset='utf-8'><title>AgentBI 榜单</title>"
                f"<meta name='description' content='225 家电商站的 AI agent 友好度实测："
                f"Shopify 86% 部署 UCP，WooCommerce 0%。含方法与局限说明。'>"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content='AgentBI 榜单 — 225 家电商站 agent 友好度实测'>"
                f"<meta property='og:description' content='Shopify 86% 已部署 UCP，WooCommerce 0%。"
                f"平台差异比站主努力更能决定你能不能被 shopping agent 找到。'>"
                f"<meta property='og:url' content='https://agentbi.tech/leaderboard'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/leaderboard'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>AgentBI 榜单</h1><p><a href='/'>← 检测你的站</a></p>"
                f"{render_leaderboard()}</body></html>").encode()

    def _send_html(self, body, cache="public, max-age=300"):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def do_HEAD(self):
        # 不覆盖 do_HEAD 的话，HEAD /leaderboard 会走静态文件逻辑返回 404，
        # 社交卡片校验器和部分爬虫会被误导
        u = urlparse(self.path)
        if u.path in ("/leaderboard", "/leaderboard.html"):
            return self._send_html(self._leaderboard_body())
        if u.path in ("/about", "/about.html"):
            self.path = "/about.html"
        return super().do_HEAD()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/check":
            q = parse_qs(u.query)
            url = (q.get("url") or [""])[0].strip()
            if not URL_RE.match(url):
                return self._json({"error": "URL 不合法（仅支持 http/https）"}, 400)
            if not rate_ok(self.client_ip()):
                return self._json({"error": "请求过于频繁，请稍后再试"}, 429)
            try:
                res, cached = do_check(url)
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}"}, 500)
            return self._json({"cached": cached, "result": res})

        if u.path in ("/leaderboard", "/leaderboard.html"):
            body = self._leaderboard_body()
            self._send_html(body)
            return self.wfile.write(body)

        if u.path in ("/about", "/about.html"):
            self.path = "/about.html"      # UA 串与页脚里对外写的是 /about

        return super().do_GET()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(f"http://{a.host}:{a.port}  （仅本机可访问；对外部署前需自行加固）")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()
