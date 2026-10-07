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
import strings as S

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
BATCH = os.path.join(HERE, "batch.json")
SUBSCRIBERS = os.path.join(HERE, "subscribers.jsonl")

RATE_MAX = 10           # 每 IP 在窗口内的请求数
RATE_WINDOW = 300
SUB_RATE_MAX = 5        # 订阅比检测更容易被刷，单独一个更紧的桶
SUB_RATE_WINDOW = 3600
CACHE_TTL = 1800
DOMAIN_COOLDOWN = 600   # 同一目标域名多久才真扫一次（别反复打同一个站）
TRUSTED_PROXY_HOPS = 1  # 前面有 1 个可信反代（Caddy/nginx）

_hits = {}
_sub_hits = {}
_cache = {}
_domain_at = {}
_lock = threading.Lock()
_sub_lock = threading.Lock()           # 订阅文件单独一把锁，别和检测抢
_sem = threading.Semaphore(6)          # 同时最多 6 个检测（I/O 密集，2 vCPU 够）
_sem_wait = 2                          # 等不到位置就明确报忙，别让用户干等着转圈
_LB = {"mtime": 0.0, "html": ""}       # 榜单渲染结果缓存：每次请求渲染 225 行没必要

URL_RE = re.compile(r"^https?://[^\s<>\"]{4,200}$", re.I)
# 刻意宽松：邮箱地址的合法形态太多，严格校验只会误杀。真正的确认是收信，不是正则。
EMAIL_RE = re.compile(r"^[^@\s,;]{1,64}@[^@\s,;]+\.[^@\s,;.]{2,}$")


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


def sub_rate_ok(ip):
    now = time.time()
    with _lock:
        q = _sub_hits.setdefault(ip, deque())
        while q and now - q[0] > SUB_RATE_WINDOW:
            q.popleft()
        if len(q) >= SUB_RATE_MAX:
            return False
        q.append(now)
        return True


def domain_ok(host, lang):
    """按目标域名冷却：别反复去打同一个站。

    语言分开计数——切语言时缓存里没有另一种语言的结果，若被冷却挡住，
    用户看到的会是"刚检测过"而不是他想要的中文报告。代价最多是双倍请求数。
    """
    now = time.time()
    key = (host, lang)
    with _lock:
        if len(_domain_at) > 5000:                      # 防止无限增长
            for h, t in list(_domain_at.items()):
                if now - t > DOMAIN_COOLDOWN:
                    del _domain_at[h]
        t = _domain_at.get(key)
        if t and now - t < DOMAIN_COOLDOWN:
            return False
        _domain_at[key] = now
        return True


def lang_of(query, cookie):
    """?lang=zh > cookie > 默认英文（站点面向海外站主）。"""
    v = (query or "").strip().lower()
    return v if v in S.LANGS else (cookie if cookie in S.LANGS else S.DEFAULT)


def sub_block(lang, long_form):
    """订阅框。长版（首页报告下方）带说明，短版（页脚 / 榜单页）一行。

    两个版本用同一套 class，交给 web/sub.js 统一接管提交。
    """
    e = html.escape
    # 注意：别用 .sub——那已经是站点副标题的 class（style.css）
    desc = S.t("sub.desc_long" if long_form else "sub.desc_short", lang)
    cls = "subscribe subscribe-long" if long_form else "subscribe subscribe-short"
    head = f"<h3>{e(S.t('sub.title', lang))}</h3>" if long_form else ""
    return (f"<div class='{cls}'>{head}"
            f"<form class='subscribe-form' novalidate>"
            f"<p class='subscribe-desc'>{e(desc)}</p>"
            f"<input type='email' name='email' class='subscribe-email' "
            f"placeholder=\"{e(S.t('sub.placeholder', lang))}\" autocomplete='email' required>"
            f"<button type='submit'>{e(S.t('sub.button', lang))}</button>"
            f"</form>"
            f"<p class='subscribe-consent'>{e(S.t('sub.consent', lang))}</p>"
            f"<p class='subscribe-msg' role='status'></p>"
            f"</div>")


def sub_script(lang):
    """给 JS 用的订阅文案 + 处理脚本。

    首页的 L 里已经含 sub.*（见 render_page 的 js_keys），这里只单独喂给榜单页——
    榜单是 Python 直接拼出来的，不走 index.html 的模板。
    """
    keys = {k: v for k, v in S.STR.get(lang, S.STR[S.DEFAULT]).items()
            if k.startswith("sub.")}
    return ("<script>window.__SUB_L=" + json.dumps(keys, ensure_ascii=False) + ";</script>"
            "<script src='/sub.js' defer></script>")


def render_page(name, lang):
    """静态页是模板：先填运行时值（语言、查询串、给 JS 用的文案），再套文案表。"""
    raw = open(os.path.join(WEB, name), encoding="utf-8").read()
    js_keys = {k: v for k, v in S.STR.get(lang, S.STR[S.DEFAULT]).items()
               if k.startswith(("dim.", "rep.", "pri.", "site.", "sub."))}
    vals = {
        "html.lang": lang,
        "qs": f"?lang={lang}" if lang != S.DEFAULT else "",
        "json.qs": json.dumps(f"&lang={lang}" if lang != S.DEFAULT else ""),
        "json.lang": json.dumps(js_keys, ensure_ascii=False),
        "alt_href": "/?lang=zh" if lang == S.DEFAULT else "/",
        "alt_lang": "中文" if lang == S.DEFAULT else "English",
        "sub_long": sub_block(lang, True),
        "sub_short": sub_block(lang, False),
    }
    for k, v in vals.items():
        raw = raw.replace("{{" + k + "}}", str(v))
    return S.render_template(raw, lang)


def do_check(url, lang):
    now = time.time()
    key = (url, lang)                      # 同一 URL 的两种语言结果不共用缓存
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1], True
        stale = hit[1] if hit else None
    host = (urlparse(url).hostname or "").lower()
    if not domain_ok(host, lang):
        # 冷却期内：有旧结果就给旧的，没有就明确拒绝，不要偷偷发起抓取
        if stale:
            return stale, True
        return {"error": S.t("err.cooldown", lang, n=DOMAIN_COOLDOWN // 60)}, False
    if not _sem.acquire(timeout=_sem_wait):
        # 宁可明确报忙，也不要让用户盯着转圈不知道发生了什么
        return {"error": S.t("err.busy", lang)}, False
    try:
        res = A.run(url, timeout=15, do_probe=True, discover=True, lang=lang)
    finally:
        _sem.release()
    with _lock:
        _cache[key] = (time.time(), res)
    return res, False


def _prev_snapshot(cur_date):
    """上一次（不同日期的）每日快照，用于榜单上给出环比。没有就返回 None。"""
    d = os.path.join(os.path.dirname(BATCH), "history")
    if not os.path.isdir(d):
        return None
    files = sorted(f for f in os.listdir(d) if f.startswith("batch-") and f.endswith(".json"))
    for f in reversed(files):
        if cur_date in f:                      # 今天这次不算"上一次"
            continue
        try:
            return f[len("batch-"):-len(".json")], json.load(open(os.path.join(d, f)))
        except Exception:
            return None
    return None


def render_leaderboard(lang=S.DEFAULT):
    if not os.path.exists(BATCH):
        return f"<p>{html.escape(S.t('lb.no_data', lang))}</p>"
    mt = os.path.getmtime(BATCH)
    if _LB.get(lang) and _LB["mtime"] == mt:
        return _LB[lang]                         # batch.json 没变就不重渲染
    data = json.load(open(BATCH))
    rows = data["rows"]
    ok = [r for r in rows if not r.get("error")]
    reach = [r for r in ok if r.get("home_status") == 200]
    plat = {}
    for r in reach:
        plat.setdefault(r["platform"], []).append(r)

    L = [f"<h2>{html.escape(S.t('lb.by_platform', lang))}</h2>",
         "<table><tr>"
         f"<th>{html.escape(S.t('lb.th_platform', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_n', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_ucp', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_product', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_llms', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_avg', lang))}</th></tr>"]
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
    L.append(f"<h2>{html.escape(S.t('lb.method', lang))}</h2>")
    L.append("<ul class='note'>")
    L.append("<li>" + S.t("lb.m1", lang, date=date, scanned=len(rows), reach=len(reach),
                          unreach=len(un), n403=n403) + "</li>")
    L.append("<li>" + S.t("lb.m2", lang) + "</li>")
    L.append("<li>" + S.t("lb.m3", lang, n=len(plat.get("WooCommerce", []))) + "</li>")
    L.append("<li>" + S.t("lb.m4", lang) + "</li>")
    L.append("<li>" + S.t("lb.m5", lang) + "</li>")

    # 环比：数字每天都在变，不解释清楚，引用方拿到的前后不一致会直接质疑数据
    prev = _prev_snapshot(date)
    if prev:
        pdate, p = prev
        pr = [r for r in p["rows"] if not r.get("error") and r.get("home_status") == 200]
        pu = sum(1 for r in pr if r.get("ucp"))
        cu = sum(1 for r in reach if r.get("ucp"))

        def delta(a, b):
            d = b - a
            sign = "+" if d >= 0 else ("−" if lang == "zh" else "-")
            return f"{b}（{sign}{abs(d)}）"

        L.append("<li>" + S.t("lb.m6", lang, pdate=pdate,
                              reach_delta=delta(len(pr), len(reach)),
                              ucp_delta=delta(pu, cu)) + "</li>")
    L.append("</ul>")

    L.append("<h2>" + S.t("lb.detail", lang, reach=len(reach), scanned=len(rows)) + "</h2>")
    L.append("<table><tr>"
             f"<th>{html.escape(S.t('lb.th_site', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_platform', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_avg', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_ucp', lang))}</th></tr>")
    dash = S.t("lb.dash", lang)
    for r in sorted(reach, key=lambda r: -r["score"]):
        L.append(f"<tr><td>{html.escape(r['site'].replace('https://',''))}</td>"
                 f"<td>{html.escape(r['platform'])}</td><td>{r['score']}</td>"
                 f"<td>{html.escape(r['ucp'] or dash)}</td></tr>")
    L.append("</table>")
    if un:
        L.append(f"<p class='note'>{S.t('lb.note_unreach', lang, n=len(un))}</p>")
    _LB["mtime"], _LB[lang] = mt, "\n".join(L)
    return _LB[lang]


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

    def lang(self):
        """?lang=zh 优先，其次 cookie，默认英文。"""
        q = parse_qs(urlparse(self.path).query)
        cookie = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("lang="):
                cookie = part.strip()[len("lang="):]
        return lang_of((q.get("lang") or [""])[0], cookie)

    def _leaderboard_body(self, lang=S.DEFAULT):
        e = html.escape
        return (f"<html lang='{lang}'><head><meta charset='utf-8'>"
                f"<title>{e(S.t('lb.title', lang))}</title>"
                f"<meta name='description' content=\"{e(S.t('og.lb_desc', lang))}\">"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content=\"{e(S.t('og.lb_title', lang))}\">"
                f"<meta property='og:description' content=\"{e(S.t('og.lb_desc', lang))}\">"
                f"<meta property='og:url' content='https://agentbi.tech/leaderboard'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/leaderboard'>"
                f"<link rel='alternate' hreflang='en' href='https://agentbi.tech/leaderboard'>"
                f"<link rel='alternate' hreflang='zh' href='https://agentbi.tech/leaderboard?lang=zh'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>{e(S.t('lb.title', lang))}</h1>"
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('lb.back', lang))}</a></p>"
                f"{render_leaderboard(lang)}"
                f"{sub_block(lang, False)}"
                f"<p class='note'><a href='{self._alt(lang)}'>{self._alt_label(lang)}</a></p>"
                f"{sub_script(lang)}"
                f"</body></html>").encode()

    def _qs(self, lang):
        return f"?lang={lang}" if lang != S.DEFAULT else ""

    def _alt(self, lang):
        base = urlparse(self.path).path or "/"
        return f"{base}?lang=zh" if lang == S.DEFAULT else base

    def _alt_label(self, lang):
        return "中文" if lang == S.DEFAULT else "English"

    def _send_html(self, body, cache="public, max-age=300"):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def _send_page(self, name, lang):
        body = render_page(name, lang).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=300")
        # 语言要粘住：不带 cookie 的话点进榜单就掉回英文
        self.send_header("Set-Cookie", f"lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        return self.wfile.write(body)

    def do_HEAD(self):
        # 不覆盖 do_HEAD 的话，HEAD /leaderboard 会走静态文件逻辑返回 404，
        # 社交卡片校验器和部分爬虫会被误导
        u = urlparse(self.path)
        if u.path in ("/leaderboard", "/leaderboard.html"):
            return self._send_html(self._leaderboard_body(self.lang()))
        if u.path in ("/about", "/about.html"):
            self.path = "/about.html"
        return super().do_HEAD()

    def do_GET(self):
        u = urlparse(self.path)
        lang = self.lang()

        if u.path == "/api/check":
            q = parse_qs(u.query)
            url = (q.get("url") or [""])[0].strip()
            if not URL_RE.match(url):
                return self._json({"error": S.t("err.bad_url", lang)}, 400)
            if not rate_ok(self.client_ip()):
                return self._json({"error": S.t("err.rate", lang)}, 429)
            try:
                res, cached = do_check(url, lang)
            except Exception as e:
                return self._json({"error": f"{type(e).__name__}"}, 500)
            return self._json({"cached": cached, "result": res})

        if u.path in ("/", "/index.html"):
            return self._send_page("index.html", lang)

        if u.path in ("/leaderboard", "/leaderboard.html"):
            body = self._leaderboard_body(lang)
            self._send_html(body)
            return self.wfile.write(body)

        if u.path in ("/about", "/about.html"):
            return self._send_page("about.html", lang)

        return super().do_GET()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/subscribe":
            return self._json({"error": "not found"}, 404)
        lang = self.lang()
        ip = self.client_ip()

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4096:            # 一个邮箱地址不该超过这个数
            return self._json({"error": S.t("sub.err_fail", lang)}, 400)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        try:
            raw = self.rfile.read(length).decode("utf-8", "replace")
            if ctype == "application/json":
                email = (json.loads(raw).get("email") or "").strip().lower()
            else:
                email = (parse_qs(raw).get("email") or [""])[0].strip().lower()
        except Exception:
            email = ""

        if not EMAIL_RE.match(email):
            return self._json({"error": S.t("sub.err_invalid", lang)}, 400)
        if not sub_rate_ok(ip):
            return self._json({"error": S.t("sub.err_rate", lang)}, 429)

        # 记邮箱 + 时间戳 + 来源 + 语言。**不记 IP**——订阅只需要这三样，
        # 多记的每一条都是出事时要解释的东西。IP 只用于限流，用完即弃。
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "email": email, "src": (parse_qs(u.query).get("src") or [""])[0][:16],
               "lang": lang}
        try:
            with _sub_lock:
                seen = set()
                if os.path.exists(SUBSCRIBERS):
                    with open(SUBSCRIBERS, encoding="utf-8") as f:
                        for line in f:
                            try:
                                seen.add(json.loads(line).get("email"))
                            except Exception:
                                pass
                if email not in seen:
                    with open(SUBSCRIBERS, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            return self._json({"error": S.t("sub.err_fail", lang)}, 500)

        # 已订阅和首次订阅返回同一句：不泄露某个邮箱在不在库里
        return self._json({"ok": True, "msg": S.t("sub.ok", lang)})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(f"http://{a.host}:{a.port}  （仅本机可访问；对外部署前需自行加固）")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()
