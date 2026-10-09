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
import categories as C
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


def sub_block(lang):
    """订阅框。只放在榜单页——首页放过一版，结论是挡在检测流程里很碍事。

    注意：别用 .sub 做 class，那已经是站点副标题的（见 style.css）。
    """
    e = html.escape
    return (f"<div class='subscribe'>"
            f"<h3>{e(S.t('sub.title', lang))}</h3>"
            f"<form class='subscribe-form' novalidate>"
            f"<p class='subscribe-desc'>{e(S.t('sub.desc_long', lang))}</p>"
            f"<input type='email' name='email' class='subscribe-email' "
            f"placeholder=\"{e(S.t('sub.placeholder', lang))}\" autocomplete='email' required>"
            f"<button type='submit'>{e(S.t('sub.button', lang))}</button>"
            f"</form>"
            f"<p class='subscribe-consent'>{e(S.t('sub.consent', lang))}</p>"
            f"<p class='subscribe-msg' role='status'></p>"
            f"</div>")


def sub_script(lang):
    """给 JS 用的订阅文案 + 处理脚本。

    榜单页是 Python 直接拼出来的，不走 index.html 的模板，所以文案要单独喂一次。
    """
    keys = {k: v for k, v in S.STR.get(lang, S.STR[S.DEFAULT]).items()
            if k.startswith("sub.")}
    return ("<script>window.__SUB_L=" + json.dumps(keys, ensure_ascii=False) + ";</script>"
            "<script src='/sub.js' defer></script>")


def render_page(name, lang):
    """静态页是模板：先填运行时值（语言、查询串、给 JS 用的文案），再套文案表。"""
    raw = open(os.path.join(WEB, name), encoding="utf-8").read()
    js_keys = {k: v for k, v in S.STR.get(lang, S.STR[S.DEFAULT]).items()
               if k.startswith(("dim.", "rep.", "pri.", "site."))}
    vals = {
        "html.lang": lang,
        "qs": f"?lang={lang}" if lang != S.DEFAULT else "",
        "json.qs": json.dumps(f"&lang={lang}" if lang != S.DEFAULT else ""),
        "json.lang": json.dumps(js_keys, ensure_ascii=False),
        "alt_href": "/?lang=zh" if lang == S.DEFAULT else "/",
        "alt_lang": "中文" if lang == S.DEFAULT else "English",
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

    # ---- 1. UCP 端点普查 ----------------------------------------------------
    # 口径与首页可达性解耦：首页被 WAF 拦住，well-known 路径照样可能返回内容。
    # 之前用"首页 200"做闸门，把 ridge / farfetch / chewy / theiconic 四个阳性
    # 静默丢了——而它们正是头部零售商。见 ucp#904 与 #867。
    def bucket(r):
        s = r.get("ucp_status")
        if r.get("ucp"):
            return "pos"
        # 被 robots 拒绝的单独成桶：这不是"没部署"也不是"连不上"，
        # #867 的 frame 要求把 robots refusals 单独计数。
        if r.get("ucp_robots_refused"):
            return "robots"
        if s == 200:
            return "noparse"
        # 3xx 单独成桶：规范说 profile 端点 MUST NOT 用重定向、实现 MUST NOT 跟随
        # （ucp#904，frmoretto）。跟随了就分不清"部署了但重定向"和"没部署"。
        if 300 <= (s or 0) < 400:
            return "3xx"
        if s == 404:
            return "404"
        if s == 410:
            return "410"
        if s == 403:
            return "403"
        if s in (429, 418, 503):
            return "rate"
        if not s:
            return "err"
        return "other"

    order = [("pos", "b_pos"), ("noparse", "b_noparse"), ("3xx", "b_3xx"),
             ("robots", "b_robots"),
             ("404", "b_404"),
             ("410", "b_410"), ("403", "b_403"), ("rate", "b_rate"),
             ("err", "b_err"), ("other", "b_other")]
    buckets = {}
    for r in rows:
        buckets.setdefault(bucket(r), []).append(r)

    L = [f"<h2>{html.escape(S.t('lb.h_census', lang))}</h2>",
         f"<p class='note'>{S.t('lb.census_note', lang)}</p>",
         "<table><tr>"
         f"<th>{html.escape(S.t('lb.th_bucket', lang))}</th>"
         f"<th>{html.escape(S.t('lb.th_n', lang))}</th></tr>"]
    for k, key in order:
        if not buckets.get(k):
            continue
        L.append(f"<tr><td>{html.escape(S.t('lb.' + key, lang))}</td>"
                 f"<td>{len(buckets[k])}</td></tr>")
    L.append("</table>")

    # ---- 2. 阳性：版本与平台 ------------------------------------------------
    pos = [r for r in rows if r.get("ucp")]
    if pos:
        vers, pplat = {}, {}
        for r in pos:
            vers[r["ucp"]] = vers.get(r["ucp"], 0) + 1
            pplat[r.get("platform", "?")] = pplat.get(r.get("platform", "?"), 0) + 1
        vstr = ", ".join(f"<code>{html.escape(v)}</code> ×{n}"
                         for v, n in sorted(vers.items(), reverse=True))
        pstr = ", ".join(f"{html.escape(p)} {n}" for p, n in
                         sorted(pplat.items(), key=lambda x: -x[1]))
        L.append(f"<h2>{html.escape(S.t('lb.h_pos', lang))}</h2>")
        L.append("<ul class='note'>")
        L.append("<li>" + S.t("lb.pos_ver", lang, versions=vstr) + "</li>")
        L.append("<li>" + S.t("lb.pos_plat", lang, platforms=pstr) + "</li>")
        L.append("<li>" + S.t("lb.decision_note", lang, n=len(pos),
                              shopify=pplat.get("Shopify", 0)) + "</li>")
        hid = [r for r in pos if r.get("home_status") != 200]
        if hid:
            hosts = ", ".join(f"<code>{html.escape(r['site'].replace('https://', ''))}</code>"
                              f" ({r.get('home_status')})" for r in hid)
            L.append("<li>" + S.t("lb.pos_hidden", lang, n=len(hid), hosts=hosts) + "</li>")
        L.append("</ul>")

    # ---- 3. 站点可读性（仍需首页 200）---------------------------------------
    hidden = sum(1 for r in pos if r.get("home_status") != 200)
    L.append(f"<h2>{html.escape(S.t('lb.h_read', lang))}</h2>")
    L.append(f"<p class='note'>{S.t('lb.read_note', lang, n=len(reach), hidden=hidden)}</p>")
    L.append("<table><tr>"
             f"<th>{html.escape(S.t('lb.th_platform', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_n', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_product', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_llms', lang))}</th>"
             f"<th>{html.escape(S.t('lb.th_avg', lang))}</th></tr>")
    for p in sorted(plat, key=lambda p: -len(plat[p])):
        g = plat[p]
        n = len(g)
        L.append(f"<tr><td>{html.escape(p)}</td><td>{n}</td>"
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
    L.append("<li>" + S.t("lb.f_frame", lang, scanned=len(rows)) + "</li>")

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


# ---- /trend 历史趋势（板块 2）--------------------------------------------
# 战略：AgentBI 转为长期内容资产，历史序列是唯一"时间买不到"的资产。
# 所以这里只做聚合（可被引用的一句话数字），不生成 225 个单站静态页——
# 单站历史走 /api/site-history，等数据攒够再决定要不要生成页面。
_HIST = os.path.join(HERE, "history")
_TR = {}                                  # {lang: (mtime, html)}


def _hist_mtime():
    if not os.path.isdir(_HIST):
        return 0.0
    try:
        return max(os.path.getmtime(os.path.join(_HIST, f))
                   for f in os.listdir(_HIST))
    except (ValueError, OSError):
        return 0.0


def _all_snapshots():
    """history/ 下全部每日快照，按日期升序。

    单个文件读坏就跳过——别让一个坏快照把整页拖挂。
    """
    if not os.path.isdir(_HIST):
        return []
    out = []
    for f in sorted(os.listdir(_HIST)):
        if not (f.startswith("batch-") and f.endswith(".json")):
            continue
        try:
            data = json.load(open(os.path.join(_HIST, f), encoding="utf-8"))
        except Exception:
            continue
        out.append((f[len("batch-"):-len(".json")], data))
    return out


def _snapshot_stats(data):
    """一个快照的三个可引用数字：平均分 / 可评估数 / 已部署 UCP 数。"""
    rows = [r for r in data.get("rows", []) if not r.get("error")]
    reach = [r for r in rows if r.get("home_status") == 200]
    scores = [r["score"] for r in reach if isinstance(r.get("score"), int)]
    avg = round(sum(scores) / len(scores)) if scores else None
    return avg, len(reach), sum(1 for r in reach if r.get("ucp"))


def _score_map(data):
    return {r["site"]: r["score"] for r in data.get("rows", [])
            if not r.get("error") and r.get("home_status") == 200
            and isinstance(r.get("score"), int)}


def _hist_movers(cur, prev, n=10):
    """进步/退步 Top n。只比两边都可评估的站——否则会把 WAF 波动当成真实变化。"""
    a, b = _score_map(prev), _score_map(cur)
    both = set(a) & set(b)
    diffs = [(b[s] - a[s], s, a[s], b[s]) for s in both]
    up = sorted([d for d in diffs if d[0] > 0], key=lambda x: -x[0])[:n]
    down = sorted([d for d in diffs if d[0] < 0], key=lambda x: x[0])[:n]
    return up, down


def render_trend(lang=S.DEFAULT):
    e = html.escape
    snaps = _all_snapshots()
    if not snaps:
        return f"<p>{e(S.t('tr.no_data', lang))}</p>"
    mt = _hist_mtime()
    cached = _TR.get(lang)
    if cached and cached[0] == mt:
        return cached[1]

    n_sites = len(snaps[-1][1].get("rows", []))
    L = [f"<p class='note'>{S.t('tr.intro', lang, n=n_sites)}</p>"]

    # ---- 1. 每日快照序列 ----
    L.append(f"<h2>{e(S.t('tr.h_series', lang))}</h2>")
    L.append("<table><tr>"
             f"<th>{e(S.t('tr.th_date', lang))}</th>"
             f"<th>{e(S.t('tr.th_avg', lang))}</th>"
             f"<th>{e(S.t('tr.th_reach', lang))}</th>"
             f"<th>{e(S.t('tr.th_ucp', lang))}</th></tr>")
    for date, data in snaps:                      # 升序：序列要能一眼读出走向
        avg, reach, ucp = _snapshot_stats(data)
        L.append(f"<tr><td>{e(date)}</td><td>{avg if avg is not None else '—'}</td>"
                 f"<td>{reach}</td><td>{ucp}</td></tr>")
    L.append("</table>")

    # ---- 2. 变化榜 ----
    if len(snaps) >= 2:
        cdate, cur = snaps[-1]
        pdate, prev = snaps[-2]
        up, down = _hist_movers(cur, prev)
        L.append(f"<h2>{e(S.t('tr.h_movers', lang, pdate=pdate, date=cdate))}</h2>")
        for label, rows in ((S.t("tr.up", lang), up), (S.t("tr.down", lang), down)):
            L.append(f"<h3>{e(label)}</h3>")
            if not rows:
                L.append(f"<p class='note'>{e(S.t('tr.none', lang))}</p>")
                continue
            L.append("<table><tr>"
                     f"<th>{e(S.t('lb.th_site', lang))}</th>"
                     f"<th>{e(S.t('tr.th_delta', lang))}</th></tr>")
            for d, site, old, new in rows:
                L.append(f"<tr><td>{e(site.replace('https://', ''))}</td>"
                         f"<td>{old} → {new} ({'+' if d > 0 else ''}{d})</td></tr>")
            L.append("</table>")
    else:
        L.append(f"<p class='note'>{e(S.t('tr.no_prev', lang))}</p>")

    # ---- 3. 方法与局限（每条数据要可引用就必须带这三要素）----
    L.append(f"<h2>{e(S.t('tr.method', lang))}</h2><ul>")
    for k in ("m1", "m2", "m3", "m4"):
        L.append("<li>" + S.t(f"tr.{k}", lang, n=n_sites) + "</li>")
    L.append("</ul>")
    L.append(f"<p class='note'>{S.t('tr.api_note', lang)}</p>")

    body = "\n".join(L)
    _TR[lang] = (mt, body)
    return body


# ---- /crawlers 爬虫准入普查（板块 4）--------------------------------------
# 数据源是 robots.txt 的 stated rule，不是实测行为——这个区别必须写在页面上，
# 否则引用方会把"写了规则"当成"真的能抓到"。
_CR = {}


def render_crawlers(lang=S.DEFAULT):
    e = html.escape
    if not os.path.exists(BATCH):
        return f"<p>{e(S.t('lb.no_data', lang))}</p>"
    mt = os.path.getmtime(BATCH)
    cached = _CR.get(lang)
    if cached and cached[0] == mt:
        return cached[1]

    data = json.load(open(BATCH))
    rows = [r for r in data.get("rows", []) if not r.get("error")]
    date = (str(data.get("generated_at") or ""))[:10]
    with_rb = [r for r in rows if r.get("robots_present")]
    n, m = len(rows), len(with_rb)

    counts = {}
    for r in with_rb:
        for a in (r.get("robots_blocked") or []):
            counts[a] = counts.get(a, 0) + 1
    wildcard = sum(1 for r in with_rb if r.get("robots_wildcard"))
    denom = m or 1                                 # 没有 robots.txt 的站不计入分母

    L = [f"<p class='note'>{S.t('cr.intro', lang, n=n, m=m)}</p>"]

    L.append("<table><tr>"
             f"<th>{e(S.t('cr.th_agent', lang))}</th>"
             f"<th>{e(S.t('cr.th_blocked', lang))}</th>"
             f"<th>{e(S.t('cr.th_pct', lang))}</th></tr>")
    # 全部 token 都列出来（包括 0）——"没人拦 GPTBot"本身也是一条可引用的信息
    for tok in sorted(A.AGENT_TOKENS, key=lambda t: (-counts.get(t, 0), t)):
        c = counts.get(tok, 0)
        L.append(f"<tr><td><code>{e(tok)}</code></td><td>{c}</td>"
                 f"<td>{c / denom:.1%}</td></tr>")
    L.append("</table>")
    if wildcard:
        L.append(f"<p class='note'>{S.t('cr.wildcard', lang, n=wildcard)}</p>")

    # 明细：哪些站拦了哪些
    blocked_rows = [r for r in with_rb if r.get("robots_blocked")]
    L.append(f"<h2>{e(S.t('cr.detail', lang))}</h2>")
    if not blocked_rows:
        L.append(f"<p class='note'>{e(S.t('cr.none', lang))}</p>")
    else:
        L.append("<table><tr>"
                 f"<th>{e(S.t('lb.th_site', lang))}</th>"
                 f"<th>{e(S.t('cr.th_blocked_list', lang))}</th></tr>")
        for r in sorted(blocked_rows, key=lambda r: -len(r.get("robots_blocked") or [])):
            L.append(f"<tr><td>{e(r['site'].replace('https://', ''))}</td>"
                     f"<td>{e(', '.join(r.get('robots_blocked') or []))}</td></tr>")
        L.append("</table>")

    L.append(f"<h2>{e(S.t('cr.method', lang))}</h2><ul>")
    L.append("<li>" + S.t("cr.m1", lang, k=len(A.AGENT_TOKENS), date=date) + "</li>")
    for k in ("m2", "m3", "m4"):
        L.append("<li>" + S.t(f"cr.{k}", lang) + "</li>")
    L.append("</ul>")

    body = "\n".join(L)
    _CR[lang] = (mt, body)
    return body


# ---- /protocols 信号采用度（板块 3）----------------------------------------
# 与 /leaderboard 的分工：榜单是 UCP 端点分桶普查 + 逐站打分；
# 这一页回答"各项信号各自有多少站有，以及**全部具备**的有多稀少"。
# 最后那个"全具备"的数字才是真正可引用的一句。
_PR = {}

# (key, 依赖字段, 判定)。依赖字段用于判断老快照能不能算这一项。
_SIGNALS = (
    ("ucp", "ucp", lambda r: bool(r.get("ucp"))),
    ("llms", "llms", lambda r: bool(r.get("llms"))),
    ("jsonld", "product_jsonld", lambda r: bool(r.get("product_jsonld"))),
    ("price", "price", lambda r: bool(r.get("price"))),
    ("availability", "availability", lambda r: bool(r.get("availability"))),
    ("robots_ok", "robots_present",
     lambda r: bool(r.get("robots_present")) and not (r.get("robots_blocked") or [])),
)


def _signal_counts(data):
    """一个快照里各项信号的站数。老快照缺字段的那项返回 None（未知，不是 0）。"""
    rows = [r for r in data.get("rows", []) if not r.get("error")]
    reach = [r for r in rows if r.get("home_status") == 200]
    out = {"reach": len(reach), "scanned": len(rows)}
    # 老快照可能没有某个字段（如 robots_present 是后来加的），缺的那项记 None：
    # "未知"不能显示成 0，否则看起来像"没有站满足条件"。
    computable = [k for k, field, _ in _SIGNALS if reach and field in reach[0]]
    out["computable"] = computable
    for k, field, fn in _SIGNALS:
        out[k] = sum(1 for r in reach if fn(r)) if k in computable else None
    # "全具备"只按能算的项统计，否则老快照会一律显示 0
    out["all"] = sum(1 for r in reach
                     if all(fn(r) for k, _, fn in _SIGNALS if k in computable))
    out["all_of"] = len(computable)
    return out


def render_protocols(lang=S.DEFAULT):
    e = html.escape
    snaps = _all_snapshots()
    if not snaps:
        return f"<p>{e(S.t('tr.no_data', lang))}</p>"
    mt = _hist_mtime()
    cached = _PR.get(lang)
    if cached and cached[0] == mt:
        return cached[1]

    date, cur = snaps[-1]
    c = _signal_counts(cur)
    reach = c["reach"] or 1
    L = [f"<p class='note'>{S.t('pr.intro', lang, n=c['reach'], date=date)}</p>"]

    L.append("<table><tr>"
             f"<th>{e(S.t('pr.th_signal', lang))}</th>"
             f"<th>{e(S.t('pr.th_n', lang))}</th>"
             f"<th>{e(S.t('pr.th_pct', lang))}</th></tr>")
    for k, _, _ in _SIGNALS:
        v = c.get(k)
        L.append(f"<tr><td>{e(S.t('pr.s_' + k, lang))}</td>"
                 f"<td>{v if v is not None else '—'}</td>"
                 f"<td>{f'{v / reach:.1%}' if v is not None else '—'}</td></tr>")
    L.append("</table>")

    L.append(f"<h2>{e(S.t('pr.all_title', lang))}</h2>")
    note = S.t("pr.all_note", lang, n=c["all"], reach=c["reach"],
               pct=f"{c['all'] / reach:.1%}", k=c["all_of"])
    L.append(f"<p class='note'>{note}</p>")

    # 序列：各信号随时间的变化（分母每天会变，所以给占比而不是绝对值）
    if len(snaps) >= 2:
        L.append(f"<h2>{e(S.t('pr.h_series', lang))}</h2>")
        L.append("<table><tr>"
                 f"<th>{e(S.t('tr.th_date', lang))}</th>"
                 f"<th>{e(S.t('tr.th_reach', lang))}</th>")
        for k, _, _ in _SIGNALS:
            L.append(f"<th>{e(S.t('pr.s_' + k, lang))}</th>")
        L.append("</tr>")
        for d, data in snaps:
            cc = _signal_counts(data)
            den = cc["reach"] or 1
            L.append(f"<tr><td>{e(d)}</td><td>{cc['reach']}</td>")
            for k, _, _ in _SIGNALS:
                v = cc.get(k)
                L.append(f"<td>{f'{v / den:.0%}' if v is not None else '—'}</td>")
            L.append("</tr>")
        L.append("</table>")

    L.append(f"<h2>{e(S.t('pr.method', lang))}</h2><ul>")
    L.append("<li>" + S.t("pr.m1", lang, date=date) + "</li>")
    L.append("<li>" + S.t("pr.m2", lang, reach=c["reach"], n=c["scanned"]) + "</li>")
    for k in ("m3", "m4"):
        L.append("<li>" + S.t(f"pr.{k}", lang) + "</li>")
    L.append("</ul>")

    body = "\n".join(L)
    _PR[lang] = (mt, body)
    return body


def _full_count(reach):
    """一组站点里"全部信号都具备"的数量。返回 (数量, 参与统计的信号数)。

    老快照缺字段时只按能算的项统计，否则会一律显示 0。
    """
    if not reach:
        return 0, 0
    computable = [k for k, field, _ in _SIGNALS if field in reach[0]]
    n = sum(1 for r in reach
            if all(fn(r) for k, _, fn in _SIGNALS if k in computable))
    return n, len(computable)


# ---- /categories 分品类基准（板块 1）----------------------------------------
# 品类是人工判定的（categories.py），这点必须在页面上写清楚：
# 不写明的话，别人会把"我们猜的品类"当成"站点自己申报的分类"来引用。
_CAT = {}


def render_categories(lang=S.DEFAULT):
    e = html.escape
    snaps = _all_snapshots()
    if not snaps:
        return f"<p>{e(S.t('tr.no_data', lang))}</p>"
    mt = _hist_mtime()
    cached = _CAT.get(lang)
    if cached and cached[0] == mt:
        return cached[1]

    date, data = snaps[-1]
    rows = [r for r in data.get("rows", []) if not r.get("error")]
    groups = {}
    for r in rows:
        groups.setdefault(C.categorize(r["site"]), []).append(r)

    L = [f"<p class='note'>{S.t('cat.intro', lang)}</p>"]
    L.append("<table><tr>"
             f"<th>{e(S.t('cat.th_cat', lang))}</th>"
             f"<th>{e(S.t('cat.th_reach', lang))}</th>"
             f"<th>{e(S.t('cat.th_avg', lang))}</th>"
             f"<th>{e(S.t('cat.th_ucp', lang))}</th>"
             f"<th>{e(S.t('cat.th_llms', lang))}</th>"
             f"<th>{e(S.t('cat.th_all', lang))}</th></tr>")

    stats = []
    for cat, g in groups.items():
        reach = [r for r in g if r.get("home_status") == 200]
        scores = [r["score"] for r in reach if isinstance(r.get("score"), int)]
        avg = round(sum(scores) / len(scores)) if scores else None
        full, n_sig = _full_count(reach)
        stats.append((cat, len(g), len(reach), avg,
                      sum(1 for r in reach if r.get("ucp")),
                      sum(1 for r in reach if r.get("llms")), full, n_sig))

    for cat, n, reach, avg, ucp, llms, full, n_sig in sorted(
            stats, key=lambda x: (-(x[3] if x[3] is not None else -1), -x[2])):
        den = reach or 1
        small = f" <i>({e(S.t('cat.small', lang))})</i>" if reach < 10 else ""
        L.append(f"<tr><td>{e(S.t('cat.c_' + cat, lang))}{small}</td>"
                 f"<td>{reach}</td>"
                 f"<td>{avg if avg is not None else '—'}</td>"
                 f"<td>{ucp / den:.0%}</td>"
                 f"<td>{llms / den:.0%}</td>"
                 f"<td>{full / den:.0%}</td></tr>")
    L.append("</table>")

    L.append(f"<h2>{e(S.t('cat.method', lang))}</h2><ul>")
    L.append("<li>" + S.t("cat.m1", lang, date=date) + "</li>")
    L.append("<li>" + S.t("cat.m2", lang) + "</li>")
    L.append("<li>" + S.t("cat.m3", lang) + "</li>")
    L.append("</ul>")

    body = "\n".join(L)
    _CAT[lang] = (mt, body)
    return body


def _site_history(site):
    """单站历史，按日期升序。

    匹配要宽容：用户会输入 allbirds.com / www.allbirds.com / https://www.allbirds.com/，
    这三种都得命中同一个站，否则接口看起来像坏了。
    """
    def norm(s):
        s = (s or "").strip().rstrip("/").replace("https://", "").replace("http://", "")
        return s.lower()
    target = norm(site)
    if not target:
        return []
    wanted = {target, "www." + target, target[4:] if target.startswith("www.") else target}
    out = []
    for date, data in _all_snapshots():
        for r in data.get("rows", []):
            if norm(r.get("site")) in wanted:
                out.append({"date": date, "score": r.get("score"),
                            "ucp": r.get("ucp"), "home_status": r.get("home_status")})
                break
    return out


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
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('lb.back', lang))}</a> · "
                f"<a href='/trend{self._qs(lang)}'>{e(S.t('site.tr_link', lang))}</a> · "
                # /categories 从首页挪过来了（首页只留 Leaderboard + Trend·Signals·Crawlers 两块），
                # 分品类基准跟榜单是一路的，放这儿比放首页合适
                f"<a href='/categories{self._qs(lang)}'>{e(S.t('site.cat_link', lang))}</a></p>"
                f"{render_leaderboard(lang)}"
                f"{sub_block(lang)}"
                f"<p class='note'><a href='{self._alt(lang)}'>{self._alt_label(lang)}</a></p>"
                f"{sub_script(lang)}"
                f"</body></html>").encode()

    def _trend_body(self, lang=S.DEFAULT):
        e = html.escape
        return (f"<html lang='{lang}'><head><meta charset='utf-8'>"
                f"<title>{e(S.t('tr.title', lang))}</title>"
                f"<meta name='description' content=\"{e(S.t('tr.desc', lang))}\">"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content=\"{e(S.t('tr.title', lang))}\">"
                f"<meta property='og:description' content=\"{e(S.t('tr.desc', lang))}\">"
                f"<meta property='og:url' content='https://agentbi.tech/trend'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/trend'>"
                f"<link rel='alternate' hreflang='en' href='https://agentbi.tech/trend'>"
                f"<link rel='alternate' hreflang='zh' href='https://agentbi.tech/trend?lang=zh'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>{e(S.t('tr.title', lang))}</h1>"
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('tr.back', lang))}</a> · "
                f"<a href='/leaderboard{self._qs(lang)}'>{e(S.t('site.lb_link', lang))}</a> · "
                f"<a href='/crawlers{self._qs(lang)}'>{e(S.t('site.cr_link', lang))}</a></p>"
                f"{render_trend(lang)}"
                f"{sub_block(lang)}"
                f"<p class='note'><a href='{self._alt(lang)}'>{self._alt_label(lang)}</a></p>"
                f"{sub_script(lang)}"
                f"</body></html>").encode()

    def _crawlers_body(self, lang=S.DEFAULT):
        e = html.escape
        return (f"<html lang='{lang}'><head><meta charset='utf-8'>"
                f"<title>{e(S.t('cr.title', lang))}</title>"
                f"<meta name='description' content=\"{e(S.t('cr.desc', lang, n=225))}\">"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content=\"{e(S.t('cr.title', lang))}\">"
                f"<meta property='og:description' content=\"{e(S.t('cr.desc', lang, n=225))}\">"
                f"<meta property='og:url' content='https://agentbi.tech/crawlers'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/crawlers'>"
                f"<link rel='alternate' hreflang='en' href='https://agentbi.tech/crawlers'>"
                f"<link rel='alternate' hreflang='zh' href='https://agentbi.tech/crawlers?lang=zh'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>{e(S.t('cr.title', lang))}</h1>"
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('tr.back', lang))}</a> · "
                f"<a href='/trend{self._qs(lang)}'>{e(S.t('site.tr_link', lang))}</a> · "
                f"<a href='/protocols{self._qs(lang)}'>{e(S.t('site.pr_link', lang))}</a></p>"
                f"{render_crawlers(lang)}"
                f"{sub_block(lang)}"
                f"<p class='note'><a href='{self._alt(lang)}'>{self._alt_label(lang)}</a></p>"
                f"{sub_script(lang)}"
                f"</body></html>").encode()

    def _protocols_body(self, lang=S.DEFAULT):
        e = html.escape
        return (f"<html lang='{lang}'><head><meta charset='utf-8'>"
                f"<title>{e(S.t('pr.title', lang))}</title>"
                f"<meta name='description' content=\"{e(S.t('pr.desc', lang))}\">"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content=\"{e(S.t('pr.title', lang))}\">"
                f"<meta property='og:description' content=\"{e(S.t('pr.desc', lang))}\">"
                f"<meta property='og:url' content='https://agentbi.tech/protocols'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/protocols'>"
                f"<link rel='alternate' hreflang='en' href='https://agentbi.tech/protocols'>"
                f"<link rel='alternate' hreflang='zh' href='https://agentbi.tech/protocols?lang=zh'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>{e(S.t('pr.title', lang))}</h1>"
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('tr.back', lang))}</a> · "
                f"<a href='/trend{self._qs(lang)}'>{e(S.t('site.tr_link', lang))}</a> · "
                f"<a href='/crawlers{self._qs(lang)}'>{e(S.t('site.cr_link', lang))}</a></p>"
                f"{render_protocols(lang)}"
                f"{sub_block(lang)}"
                f"<p class='note'><a href='{self._alt(lang)}'>{self._alt_label(lang)}</a></p>"
                f"{sub_script(lang)}"
                f"</body></html>").encode()

    def _categories_body(self, lang=S.DEFAULT):
        e = html.escape
        return (f"<html lang='{lang}'><head><meta charset='utf-8'>"
                f"<title>{e(S.t('cat.title', lang))}</title>"
                f"<meta name='description' content=\"{e(S.t('cat.desc', lang, n=225))}\">"
                f"<meta property='og:type' content='article'>"
                f"<meta property='og:site_name' content='AgentBI'>"
                f"<meta property='og:title' content=\"{e(S.t('cat.title', lang))}\">"
                f"<meta property='og:description' content=\"{e(S.t('cat.desc', lang, n=225))}\">"
                f"<meta property='og:url' content='https://agentbi.tech/categories'>"
                f"<meta name='twitter:card' content='summary'>"
                f"<link rel='canonical' href='https://agentbi.tech/categories'>"
                f"<link rel='alternate' hreflang='en' href='https://agentbi.tech/categories'>"
                f"<link rel='alternate' hreflang='zh' href='https://agentbi.tech/categories?lang=zh'>"
                f"<link rel='stylesheet' href='/style.css'></head><body>"
                f"<h1>{e(S.t('cat.title', lang))}</h1>"
                f"<p><a href='/{self._qs(lang)}'>{e(S.t('tr.back', lang))}</a> · "
                f"<a href='/protocols{self._qs(lang)}'>{e(S.t('site.pr_link', lang))}</a> · "
                f"<a href='/trend{self._qs(lang)}'>{e(S.t('site.tr_link', lang))}</a></p>"
                f"{render_categories(lang)}"
                f"{sub_block(lang)}"
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
        if u.path in ("/trend", "/trend.html"):
            return self._send_html(self._trend_body(self.lang()))
        if u.path in ("/crawlers", "/crawlers.html"):
            return self._send_html(self._crawlers_body(self.lang()))
        if u.path in ("/protocols", "/protocols.html"):
            return self._send_html(self._protocols_body(self.lang()))
        if u.path in ("/categories", "/categories.html"):
            return self._send_html(self._categories_body(self.lang()))
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

        if u.path in ("/trend", "/trend.html"):
            body = self._trend_body(lang)
            self._send_html(body)
            return self.wfile.write(body)

        if u.path in ("/crawlers", "/crawlers.html"):
            body = self._crawlers_body(lang)
            self._send_html(body)
            return self.wfile.write(body)

        if u.path in ("/protocols", "/protocols.html"):
            body = self._protocols_body(lang)
            self._send_html(body)
            return self.wfile.write(body)

        if u.path in ("/categories", "/categories.html"):
            body = self._categories_body(lang)
            self._send_html(body)
            return self.wfile.write(body)

        if u.path == "/api/site-history":
            q = parse_qs(u.query)
            site = (q.get("site") or [""])[0].strip()
            if not site:
                return self._json({"error": "site required"}, 400)
            return self._json({"site": site, "history": _site_history(site)})

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

        # 记邮箱 + 时间戳 + 语言。**不记 IP**——订阅只需要这三样，
        # 多记的每一条都是出事时要解释的东西。IP 只用于限流，用完即弃。
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "email": email, "lang": lang}
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
