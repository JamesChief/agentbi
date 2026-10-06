#!/usr/bin/env python3
"""agentbi v0 —— 网站的 AI agent 友好度检测。

用法:
    python3 agentbi.py https://example.com
    python3 agentbi.py https://example.com --json
    python3 agentbi.py https://example.com --no-probe     # 只做静态检查，不做多 UA 探测

设计原则:
  * **不给无法归因的结论**。若探测器自己所在网络就访问不了（403/超时/被地区封），
    明确输出 inconclusive，而不是把账算在站点"拦截 agent"头上。
  * 协议层（ACP/UCP/AP2）目前只做**证据探针**，不计入评分——站点侧标识尚未一手核实，
    编造路径会给出错误结论。
"""
import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

# 对外服务时用于内容抓取的诚实标识（用户 2026-10-05 决定：不用伪装 UA）。
# 上线前把 SCANNER_CONTACT 换成真实域名。
SCANNER_CONTACT = "https://agentbi.tech/about"
UA_SCANNER = f"agentbi/0.1 (+{SCANNER_CONTACT}; agent-readiness scanner)"

# 仅作**对照测量**用：多 UA 探测要回答"这个站是否把 AI agent 和正常访客区别对待"，
# 对照组必须是真实访客的 UA，否则测不出来。这是测量工具，不是伪装——
# 内容抓取一律用上面的 UA_SCANNER。
UA_BROWSER = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# JSON-LD 可能出现在页面极靠后的位置（实测 Shopify 商品页在 74 万字符处），
# 截断过短会直接漏判"没有结构化数据"。2M 已覆盖绝大多数页面。
MAX_TEXT = 2_000_000

# 主流 AI agent 的公开 UA。这是壁垒①(agent 指纹库)的起点，需持续维护。
AGENTS = {
    "GPTBot": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "ClaudeBot": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "PerplexityBot": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
    "Amazonbot": "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
    "Applebot-Extended": "Mozilla/5.0 (compatible; Applebot-Extended/0.1; +http://www.apple.com/go/applebot)",
    "Bytespider": "Mozilla/5.0 (compatible; Bytespider; https://zhanzhang.toutiao.com/)",
}

LD_JSON = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S)


# ------------------------------------------------------------------ fetching

# 完整浏览器头部指纹。实测（2026-10-05）：加上 sec-ch-ua / sec-fetch-* / upgrade-insecure-requests
# 后，12 个原本 403 的站里救回 2 个（williams-sonoma、sephora）；不加这些头会被 WAF 直接挡。
# 注意不要声明 br/zstd 编码——本机无 brotli，服务端真返回 br 会拿到乱码。
BASE_HEADERS = {
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Sec-CH-UA": '"Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Linux"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def _headers(ua):
    """**多 UA 探测时必须让所有 UA 用同一套头部，只改 User-Agent。**
    否则 agent UA 因缺少浏览器指纹被 WAF 挡下，会被误判成"该站专门拦 agent"。"""
    h = dict(BASE_HEADERS)
    h["User-Agent"] = ua
    return h


def is_safe_url(url):
    """SSRF 防护：只放行公网 http/https 标准端口。

    网页版要接受用户输入的任意网址，没有这层防护就等于开放一个内网代理——
    攻击者可以用它探测内网服务、云元数据端点（169.254.169.254）等。
    重定向也必须逐跳校验，否则可以 302 到内网绕过。
    """
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if p.port not in (None, 80, 443, 8080, 8443):
        return False
    host = p.hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except Exception:
            return False
        # is_global 排除 私有/回环/链路本地(含 169.254 云元数据)/保留/未指定
        if not ip.is_global:
            return False
    return True


def fetch(url, ua, timeout=15):
    """GET 一次，逐跳校验重定向目标。任何失败都体现在 status=0 / error，不抛异常。"""
    out = {"url": url, "status": 0, "final_url": url, "bytes": 0,
           "text": "", "error": None, "headers": {}}
    if not is_safe_url(url):
        out["error"] = "BlockedURL"
        return out
    cur = url
    try:
        for _ in range(6):
            r = requests.get(cur, headers=_headers(ua), timeout=timeout,
                             allow_redirects=False)
            loc = r.headers.get("location")
            if r.is_redirect and loc:
                nxt = urljoin(cur, loc)
                if not is_safe_url(nxt):
                    out["error"] = "BlockedRedirect"
                    out["status"] = r.status_code
                    return out
                cur = nxt
                continue
            out.update(status=r.status_code, final_url=cur, headers=dict(r.headers),
                       bytes=len(r.content), text=r.text[:MAX_TEXT])
            return out
        out["error"] = "TooManyRedirects"
    except Exception as e:
        out["error"] = type(e).__name__
    return out


# ------------------------------------------------------------ structured data

def jsonld_nodes(text):
    nodes = []
    for m in LD_JSON.finditer(text):
        try:
            data = json.loads(m.group(1).strip())
        except Exception:
            continue
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                nodes.append(cur)
                stack.extend(v for v in cur.values() if isinstance(v, (dict, list)))
            elif isinstance(cur, list):
                stack.extend(cur)
    return nodes


def _types(node):
    t = node.get("@type")
    if isinstance(t, list):
        return {str(x).lower() for x in t}
    return {str(t).lower()} if t else set()


def find_product(nodes):
    """返回 (product_node, offer_node)。Product 可能写作 Product/ProductGroup/IndividualProduct。"""
    prod = offer = None
    for n in nodes:
        ts = _types(n)
        if prod is None and any("product" in t for t in ts):
            prod = n
        if offer is None and any(t in ("offer", "aggregateoffer") for t in ts):
            offer = n
    if prod and not offer:
        o = prod.get("offers")
        if isinstance(o, dict):
            offer = o
        elif isinstance(o, list) and o:
            offer = o[0] if isinstance(o[0], dict) else None
    return prod, offer


def check_structured(text):
    nodes = jsonld_nodes(text)
    prod, offer = find_product(nodes)
    r = {
        "jsonld_blocks": len(LD_JSON.findall(text)),
        "has_product": prod is not None,
        "has_offer": offer is not None,
        "fields": {},
        "missing": [],
    }
    if prod:
        for f in ("name", "brand", "sku", "gtin13", "gtin", "mpn", "image", "description"):
            if prod.get(f):
                r["fields"][f] = True
    if offer:
        for f in ("price", "priceCurrency", "availability", "itemCondition", "url"):
            if offer.get(f):
                r["fields"][f] = True
    want = ["name", "brand", "sku", "image", "description",
            "price", "priceCurrency", "availability"]
    r["missing"] = [f for f in want if f not in r["fields"]]
    return r


# -------------------------------------------------------------------- llms.txt

def check_llms(origin, ua, timeout=15):
    """llms.txt 必须是纯文本。SPA / soft-404 会对任意路径返回 200+HTML，
    只判状态码会把首页当成 llms.txt（实测 ombraz.com 就是 301 到 HTML）。"""
    r = fetch(urljoin(origin, "/llms.txt"), ua, timeout)
    body = r["text"] if r["status"] == 200 else ""
    redirected = urlparse(r["final_url"]).path.rstrip("/").lower() != "/llms.txt"
    is_html = bool(re.search(r"^\s*(<!doctype|<html|<script)", body, re.I))
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    links = [l for l in lines if l.startswith(("-", "*", "[")) or l.startswith("http")]
    present = (r["status"] == 200 and len(lines) > 0 and not is_html and not redirected)
    return {"status": r["status"], "bytes": r["bytes"], "lines": len(lines),
            "links": len(links), "present": present, "redirected": redirected,
            "is_html": is_html, "final_url": r["final_url"]}


# ------------------------------------------------------------------- robots.txt

AGENT_TOKENS = list(AGENTS.keys()) + ["Google-Extended", "CCBot", "anthropic-ai",
                                      "cohere-ai", "Diffbot", "omgili", "Timpibot"]


def check_robots(origin, ua, timeout=15):
    r = fetch(urljoin(origin, "/robots.txt"), ua, timeout)
    res = {"status": r["status"], "rules": {}, "wildcard_disallow": False, "present": False}
    if r["status"] != 200:
        return res
    res["present"] = True
    cur_agents, cur_allow = [], None
    for raw in r["text"].splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("user-agent:"):
            val = line.split(":", 1)[1].strip()
            cur_agents = [val]
            cur_allow = None
        elif low.startswith(("allow:", "disallow:")):
            kind, _, val = line.partition(":")
            val = val.strip()
            if cur_agents is None:
                continue
            if kind.lower() == "disallow" and val == "":
                cur_allow = True
            else:
                cur_allow = kind.lower() == "allow"
            for a in cur_agents:
                if a == "*":
                    if kind.lower() == "disallow" and val == "/":
                        res["wildcard_disallow"] = True
                    continue
                for tok in AGENT_TOKENS:
                    if tok.lower() in a.lower():
                        res["rules"].setdefault(tok, []).append(
                            ("allow" if cur_allow else "disallow", val))
    return res


# ----------------------------------------------------------------- UA 探测

PRICE_HINT = re.compile(
    r'(itemprop=["\']price|"price"\s*:|priceCurrency|\bUSD\s?\$|\$\s?\d)', re.I)


def probe_agents(url, timeout=15, delay=0.5):
    """用浏览器 UA + 各 agent UA 各 GET 一次，比较状态码与内容可读性。"""
    base = fetch(url, UA_BROWSER, timeout)
    res = {"browser": {k: base[k] for k in ("status", "bytes", "error")},
           "agents": {}, "blocked": [], "inconclusive": False, "note": None}
    base_ok = base["status"] == 200 and base["bytes"] > 0
    base_has_product = bool(jsonld_nodes(base["text"])) or bool(PRICE_HINT.search(base["text"]))

    if not base_ok:
        # 探测器自己都访问不了 —— 无法区分"拦 agent"和"地区/反爬/网络"，不给结论
        res["inconclusive"] = True
        res["note"] = (f"浏览器 UA 亦返回 {base['status'] or base['error']}，"
                       f"本探测器所在网络无法访问该站，多 UA 对比不可用（不归因于站点拦截）")
        return res

    for name, ua in AGENTS.items():
        time.sleep(delay)
        r = fetch(url, ua, timeout)
        ok = r["status"] == 200 and r["bytes"] > 0
        readable = bool(jsonld_nodes(r["text"])) or bool(PRICE_HINT.search(r["text"]))
        res["agents"][name] = {"status": r["status"], "bytes": r["bytes"],
                               "readable": readable, "error": r["error"]}
        if not ok:
            res["blocked"].append(name)
    res["browser"]["readable"] = base_has_product
    return res


# ------------------------------------------------------------------ 协议探针

# UCP 站点侧标识已一手核实（2026-10-05）：Shopify 店铺返回
# /.well-known/ucp → application/json，含 version / supported_versions / services。
# ACP / AP2 的站点侧标识尚未核实，只做证据探针、不计分。
UCP_PATH = "/.well-known/ucp"
UNVERIFIED_PROTO_PATHS = ["/.well-known/acp", "/.well-known/agent-commerce.json"]
PROTO_TOKENS = re.compile(r'\b(acp|ucp|ap2|agentic[- ]commerce)\b', re.I)


def check_ucp(origin, ua, timeout=12):
    """解析 UCP manifest。返回结构化的版本/服务信息，用于"落后几个版本"的判断。"""
    out = {"present": False, "status": 0, "version": None, "is_html": False,
           "supported_versions": [], "services": {}, "endpoints": [], "raw_bytes": 0}
    r = fetch(urljoin(origin, UCP_PATH), ua, timeout)
    out["status"], out["raw_bytes"] = r["status"], r["bytes"]
    if r["status"] != 200:
        return out
    # soft-404：有站点对任意路径返回 200 + HTML（实测 warbyparker 返回 190KB 的 Next.js
    # 错误页）。只判状态码会把"没部署"说成"返回 200"，故必须校验内容类型。
    if re.match(r"^\s*(<!doctype|<html)", r["text"], re.I):
        out["is_html"] = True
        return out
    try:
        u = json.loads(r["text"]).get("ucp", {})
    except Exception:
        return out
    out["present"] = True
    out["version"] = u.get("version")
    out["supported_versions"] = sorted(u.get("supported_versions", {}) or {}, reverse=True)
    for name, entries in (u.get("services") or {}).items():
        if isinstance(entries, list):
            out["services"][name] = [{"version": e.get("version"),
                                      "transport": e.get("transport"),
                                      "endpoint": e.get("endpoint")} for e in entries
                                     if isinstance(e, dict)]
            for e in entries:
                if isinstance(e, dict) and e.get("endpoint"):
                    out["endpoints"].append({"service": name, "endpoint": e["endpoint"],
                                             "transport": e.get("transport")})
    return out


def probe_unverified(origin, text, ua, timeout=8):
    """ACP / AP2：站点侧标识未核实，仅收集证据，不给结论。"""
    found = {"paths": {}, "tokens": sorted({m.lower() for m in PROTO_TOKENS.findall(text)})[:10]}
    for p in UNVERIFIED_PROTO_PATHS:
        r = fetch(urljoin(origin, p), ua, timeout)
        if r["status"] == 200:
            found["paths"][p] = r["bytes"]
    return found


# -------------------------------------------------------------- 平台识别

PLATFORM_SIGNALS = [
    ("Shopify", (r"cdn\.shopify\.com", r"myshopify\.com", r"Shopify\.theme",
                 r"x-shopify", r"/collections/"),),
    ("WooCommerce", (r"wp-content/plugins/woocommerce", r"woocommerce",
                     r"/wp-json/", r"wc-ajax")),
    ("Magento", (r"Mage\.Cookies", r"/static/version\d+", r"x-magento",
                 r"mage/cookies")),
    ("BigCommerce", (r"bigcommerce\.com", r"cdn\d+\.bigcommerce")),
    ("SalesforceCC", (r"demandware", r"/on/demandware", r"dwac_")),
    ("Shopware", (r"shopware",)),
    ("PrestaShop", (r"prestashop",)),
    ("Squarespace", (r"squarespace\.com",)),
    ("Wix", (r"wixstatic\.com", r"wix\.com")),
]


def detect_platform(headers, text):
    """按 HTTP 头 + HTML 特征识别电商平台。识别不出返回 Unknown。"""
    hay = " ".join(f"{k}:{v}" for k, v in headers.items()).lower() + "\n" + text.lower()
    hit = []
    for name, pats in PLATFORM_SIGNALS:
        for p in pats:
            if re.search(p, hay):
                hit.append(name)
                break
    # Shopify 特征最独特，优先；多个命中时取第一个
    order = ["Shopify", "WooCommerce", "Magento", "BigCommerce", "SalesforceCC",
             "Shopware", "PrestaShop", "Squarespace", "Wix"]
    for n in order:
        if n in hit:
            return n
    return "Unknown"


# ---------------------------------------------------------------------- 评分

def score(probe, struct, llms, robots, ucp):
    s, detail, skipped = 0, {}, []

    # 可抓取性 35
    if probe.get("skipped"):
        skipped.append(("fetch", 35))
        detail["fetch"] = "未测（--no-probe）"
    elif probe.get("inconclusive"):
        detail["fetch"] = "不可判定（探测器网络受限，不计分）"
        skipped.append(("fetch", 35))
    else:
        ags = probe.get("agents", {})
        ok = [n for n, v in ags.items() if v["status"] == 200 and v["bytes"] > 0]
        readable = [n for n in ok if ags[n]["readable"]]
        grab = 18 if len(ok) >= len(ags) / 2 else (8 if ok else 0)
        if len(ok) == len(ags) and ags:
            grab += 9
        if readable:
            grab += 8 if len(readable) == len(ok) else 4
        detail["fetch"] = (f"{len(ok)}/{len(ags)} 个 agent 可取到页面，"
                           f"{len(readable)} 个能读到产品/价格数据")
        s += grab

    # 结构化产品数据 30
    sd = 0
    if struct["has_product"]:
        sd += 12
    if struct["has_offer"]:
        sd += 6
    for f, w in (("price", 5), ("priceCurrency", 2), ("availability", 3)):
        if f in struct["fields"]:
            sd += w
    if any(f in struct["fields"] for f in ("brand", "sku", "gtin13", "gtin", "mpn")):
        sd += 2
    if any(f in struct["fields"] for f in ("image", "description", "name")):
        sd += 5
    sd = min(sd, 30)          # 各分项权重之和为 35，按维度上限 30 截断
    detail["structured"] = ("Product JSON-LD 完整" if sd >= 26 else
                            "有部分产品数据" if sd else "未找到结构化产品数据")
    s += sd

    # UCP 15（已一手核实的站点侧标识）
    up = 0
    if ucp["present"]:
        up = 10
        if ucp["services"]:
            up += 3
        if ucp["endpoints"]:
            up += 2
        detail["ucp"] = (f"已部署 {ucp['version']}，"
                         f"{len(ucp['services'])} 个服务、{len(ucp['endpoints'])} 个 endpoint，"
                         f"兼容 {len(ucp['supported_versions'])} 个历史版本")
    elif ucp["is_html"]:
        detail["ucp"] = f"未部署（{UCP_PATH} 返回 HTML 页面，非 manifest）"
    else:
        detail["ucp"] = f"未部署（{UCP_PATH} 返回 {ucp['status']}）"
    s += up

    # llms.txt 10
    lm = 7 if llms["present"] else 0
    if llms["present"] and llms["links"] >= 3:
        lm += 3
    detail["llms"] = "有且含链接" if lm == 10 else ("有" if lm else "无")
    s += lm

    # robots 10
    rb = 0
    if robots["present"]:
        blocked_any = [t for t, rules in robots["rules"].items()
                       if any(k == "disallow" and v == "/" for k, v in rules)]
        if not blocked_any and not robots["wildcard_disallow"]:
            rb = 6
        if any(t in robots["rules"] for t in AGENTS):
            rb += 4
    else:
        rb = 6  # 没有 robots.txt 等价于默认放行
    detail["robots"] = f"拦 {len(blocked_any) if robots['present'] else 0} 类 agent" if robots["present"] else "无 robots.txt（默认放行）"
    s += rb

    # 未测的维度不计入分母，按已测维度折算回百分制
    max_got = 100 - sum(w for _, w in skipped)
    total = min(100, round(s / max_got * 100) if max_got and skipped else s)
    detail["_skipped"] = [k for k, _ in skipped]
    return total, detail


# ------------------------------------------------------------------ 修复建议

def fixes(struct, llms, robots, probe, ucp, protos):
    out = []
    if not ucp["present"]:
        out.append(("部署 UCP manifest", "高",
                    f"{UCP_PATH} 返回 {ucp['status']}。UCP 已有一手核实的站点侧标识，"
                    f"Shopify 部分店铺已自动部署（实测版本 2026-08-25）。"
                    f"缺它意味着 shopping agent 无法按标准流程发现你的商品与下单入口。"))
    elif len(ucp["supported_versions"]) <= 1:
        out.append(("UCP 只声明单一版本", "中",
                    f"当前 {ucp['version']}。多声明历史版本可兼容尚未升级的 agent。"))
    if not llms["present"]:
        out.append(("加 /llms.txt", "高",
                    "给 agent 一份纯文本站点地图：核心页面 + 一句话说明。放站点根目录。"))
    if not struct["has_product"]:
        out.append(("加 Product JSON-LD", "高",
                    "商品页嵌 <script type=\"application/ld+json\">，@type=Product，"
                    "含 name/brand/sku/image/description。"))
    if struct["has_product"] and "price" not in struct["fields"]:
        out.append(("补齐 Offer 价格", "高",
                    "Product.offers 里给 price、priceCurrency、availability——"
                    "shopping agent 主要靠这三个字段判断是否可买。"))
    for f in struct["missing"]:
        if f in ("priceCurrency", "availability", "brand", "sku"):
            out.append((f"补 {f}", "中", "结构化数据字段缺失，agent 读到的信息不完整。"))
    if probe.get("blocked"):
        out.append((f"放行被拦的 agent: {', '.join(probe['blocked'])}", "高",
                    "robots.txt 或 WAF 把这些 agent 挡了，且浏览器 UA 没被挡——"
                    "属于只挡 agent，会直接损失 agent 带来的流量与订单。"))
    if robots.get("wildcard_disallow"):
        out.append(("检查 robots.txt 的 User-agent: * Disallow: /", "高",
                    "通配规则会一并挡住所有 agent。"))
    if protos["paths"] or protos["tokens"]:
        out.append((f"ACP/AP2 探针命中: {protos['paths'] or protos['tokens']}", "低",
                    "（站点侧标识尚未一手核实，仅作证据，不作为结论）"))
    seen, uniq = set(), []
    for t, p, d in out:
        if t not in seen:
            seen.add(t)
            uniq.append((t, p, d))
    return uniq


# ---------------------------------------------------------------------- main

PRODUCT_LINK = re.compile(r'href=["\']([^"\']*(?:/products?/|/p/|/item/|/dp/)[^"\']*)["\']', re.I)


def discover_product_url(home_text, base):
    """从首页找第一个像商品页的链接。电商首页通常没有 Product JSON-LD，商品页才有。"""
    seen = set()
    for m in PRODUCT_LINK.finditer(home_text):
        u = urljoin(base, m.group(1)).split("#")[0].split("?")[0]
        if u not in seen:
            seen.add(u)
            return u
    return None


def run(url, timeout=15, do_probe=True, discover=False, product_url=None, unverified=False):
    if not urlparse(url).scheme:
        url = "https://" + url
    origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    home = fetch(url, UA_SCANNER, timeout)
    if home["status"] == 0:
        return {"url": url, "error": f"无法访问：{home['error']}"}

    target, target_kind = url, "homepage"
    if product_url:
        target, target_kind = product_url, "product-page(given)"
    elif discover:
        p = discover_product_url(home["text"], home["final_url"])
        if p:
            target, target_kind = p, "product-page(discovered)"

    page = home if target == url else fetch(target, UA_SCANNER, timeout)
    struct = check_structured(page["text"])
    llms = check_llms(origin, UA_SCANNER, timeout)
    robots = check_robots(origin, UA_SCANNER, timeout)
    ucp = check_ucp(origin, UA_SCANNER)
    protos = (probe_unverified(origin, home["text"], UA_SCANNER) if unverified
              else {"paths": {}, "tokens": []})
    platform = detect_platform(home["headers"], home["text"])

    if do_probe:
        probe = probe_agents(target, timeout)
    else:
        probe = {"skipped": True, "agents": {}, "blocked": [],
                 "browser": {"status": page["status"], "bytes": page["bytes"]},
                 "note": "已跳过多 UA 探测（--no-probe）"}
    total, detail = score(probe, struct, llms, robots, ucp)

    return {"url": url, "checked_url": target, "checked_kind": target_kind,
            "platform": platform,
            "home_status": home["status"],
            "score": total, "detail": detail, "structured": struct, "llms": llms,
            "robots": robots, "ucp": ucp, "probe": probe, "protocols": protos,
            "fixes": fixes(struct, llms, robots, probe, ucp, protos)}


def render(r):
    if r.get("error"):
        return f"✗ {r['url']}: {r['error']}"
    L = [f"\nagentbi  ·  {r['url']}", "=" * 64,
         f"检测对象  {r['checked_url']}  ({r['checked_kind']})",
         f"得分  {r['score']}/100"
         + (f"   [未测: {', '.join(r['detail']['_skipped'])}]" if r["detail"]["_skipped"] else "")
         + "\n"]
    for k in ("fetch", "structured", "ucp", "llms", "robots"):
        L.append(f"  {k:12} {r['detail'][k]}")
    p = r["probe"]
    if p.get("inconclusive"):
        L.append(f"\n  ⚠ {p['note']}")
    elif p.get("agents"):
        L.append("\n  多 UA 探测:")
        L.append(f"    {'browser':18} {p['browser']['status']}  "
                 f"{p['browser']['bytes']}B  {'可读' if p['browser'].get('readable') else '—'}")
        for n, v in p["agents"].items():
            mark = "✗ 被拦" if v["status"] != 200 or v["bytes"] == 0 else "✓"
            L.append(f"    {n:18} {v['status']}  {v['bytes']}B  "
                     f"{'可读' if v['readable'] else '—'}  {mark}")
    u = r["ucp"]
    if u["present"]:
        L.append("\n  UCP manifest:")
        L.append(f"    version {u['version']}  历史版本 {', '.join(u['supported_versions'])}")
        for name, entries in u["services"].items():
            L.append(f"    service {name}")
            for e in entries[:3]:
                L.append(f"      {e['version']}  {e['transport']}  {e['endpoint']}")
    if r["protocols"]["paths"] or r["protocols"]["tokens"]:
        L.append(f"\n  ACP/AP2 探针（未核实）: {r['protocols']}")
    if r["fixes"]:
        L.append("\n  修复清单:")
        for t, pri, d in r["fixes"]:
            L.append(f"    [{pri}] {t}\n         {d}")
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="网站的 AI agent 友好度检测")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-probe", action="store_true", help="跳过多 UA 探测")
    ap.add_argument("--discover", action="store_true", help="自动找一个商品页来检测")
    ap.add_argument("--product-url", help="指定商品页 URL")
    ap.add_argument("--timeout", type=int, default=15)
    a = ap.parse_args()
    res = run(a.url, a.timeout, not a.no_probe, a.discover, a.product_url)
    print(json.dumps(res, ensure_ascii=False, indent=1) if a.json else render(res))
