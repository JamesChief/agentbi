#!/usr/bin/env python3
"""批量扫描，产出榜单数据。默认不做多 UA 探测（请求数 ×7，不礼貌且慢）。

用法:
    python3 scan_batch.py                      # 用内置默认站点列表（--dry，不碰真实数据）
    python3 scan_batch.py sites.txt            # 每行一个 URL
    python3 scan_batch.py sites.txt --probe    # 附带多 UA 探测
    python3 scan_batch.py --render             # 只从 batch.json 重渲染榜单，不发请求

**不带站点文件时默认 --dry**：小样本试跑已经三次把真实的 batch.json / leaderboard.md
覆盖掉，试跑必须显式加 --live 才写生产文件。
"""
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import agentbi as A
import requests

DEFAULT_SITES = [
    "https://www.allbirds.com",
    "https://www.deathwishcoffee.com",
    "https://www.gymshark.com",
    "https://us.huel.com",
    "https://www.kithandkin.co.uk",
    "https://www.chubbiesshorts.com",
    "https://www.beardbrand.com",
    "https://www.ombraz.com",
    "https://www.darngoodyarn.com",
    "https://bulk.com",
    "https://www.anthropic.com",
    "https://www.ikea.com",
    "https://www.target.com",
    "https://www.gap.com",
]


def ucp_fields(u):
    """UCP 端点探测结果。#867 报告框架要求把"200 但解析不了""404""410""被拒"
    分开报——不能折成一个"没部署"，否则不同普查的数字没法放在一张表里。"""
    return {
        "ucp": u["version"] if u["present"] else None,
        "ucp_status": u["status"],
        "ucp_ctype": u["ctype"],
        "ucp_is_html": bool(u["is_html"]),
        "ucp_bytes": u["raw_bytes"],
        "ucp_redirected": bool(u["redirected"]),
        # 3xx 单独一类：规范说 profile 端点 MUST NOT 跟随重定向（ucp#904）
        "ucp_3xx": bool(u.get("redirect_3xx")),
        "ucp_location_host": u.get("location_host"),
        "ucp_versions": len(u["supported_versions"]),
        "ucp_keys_field": u.get("keys_field"),
        "ucp_robots_refused": bool(u.get("robots_refused")),
        # frame v3：429 要带 Retry-After 值；hosting 行（可选）看缓存头与校验器
        "ucp_retry_after": u.get("retry_after"),
        "ucp_cache_public": bool(u.get("cache_public")),
        "ucp_has_validator": bool(u.get("has_validator")),
        "ucp_services": list(u["services"]),
    }


def server_card_fields(origin, c=None):
    """MCP server card 第二路由（仍为 proposal）。

    frmoretto 要求：只通过 server card 找到的 host 必须单独成行，
    **不能并进** /.well-known/ucp 的计数，所以这里独立成字段。
    """
    # c 可直接传 check_server_card 的结果（run() 已用规范 host 探过一次，别再探第二遍）
    if not (isinstance(c, dict) and "present" in c):
        c = A.check_server_card(origin, A.UA_SCANNER)
    return {"server_card": bool(c["present"]),
            "server_card_robots_refused": bool(c.get("robots_refused")),
            "server_card_status": c["status"],
            "server_card_is_json": bool(c["is_json"])}


def detect_vantage(timeout=10):
    """探测所在国。geo-redirect 的结果取决于探测位置，所以必须写进运行字段
    （ucp#904 frmoretto 明确要求）。失败就记 unknown，不猜。

    **不记 ip**：batch.json 是公开仓库里的文件，探测机的公网 IP 等于把它暴露出来
    （国家/城市/ASN 已经足够说明 vantage，IP 没有额外信息量）。
    """
    try:
        r = requests.get("https://ipinfo.io/json", timeout=timeout)
        d = r.json()
        return {"country": d.get("country"), "city": d.get("city"),
                "org": d.get("org")}
    except Exception as e:
        return {"country": None, "error": type(e).__name__}


def origin_of(url):
    if not urlparse(url).scheme:
        url = "https://" + url
    return f"{urlparse(url).scheme}://{urlparse(url).netloc}"


def one(url, do_probe):
    try:
        r = A.run(url, timeout=15, do_probe=do_probe, discover=True)
        if r.get("error"):
            # 首页连不上不等于 well-known 路径连不上。run() 在首页不可达时就返回了，
            # 但普查的口径是"UCP 端点探过没有"，所以这里单独再探一次——
            # 否则"无法询问"会被静默记成"没部署"。
            row = {"site": url, "error": r["error"], "home_status": 0, "platform": "?"}
            row.update(ucp_fields(A.check_ucp(origin_of(url), A.UA_SCANNER)))
            row.update(server_card_fields(origin_of(url)))
            return row
        return {
            "site": url,
            "platform": r["platform"],
            "home_status": r["home_status"],
            "checked": r["checked_url"],
            "score": r["score"],
            **ucp_fields(r["ucp"]),
            **server_card_fields(origin_of(url), r["server_card"]),
            "product_jsonld": r["structured"]["has_product"],
            "price": "price" in r["structured"]["fields"],
            "availability": "availability" in r["structured"]["fields"],
            "llms": r["llms"]["present"],
            # 存明细而不只是布尔值：/crawlers 普查页要按 agent 逐个统计，
            # 且这是要天天对比的序列（谁开始封锁 GPTBot 是有新闻性的数字）。
            "robots_blocks_agents": bool(r["robots"].get("rules")),
            "robots_present": bool(r["robots"].get("present")),
            "robots_wildcard": bool(r["robots"].get("wildcard_disallow")),
            "robots_blocked": sorted(
                t for t, rules in r["robots"].get("rules", {}).items()
                if any(k == "disallow" and v == "/" for k, v in rules)),
            "blocked_agents": r["probe"].get("blocked", []),
            "inconclusive": bool(r["probe"].get("inconclusive")),
            "n_fixes": len(r["fixes"]),
        }

    except Exception as e:
        return {"site": url, "error": f"{type(e).__name__}: {e}"}


def render_leaderboard(rows):
    """把一批结果渲染成榜单 markdown。从 main() 拆出来，好让 --render 能只重渲染、
    不重扫（重扫 225 站要 4 分钟，且会惊动所有站）。"""
    # 首页非 200 的站无法评估：把"我们访问不了"和"站点真的什么都没有"分开，
    # 否则会把被 WAF 拦下的大站误记成 0 分（实测 79 个 Unknown 里绝大多数是 403）。
    ok = [r for r in rows if not r.get("error")]
    reachable = [r for r in ok if r["home_status"] == 200]
    unreachable = [r for r in ok if r["home_status"] != 200]

    yn = lambda b: "✓" if b else "—"
    L = ["# agentbi 榜单（样本）\n",
         f"扫描 {len(rows)} 站｜取到 {len(ok)}｜**可评估（首页 200）{len(reachable)}**｜"
         f"无法评估（首页非 200）{len(unreachable)}｜连接失败 {len(rows) - len(ok)}\n"]

    # 按平台分组对比——这是榜单的叙事核心
    by = {}
    for r in reachable:
        by.setdefault(r["platform"], []).append(r)
    L.append("## 按平台对比\n")
    L.append("| 平台 | 站点数 | UCP 部署率 | Product JSON-LD | llms.txt | 平均分 |")
    L.append("|---|---|---|---|---|---|")
    for p in sorted(by, key=lambda p: -len(by[p])):
        g = by[p]
        n = len(g)
        L.append(f"| {p} | {n} | {sum(1 for r in g if r['ucp'])}/{n} | "
                 f"{sum(1 for r in g if r['product_jsonld'])}/{n} | "
                 f"{sum(1 for r in g if r['llms'])}/{n} | "
                 f"{sum(r['score'] for r in g) // n} |")
    L.append("")

    reachable.sort(key=lambda r: -r["score"])
    L.append("## 明细（仅可评估站点，按分数）\n")
    L.append("| # | 站点 | 平台 | 分数 | UCP | Product JSON-LD | 价格 | 库存 | llms.txt |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(reachable, 1):
        L.append(f"| {i} | {r['site'].replace('https://', '')} | {r['platform']} | {r['score']} | "
                 f"{r['ucp'] or '—'} | {yn(r['product_jsonld'])} | {yn(r['price'])} | "
                 f"{yn(r['availability'])} | {yn(r['llms'])} |")

    if unreachable:
        L.append(f"\n## 无法评估（首页非 200，{len(unreachable)}）\n")
        L.append("这些站对探测器返回了非 200（多为 WAF / 反爬 / 地区限制），"
                 "**不代表它们 agent 友好度低**，故不计入榜单。\n")
        for r in sorted(unreachable, key=lambda r: r["home_status"]):
            L.append(f"- {r['site'].replace('https://', '')} — HTTP {r['home_status']}")

    dead = [r for r in rows if r.get("error")]
    if dead:
        L.append(f"\n## 连接失败（{len(dead)}）\n")
        for r in dead:
            L.append(f"- {r['site']}：{r['error']}")

    n = len(reachable)
    L.append(f"\n## 汇总（仅 {n} 个可评估站点）\n")
    L.append(f"- 已部署 UCP：**{sum(1 for r in reachable if r['ucp'])}/{n}**")
    L.append(f"- 有 Product JSON-LD：**{sum(1 for r in reachable if r['product_jsonld'])}/{n}**")
    L.append(f"- 有 llms.txt：**{sum(1 for r in reachable if r['llms'])}/{n}**")
    return "\n".join(L) + "\n"


def write_text(path, text):
    """原子替换：网页端随时可能在读这些文件，直接 open(w) 会让它读到半个文件。"""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}

    if "--render" in flags:
        with open("batch.json") as f:
            rows = json.load(f)["rows"]
        write_text("leaderboard.md", render_leaderboard(rows))
        print(f"写入 leaderboard.md（从 batch.json 的 {len(rows)} 行重渲染）", file=sys.stderr)
        return

    do_probe = "--probe" in flags
    if args:
        sites = [l.strip() for l in open(args[0]) if l.strip() and not l.startswith("#")]
    else:
        sites = DEFAULT_SITES
    # 不传站点文件就是试跑，写 *.test.*；要覆盖生产数据得显式 --live
    dry = "--live" not in flags
    batch_path = "batch.test.json" if dry else "batch.json"
    lb_path = "leaderboard.test.md" if dry else "leaderboard.md"
    if dry:
        print(f"试跑模式：写 {batch_path} / {lb_path}，不动生产数据（要覆盖请加 --live）",
              file=sys.stderr)

    print(f"扫描 {len(sites)} 个站点（多 UA 探测: {'开' if do_probe else '关'}）", file=sys.stderr)
    rows = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(lambda s: one(s, do_probe), sites):
            rows.append(r)
            tag = "ERR " if r.get("error") else f"{r['score']:3}"
            print(f"  {tag}  {r['site']}", file=sys.stderr)

    ok = [r for r in rows if not r.get("error")]
    vantage = detect_vantage()
    print(f"探测地: {vantage.get('country')} {vantage.get('city') or ''}", file=sys.stderr)
    # vantage 必须随数据一起发布：geo-redirect 的结果取决于探测位置
    out = {"generated_at": time.time(), "vantage": vantage,
           "ucp_route": A.UCP_PATH, "server_card_route": A.SERVER_CARD_PATH,
           "rows": rows}

    write_text(batch_path, json.dumps(out, ensure_ascii=False, indent=1))
    write_text(lb_path, render_leaderboard(rows))

    # 每天留一份快照：趋势与「UCP 版本滞后」追踪只靠这个，同一天重复跑不覆盖
    snap = "-"
    if not dry:
        os.makedirs("history", exist_ok=True)
        snap = f"history/batch-{time.strftime('%Y-%m-%d')}.json"
        if not os.path.exists(snap):
            write_text(snap, json.dumps(out, ensure_ascii=False, indent=1))

    print(f"\n写入 {batch_path} / {lb_path} / {snap}", file=sys.stderr)


if __name__ == "__main__":
    main()
