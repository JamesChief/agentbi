#!/usr/bin/env python3
"""批量扫描，产出榜单数据。默认不做多 UA 探测（请求数 ×7，不礼貌且慢）。

用法:
    python3 scan_batch.py                      # 用内置默认站点列表
    python3 scan_batch.py sites.txt            # 每行一个 URL
    python3 scan_batch.py sites.txt --probe    # 附带多 UA 探测
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import agentbi as A

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


def one(url, do_probe):
    try:
        r = A.run(url, timeout=15, do_probe=do_probe, discover=True)
        if r.get("error"):
            return {"site": url, "error": r["error"]}
        return {
            "site": url,
            "platform": r["platform"],
            "home_status": r["home_status"],
            "checked": r["checked_url"],
            "score": r["score"],
            "ucp": r["ucp"]["version"] if r["ucp"]["present"] else None,
            "ucp_versions": len(r["ucp"]["supported_versions"]),
            "ucp_services": list(r["ucp"]["services"]),
            "product_jsonld": r["structured"]["has_product"],
            "price": "price" in r["structured"]["fields"],
            "availability": "availability" in r["structured"]["fields"],
            "llms": r["llms"]["present"],
            "robots_blocks_agents": bool(r["robots"].get("rules")),
            "blocked_agents": r["probe"].get("blocked", []),
            "inconclusive": bool(r["probe"].get("inconclusive")),
            "n_fixes": len(r["fixes"]),
        }
    except Exception as e:
        return {"site": url, "error": f"{type(e).__name__}: {e}"}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    do_probe = "--probe" in sys.argv
    if args:
        sites = [l.strip() for l in open(args[0]) if l.strip() and not l.startswith("#")]
    else:
        sites = DEFAULT_SITES

    print(f"扫描 {len(sites)} 个站点（多 UA 探测: {'开' if do_probe else '关'}）", file=sys.stderr)
    rows = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(lambda s: one(s, do_probe), sites):
            rows.append(r)
            tag = "ERR " if r.get("error") else f"{r['score']:3}"
            print(f"  {tag}  {r['site']}", file=sys.stderr)

    ok = [r for r in rows if not r.get("error")]
    json.dump({"generated_at": time.time(), "rows": rows},
              open("batch.json", "w"), ensure_ascii=False, indent=1)

    # 首页非 200 的站无法评估：把"我们访问不了"和"站点真的什么都没有"分开，
    # 否则会把被 WAF 拦下的大站误记成 0 分（实测 79 个 Unknown 里绝大多数是 403）。
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
    open("leaderboard.md", "w").write("\n".join(L) + "\n")
    print("\n写入 batch.json / leaderboard.md", file=sys.stderr)


if __name__ == "__main__":
    main()
