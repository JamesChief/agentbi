#!/usr/bin/env python3
"""发帖当天用：把 batch.json 变成稿子里要用的数字与表格。

数字每天都在变（可评估率会波动十几个），所以发帖前跑一次，用当天的快照，
并在稿子里标注快照日期 —— 否则帖子里的数和站点上的数对不上，第一个评论就会指出。

    python3 post_numbers.py                      # 读 ./batch.json
    python3 post_numbers.py /opt/agentbi/batch.json

输出的表格可以直接贴进 posts_en.md。
"""
import argparse
import collections
import json
import sys
import time

PLAT_ORDER = ["Shopify", "WooCommerce", "SalesforceCC", "Unknown", "Other"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("batch", nargs="?", default="batch.json")
    a = ap.parse_args()

    try:
        d = json.load(open(a.batch))
    except Exception as e:
        sys.exit(f"读不了 {a.batch}: {e}")

    rows = d["rows"]
    ok = [r for r in rows if not r.get("error")]
    reach = [r for r in ok if r.get("home_status") == 200]
    non200 = [r for r in ok if r.get("home_status") != 200]
    dead = [r for r in rows if r.get("error")]
    date = time.strftime("%Y-%m-%d", time.localtime(d.get("generated_at", 0)))

    print(f"# 快照 {date}（扫描 {len(rows)}｜可评估 {len(reach)}｜非 200 {len(non200)}｜"
          f"连接失败 {len(dead)}）\n")

    # UCP 普查口径与首页可达性解耦：首页被 WAF 拦住，well-known 路径照样可能返回内容。
    # 用"首页 200"做闸门会把头部零售商的阳性静默丢掉（见 ucp#904）。
    def bucket(r):
        s = r.get("ucp_status")
        if r.get("ucp"):
            return "200 + parses (positive)"
        if s == 200:
            return "200 but does not parse"
        if s == 404:
            return "404"
        if s == 410:
            return "410"
        if s == 403:
            return "403"
        if s in (429, 418, 503):
            return "429/418/503"
        if not s:
            return "could not connect"
        return f"other {s}"

    bc = collections.Counter(bucket(r) for r in rows)
    print("UCP 端点普查（全部站点，不看首页状态）:")
    for k, v in bc.most_common():
        print(f"  {k:<28} {v}")
    print()

    print("| platform | n | UCP deployed | product data | llms.txt | avg score |")
    print("|---|---|---|---|---|---|")

    by = collections.defaultdict(list)
    for r in reach:
        by[r["platform"]].append(r)
    keys = [p for p in PLAT_ORDER if p in by] + [p for p in sorted(by) if p not in PLAT_ORDER]
    for p in keys:
        g = by[p]
        n = len(g)
        print(f"| {p} | {n} | {sum(1 for r in g if r['ucp'])} ({100*sum(1 for r in g if r['ucp'])//n}%) "
              f"| {sum(1 for r in g if r['product_jsonld'])} "
              f"| {sum(1 for r in g if r['llms'])} "
              f"| {sum(r['score'] for r in g)//n} |")

    vc = collections.Counter(r["ucp"] for r in rows if r.get("ucp"))
    print("\nUCP 版本分布（普查口径）:", dict(vc) or "无")

    latest = max(vc) if vc else None
    lag = [(r["site"].replace("https://", ""), r["ucp"])
           for r in rows if r.get("ucp") and latest and r["ucp"] != latest]
    print("版本滞后（不是最新版）:", lag or "无")

    shop_all = [r for r in rows if r.get("platform") == "Shopify"]
    no_ucp = [r["site"].replace("https://", "") for r in shop_all if not r["ucp"]]
    print(f"\nShopify 未部署 UCP（{len(no_ucp)}/{len(shop_all)}）:", ", ".join(no_ucp) or "无")

    non_shopify_ucp = [(r["site"].replace("https://", ""), r.get("home_status"))
                       for r in rows if r.get("ucp") and r.get("platform") != "Shopify"]
    print("非 Shopify 却部署了 UCP（含首页被拦的）:", non_shopify_ucp or "无")

    print(f"\n局限提示（稿子必须写）：WooCommerce n={len(by.get('WooCommerce', []))}；"
          f"可评估率 {100*len(reach)//len(rows)}%，其余多为 WAF 拦截，不代表对方配置。")


if __name__ == "__main__":
    main()
