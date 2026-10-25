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
        # frame 的 row 2 = 200 + 解析为 JSON，不含"声明版本"这一层。
        # 我们的阳性多要求 ucp.version，两者今天可能相等、明天可能不等，
        # 合进 ucp 一个字段就再也分不开了（ucp#867 的 runs 表要的就是这两个数）。
        "ucp_parsed": bool(u["present"]),
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
        # ask capability（dev.ucp.common.ask）：10-07 进 main、没进 v2026-08-25，
        # 所以今天全 False。老快照没有这个字段 → 一律按"未测量"，不按 False。
        "ucp_ask": bool(u.get("ask")),
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
            # host selection（ucp#867 frame 的 run field）：探的是哪个 host、
            # 与种子的注册域关系、有没有 settle 到非店主机（CDN/asset 主机）。
            "probed_host": urlparse(r["origin"]).netloc,
            "settled_host": r.get("settled_host") or "",
            "host_unsettled": bool(r.get("host_unsettled")),
            "checked": r["checked_url"],
            "score": r["score"],
            # 首页对我们的 UA 返回 403/429/418 时 run() 只在 status==0（连不上）才放弃，
            # 被拦的情况下仍会拿那个错误页继续打分（warbyparker 403 也有 22 分）。
            # 页面一律按 home_status==200 过滤、不显示这些行，但 batch.json 是公开的，
            # 直接读它的人必须能一眼看出这个分不是从真实首页算出来的。
            "score_from_blocked_page": (isinstance(r["score"], int)
                                        and r["home_status"] != 200),
            # 通用可抓取分（可抓取性 + llms.txt + robots = 55）：不卖东西的站
            # 总分封顶 55，这个子分是它们唯一能跟商店站横向比的数字。
            "core_score": r.get("core_score"),
            **ucp_fields(r["ucp"]),
            **server_card_fields(origin_of(url), r["server_card"]),
            "product_jsonld": r["structured"]["has_product"],
            "price": "price" in r["structured"]["fields"],
            "availability": "availability" in r["structured"]["fields"],
            "llms": r["llms"]["present"],
            # ---- A 档（扫描字段升级清单，2026-10-25 落地）：零额外请求，全部来自已抓响应。
            # 序列从落地这天起才有，老快照缺这些字段一律按"未测量"处理（不是 0）。
            "llms_sha": r["llms"].get("sha"),
            "llms_lines": r["llms"].get("lines"),
            "llms_has_products": r["llms"].get("has_products"),
            "robots_sha": r["robots"].get("sha"),
            # 逐 agent 的 robots 结论（allow/disallow）。跟实测的 blocked_agents 并列，
            # 才分得出"robots 说允许、但被 WAF 挡"这一种。
            "robots_agent_rules": r["robots"].get("agent_rules") or {},
            "cdn": (r.get("infra") or {}).get("cdn"),
            "waf": (r.get("infra") or {}).get("waf"),
            "jsonld_types": r["structured"].get("types") or [],
            "nojs_readable": (r.get("nojs") or {}).get("readable"),
            "nojs_text_chars": (r.get("nojs") or {}).get("text_chars"),
            "nojs_price_hint": (r.get("nojs") or {}).get("price_hint"),
            "canonical": (r.get("seo") or {}).get("canonical"),
            "hreflang": (r.get("seo") or {}).get("hreflang") or [],
            "og_tags": (r.get("seo") or {}).get("og_tags") or [],
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


# 对照请求的间隔。403 站里混着限流（实测 bombas 三个 UA 全 429 是因为当天 batch 刚扫过），
# 打太快会把自己挡在外面，而且这里已经是在别人门口多敲一次门了。
CONTROL_DELAY = 2.0


def control_pass(rows):
    """对首页非 200 的站补发一次**浏览器 UA** 对照请求（同一套头部，只换 UA）。

    目的不是把这些站"救回"进榜单，而是把 403 拆成两桶——现在两者长得一模一样：
      - 对照也是非 200 → 该站对本扫描器所在的 vantage 关门（与 agent 无关，不给分）
      - 对照拿到 200   → 该站放真人浏览器、挡脚本/agent，这是真信号，不该算盲区
    实测（2026-10-18，KR 出口 12 个当日 403 站 ×3 UA）：10 站三 UA 全 403 且字节数一致，
    只有 rei / sephora 是 Chrome UA 200 而 GPTBot 也 403 —— 没有对照请求看不出这个区别。
    """
    n = 0
    for r in rows:
        if r.get("error") or r.get("home_status") == 200:
            continue
        try:
            c = A.fetch(r["site"], A.UA_BROWSER, timeout=15)
            r["home_ctrl_status"] = c["status"]
            r["home_ctrl_bytes"] = c["bytes"]
        except Exception:
            r["home_ctrl_status"] = None
            r["home_ctrl_bytes"] = None
        n += 1
        time.sleep(CONTROL_DELAY)
    return n


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
        # 2026-10-18 起每个非 200 站都补了一次浏览器 UA 对照，据此把"我们被挡"和
        # "站点挡脚本/agent"分开——两者在 home_status 上长得一模一样。
        blocks_script = [r for r in unreachable if r.get("home_ctrl_status") == 200]
        vantage_blocked = [r for r in unreachable
                           if "home_ctrl_status" in r and r["home_ctrl_status"] != 200]
        unmeasured = [r for r in unreachable if "home_ctrl_status" not in r]

        L.append(f"\n## 无法评估（首页非 200，{len(unreachable)}）\n")
        L.append("这些站对探测器返回了非 200，**不代表它们 agent 友好度低**，故不计入榜单。"
                 "每个站都补发过一次浏览器 UA 对照请求（同一套头部，只换 UA），据此分两桶：\n")

        if blocks_script:
            L.append(f"### 放真人浏览器、挡脚本/agent（{len(blocks_script)}）\n")
            L.append("对照 UA 拿到 200，本扫描器被挡 —— 这类站是**真的对非浏览器客户端关门**。\n")
            for r in sorted(blocks_script, key=lambda r: r["home_status"]):
                L.append(f"- {r['site'].replace('https://', '')} — 本扫描器 HTTP "
                         f"{r['home_status']} / 浏览器 UA 200")
            L.append("")
        if vantage_blocked:
            L.append(f"### 本扫描器 vantage 不可达（{len(vantage_blocked)}）\n")
            L.append("浏览器 UA 对照同样非 200 —— 站点对本扫描器所在网络/指纹关门，"
                     "**与 agent 无关**，这些站的 agent 友好度未知。\n")
            for r in sorted(vantage_blocked, key=lambda r: r["home_status"]):
                L.append(f"- {r['site'].replace('https://', '')} — HTTP "
                         f"{r['home_status']} / 对照 {r['home_ctrl_status']}")
            L.append("")
        if unmeasured:
            L.append(f"### 未做对照（{len(unmeasured)}，老快照）\n")
            for r in sorted(unmeasured, key=lambda r: r["home_status"]):
                L.append(f"- {r['site'].replace('https://', '')} — HTTP {r['home_status']}")
            L.append("")

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


def _positives(rows):
    """本站对外口径的 UCP 阳性：200 + 解析成功 + 声明了 ucp.version。

    与 ucp#867 表格里我们那行（row 2 + ucp.version）是同一个判据，别换成别的。
    """
    out = {}
    for r in rows:
        if r.get("ucp_status") == 200 and r.get("ucp"):
            out[urlparse(r["site"]).netloc or r["site"]] = r["ucp"]
    return out


def _prev_snapshot(today, prefix="batch-"):
    """history/ 里今天之前最近的一份快照文件名；没有（第一天）返回 None。

    prefix 用于分池：扩展池的快照叫 batch-cn-<date>.json，不能拿主池的快照当它的"上一次"
    （成员都不一样，比出来的 entered/left 全是假的）。
    """
    if not os.path.isdir("history"):
        return None
    n = len(prefix)
    cands = [f for f in os.listdir("history")
             if f.startswith(prefix) and f.endswith(".json") and f[n:n + 10] < today]
    return sorted(cands)[-1] if cands else None


def delta_block(rows, today, prefix="batch-"):
    """相对上一次 pass 的变化：进了哪些、掉了哪些、声明版本怎么分布。

    ucp#867 的 frame 把这两项设为可选字段（2026-10-23 frmoretto 加的），
    目的就是让"数量变了"不被读成采用率在动。只跟生产快照比，试跑不产 delta。
    """
    prev_file = _prev_snapshot(today, prefix)
    if not prev_file:
        return None
    try:
        with open(os.path.join("history", prev_file)) as f:
            prev_rows = json.load(f)["rows"]
    except (OSError, ValueError, KeyError):
        return None
    now, prev = _positives(rows), _positives(prev_rows)
    versions = {}
    for v in now.values():
        versions[v] = versions.get(v, 0) + 1
    return {"prev_date": prev_file[6:16],
            "n_positive": len(now), "prev_n_positive": len(prev),
            "entered": sorted(set(now) - set(prev)),
            "left": sorted(set(prev) - set(now)),
            "ucp_versions": dict(sorted(versions.items(), key=lambda kv: -kv[1]))}


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

    # 分池（2026-10-25）：主池 225 的数字已对外引用过，扩展池单独成文件、单独成序列，
    # 绝不并进 batch.json —— 并池会改掉分母，之前对外报的数就对不上了。
    pool = next((a.split("=", 1)[1].strip() for a in sys.argv[1:]
                 if a.startswith("--pool=") and a.split("=", 1)[1].strip()), None)
    sfx = "-%s" % pool if pool else ""
    do_probe = "--probe" in flags
    if args:
        sites = [l.strip() for l in open(args[0]) if l.strip() and not l.startswith("#")]
    else:
        sites = DEFAULT_SITES
    # 不传站点文件就是试跑，写 *.test.*；要覆盖生产数据得显式 --live
    dry = "--live" not in flags
    batch_path = "batch%s.test.json" % sfx if dry else "batch%s.json" % sfx
    lb_path = "leaderboard%s.test.md" % sfx if dry else "leaderboard%s.md" % sfx
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

    n_ctrl = control_pass(rows)
    ctrl_ok = sum(1 for r in rows
                  if not r.get("error") and r.get("home_status") != 200
                  and r.get("home_ctrl_status") == 200)
    print(f"对照请求 {n_ctrl} 次（非 200 站点补一次浏览器 UA）："
          f"{ctrl_ok} 家放真人、挡脚本/agent，其余为本扫描器 vantage 不可达", file=sys.stderr)

    ok = [r for r in rows if not r.get("error")]
    vantage = detect_vantage()
    print(f"探测地: {vantage.get('country')} {vantage.get('city') or ''}", file=sys.stderr)
    # vantage 必须随数据一起发布：geo-redirect 的结果取决于探测位置
    out = {"generated_at": time.time(), "vantage": vantage,
           "ucp_route": A.UCP_PATH, "server_card_route": A.SERVER_CARD_PATH,
           "rows": rows}

    if not dry:
        # 只跟生产快照比：试跑数据不能混进对外序列
        delta = delta_block(rows, time.strftime("%Y-%m-%d"), "batch%s-" % sfx)
        if delta:
            out["delta"] = delta
            print("delta 对比 %s：进 %d / 掉 %d" % (delta["prev_date"], len(delta["entered"]), len(delta["left"])), file=sys.stderr)

    write_text(batch_path, json.dumps(out, ensure_ascii=False, indent=1))
    write_text(lb_path, render_leaderboard(rows))

    # 每天留一份快照：趋势与「UCP 版本滞后」追踪只靠这个，同一天重复跑不覆盖
    snap = "-"
    if not dry:
        os.makedirs("history", exist_ok=True)
        snap = f"history/batch{sfx}-{time.strftime('%Y-%m-%d')}.json"
        if not os.path.exists(snap):
            write_text(snap, json.dumps(out, ensure_ascii=False, indent=1))

    print(f"\n写入 {batch_path} / {lb_path} / {snap}", file=sys.stderr)


if __name__ == "__main__":
    main()
