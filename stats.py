#!/usr/bin/env python3
"""从 Caddy 的 JSON 访问日志统计使用量，用于阶段 1 出口判据。

阶段 1 的三个判据里，「≥100 人跑过」只能靠日志数；「≥3 个站主有反应」要靠被检测
域名里有多少是真实的、可点名的站点。这个脚本给出这两组数。

    python3 stats.py /var/log/caddy/agentbi.log          # 在服务器上直接跑
    ssh <你的主机> "sudo cat /var/log/caddy/agentbi.log" | python3 stats.py -
    python3 stats.py /var/log/caddy/agentbi.log --top 30

主机地址与登录用户写在 部署清单.md（未提交进公开仓库），别把真实 IP 抄进这里。

只统计 /api/check（真正发起检测的端点）；静态页面与榜单不计数。
"""
import argparse
import json
import sys
import time
from collections import Counter
from urllib.parse import parse_qs, urlparse

CHECK = "/api/check"


def iter_lines(path):
    if path == "-":
        yield from sys.stdin
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        yield from f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="Caddy JSON 访问日志路径，或 - 表示 stdin")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--json", action="store_true", help="输出 JSON，便于存档对比")
    a = ap.parse_args()

    total = checks = cached_ok = limited = 0
    ips = Counter()
    targets = Counter()
    statuses = Counter()
    first = last = None

    for line in iter_lines(a.log):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue                      # 滚动/截断的半行
        if e.get("logger") != "http.log.access.log0":
            continue
        req = e.get("request") or {}
        uri = req.get("uri") or ""
        total += 1
        ts = e.get("ts")
        if ts:
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
        if not uri.startswith(CHECK):
            continue
        checks += 1
        statuses[e.get("status")] += 1
        ip = req.get("client_ip") or req.get("remote_ip")
        if ip:
            ips[ip] += 1
        q = parse_qs(urlparse(uri).query)
        url = (q.get("url") or [""])[0].strip()
        if url:
            host = (urlparse(url).hostname or "").lower()
            if host:
                targets[host] += 1

    cached_ok = statuses.get(200, 0)
    limited = statuses.get(429, 0)

    def fmt(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"

    if a.json:
        print(json.dumps({
            "window": {"first": fmt(first), "last": fmt(last)},
            "all_requests": total,
            "checks": checks,
            "unique_visitor_ips": len(ips),
            "unique_target_domains": len(targets),
            "status_200": cached_ok,
            "status_429": limited,
            "top_targets": targets.most_common(a.top),
        }, ensure_ascii=False, indent=2))
        return

    print(f"时间范围           {fmt(first)}  →  {fmt(last)}")
    print(f"全部请求           {total}")
    print(f"检测请求           {checks}")
    print(f"独立来访 IP        {len(ips)}        ← 阶段1 判据「≥100 人跑过」的近似值")
    print(f"独立被检测域名     {len(targets)}")
    print(f"成功 / 被限流      {cached_ok} / {limited}")
    print()
    print(f"被检测最多的 {min(a.top, len(targets))} 个域名：")
    for h, n in targets.most_common(a.top):
        print(f"  {n:>4}  {h}")
    print()
    print("注意：独立 IP 会被公司出口 NAT、VPN、移动网络低估，也会因同一个人多次访问被高估。")
    print("它是量级参考，不是精确人数。")


if __name__ == "__main__":
    main()
