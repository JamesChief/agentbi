#!/usr/bin/env python3
"""文案表：默认英文，?lang=zh 切中文。

站点面向的是海外站主（Shopify / WooCommerce / 自建站），报告与页面默认英文；
中文版保留给国内独立站卖家这个受众。

两份文案必须同结构：加 key 时两个语言都要加，否则会静默回落到英文。
"""
import re

LANGS = ("en", "zh")
DEFAULT = "en"

STR = {
    # ---------------------------------------------------------------- 首页
    "en": {
        "site.title": "AgentBI — Is your site ready for AI agents?",
        "site.sub": "Enter a URL. See whether an AI agent can find, understand and buy from your site.",
        "site.placeholder": "https://your-store.com",
        "site.button": "Scan",
        "site.scanning": "Scanning, 10–20 seconds…",
        "site.lb_link": "Leaderboard: 225 stores tested →",
        "site.tr_link": "Trend",
        "site.cr_link": "Crawlers",
        "site.cat_link": "Categories",
        "site.pr_link": "Signals",
        "site.checks": "Checks: can agents fetch you · product structured data · UCP deployment "
                       "and version · llms.txt · robots. Open source and reproducible:",
        "site.about_link": "How we crawl / how to opt out",
        "site.issues_link": "Wrong result? Open an issue",
        "site.cached": "(from cache)",
        "site.req_failed": "Request failed: {err}",
        "site.err": "✗ {msg}",

        # 订阅。文案刻意不承诺发送节奏——发送通道还没接，承诺了就是骗人。
        "sub.title": "Weekly digest",
        "sub.desc_long": "I re-scan the same 225 stores every day. Leave your email and you'll get "
                         "the weekly digest when it starts: UCP version moves, new deployments, "
                         "and what changed week over week.",
        "sub.placeholder": "you@your-store.com",
        "sub.button": "Notify me",
        "sub.consent": "Used only to send the digest. No tracking, no sharing, unsubscribe any time.",
        "sub.ok": "Got it — you're on the list.",
        "sub.err_invalid": "That doesn't look like an email address.",
        "sub.err_rate": "Too many attempts. Try again in a while.",
        "sub.err_fail": "Something broke on my side. Try again, or open an issue.",

        # ---- 榜单条目自助纠错（冷邮那条线留下的唯一正经产出）----------------
        # 实测：中型 DTC 的公开邮箱只能到客服，到不了管网站的人（20 封到达率 0/20）。
        # 所以别再找人，让站主自己在条目上找到入口。
        "corr.title": "Is your entry wrong?",
        "corr.desc": "This benchmark is measured from outside, so it gets things wrong. "
                     "If one of these stores is yours, tell me — correct it, take it down, or claim it.",
        "corr.site": "Store",
        "corr.kind": "What do you need",
        "corr.k_wrong": "The data is wrong",
        "corr.k_remove": "Take my store off the leaderboard",
        "corr.k_claim": "I own this store — talk to me",
        "corr.note": "Details (optional)",
        "corr.email": "Your email (optional, only so I can reply)",
        "corr.button": "Send",
        "corr.ok": "Got it — I'll look at it.",
        "corr.err_site": "Pick a store from the list.",
        "corr.err_rate": "Too many attempts. Try again in a while.",
        "corr.err_fail": "Something broke on my side. Try again, or open an issue.",
        "corr.consent": "No tracking. An email is used only to reply to this.",
        "corr.link": "Wrong entry? Tell me",

        "dim.fetch": "Fetchable by agents",
        "dim.structured": "Product structured data",
        "dim.ucp": "UCP manifest",
        "dim.llms": "llms.txt",
        "dim.robots": "robots.txt",

        "rep.checked": "Checked",
        "rep.probe": "Multi-UA probe",
        "rep.ua": "UA",
        "rep.status": "status",
        "rep.product": "product data",
        "rep.result": "result",
        "rep.readable": "readable",
        "rep.blocked": "✗ blocked",
        "rep.ok": "✓",
        "rep.ucp_title": "UCP manifest",
        "rep.ucp_current": "Current version {v}, compatible with {versions}",
        "rep.service": "service",
        "rep.version": "version",
        "rep.transport": "transport",
        "rep.fixes": "What to fix",
        "rep.warn": "⚠ {note}",

        "err.bad_url": "Invalid URL (http/https only)",
        "err.rate": "Too many requests, try again shortly",
        "err.cooldown": "That site was just scanned, try again in {n} minutes",
        "err.busy": "Busy right now, retry in 30 seconds",

        "lb.title": "AgentBI leaderboard",
        "lb.back": "← Scan your site",
        "lb.by_platform": "By platform",
        "lb.th_platform": "Platform",
        "lb.th_n": "Stores",
        "lb.th_ucp": "UCP",
        "lb.th_product": "Product JSON-LD",
        "lb.th_llms": "llms.txt",
        "lb.th_avg": "Avg score",
        "lb.method": "Method and limitations (read before quoting)",
        "lb.m1": "Snapshot <b>{date}</b>: {scanned} stores scanned, "
                 "<b>{reach}</b> returned 200 and are evaluable, {unreach} returned non-200 "
                 "({n403} of them 403).",
        "lb.m2": "<b>A 403 is our IP reputation, not their configuration</b> — most are "
                 "enterprise WAFs blocking datacenter egress (Walmart, Macy's, Nordstrom, "
                 "Costco are all in there). Full browser headers were tried and did not "
                 "reproduce. This table covers stores <b>without</b> an enterprise WAF, "
                 "not the industry.",
        "lb.m3": "<b>WooCommerce n={n}</b>, every site harvestable from WooCommerce's own "
                 "showcase. A direction, not a precise ratio.",
        "lb.m4": "On Shopify, <code>llms.txt</code> and UCP are mostly "
                 "<b>generated by the platform</b> (several stores ship byte-identical "
                 "templates) — it's a platform dividing line, not a signal of effort.",
        "lb.m5": "Scoring is <b>heuristic</b>: no JS rendering, and it does not place a real "
                 "order through UCP — it only checks that the manifest exists and its version.",
        "lb.m6": "Compared with the previous snapshot ({pdate}): evaluable {reach_delta}, "
                 "UCP deployed {ucp_delta}. <b>The evaluable count fluctuates day to day</b> "
                 "— the same list can differ by a dozen depending on each site's WAF and our "
                 "egress reputation, so quote these numbers with their snapshot date.",
        "lb.detail": "Detail (evaluable {reach} / scanned {scanned})",
        "lb.th_site": "Site",
        "lb.note_unreach": "{n} sites returned non-200 to the scanner (mostly WAF blocks). "
                          "That is not a judgement on their agent-readiness; they are not "
                          "counted here.",
        "lb.no_data": "No leaderboard data yet",
        "lb.dash": "—",

        # ---- /trend 历史趋势（板块 2）------------------------------------
        # 文案原则：每一句都能被直接引用，所以必须自带日期 / 样本量 / 口径。
        "tr.title": "Agent-readiness trend",
        "tr.desc": "Daily agent-readiness snapshots of the same stores: average score, UCP "
                   "deployment, and day-over-day movers. One scan per day, no JS rendering.",
        "tr.back": "← Scan your site",
        "tr.intro": "The same {n} stores, re-scanned once a day. This is the part of AgentBI "
                    "that only gets more valuable with time — a day of history cannot be "
                    "backfilled.",
        "tr.h_series": "Daily snapshots",
        "tr.h_movers": "Biggest movers ({pdate} → {date})",
        "tr.th_date": "Date",
        "tr.th_avg": "Avg score",
        "tr.th_reach": "Evaluable",
        "tr.th_ucp": "UCP deployed",
        "tr.th_delta": "Change",
        "tr.none": "None in this window.",
        "tr.up": "Improved",
        "tr.down": "Declined",
        "tr.no_prev": "Only one snapshot so far. Movers need at least two days of history — "
                      "this page fills in on its own from here.",
        "tr.no_data": "No history yet.",
        "tr.method": "Method and limitations (read before quoting)",
        "tr.m1": "Each row is one daily snapshot of the same {n} stores, scanned once per day "
                 "at about 03:30 CST, no JS rendering.",
        "tr.m2": "<b>Avg score</b> covers evaluable stores only (homepage returned 200). The "
                 "evaluable count moves day to day with WAF blocks, so quote an avg score "
                 "together with its date and sample size.",
        "tr.m3": "A 403 is <b>our</b> egress reputation, not the store's configuration. A "
                 "store blocked today may score again tomorrow — read the series as a trend, "
                 "not a verdict on any single store.",
        "tr.m4": "Scoring is <b>heuristic</b>: it checks that a UCP manifest exists and its "
                 "version, it does not place a real order.",
        "tr.api_note": "Per-store history is available as JSON: "
                       "<code>/api/site-history?site=https://example.com</code>",
        # ---- /crawlers 爬虫准入普查（板块 4）------------------------------
        "cr.title": "AI crawler access census",
        "cr.desc": "How many retailers block each AI crawler in robots.txt. Same {n} stores, "
                   "re-scanned daily.",
        "cr.intro": "robots.txt is where a store decides whether AI crawlers may read it. This "
                    "counts <code>Disallow: /</code> rules per crawler across {n} stores "
                    "({m} of them publish a robots.txt).",
        "cr.th_agent": "Crawler",
        "cr.th_blocked": "Blocked by",
        "cr.th_pct": "Share",
        "cr.wildcard": "Stores that disallow <code>/</code> for <code>*</code> "
                       "(this blocks every crawler, AI or not): <b>{n}</b>",
        "cr.detail": "Which store blocks which crawler",
        "cr.th_blocked_list": "Blocked crawlers",
        "cr.none": "No store in this sample publishes a block for any tracked crawler.",
        "cr.method": "Method and limitations (read before quoting)",
        "cr.m1": "Counts <code>Disallow: /</code> rules matched to {k} known AI crawler tokens "
                 "in each store's robots.txt. Snapshot <b>{date}</b>.",
        "cr.m2": "A block in robots.txt is a <b>stated rule, not observed behaviour</b> — some "
                 "stores that allow crawlers still block them at the WAF, and a 403 in our "
                 "scanner is our egress reputation, not their rule.",
        "cr.m3": "Stores without a robots.txt are excluded from the denominator: no file means "
                 "allow by default, not a block.",
        "cr.m4": "Re-scanned daily, so these counts move as stores edit their files. Quote with "
                 "the snapshot date.",
        # ---- /protocols 信号采用度（板块 3）------------------------------
        # 与 leaderboard 的分工：榜单是 UCP 端点分桶普查 + 打分明细；
        # 这一页回答"这些信号各自有多少站有，以及全部具备的有多稀少"。
        "pr.title": "Agent-readiness signals",
        "pr.desc": "What share of stores actually publish each machine-readable signal — UCP, "
                   "llms.txt, product structured data — and how few publish all of them.",
        "pr.intro": "Across {n} evaluable stores in the {date} snapshot. Publishing one signal "
                    "does not make a store usable to an agent, so the last line is the one "
                    "that matters.",
        "pr.th_signal": "Signal",
        "pr.th_n": "Stores",
        "pr.th_pct": "Share",
        "pr.s_ucp": "UCP manifest deployed",
        "pr.s_llms": "llms.txt present",
        "pr.s_jsonld": "Product JSON-LD",
        "pr.s_price": "…with price",
        "pr.s_availability": "…with availability",
        "pr.s_robots_ok": "robots.txt blocks no AI crawler",
        "pr.all_title": "Stores with every signal",
        "pr.all_note": "Only <b>{n}</b> of {reach} stores ({pct}) publish all {k} signals. "
                       "Everything else is partial.",
        "pr.h_series": "How these shares moved",
        "pr.method": "Method and limitations (read before quoting)",
        "pr.m1": "Signals are read from each store's homepage and <code>/.well-known/</code> "
                 "paths. Snapshot <b>{date}</b>, no JS rendering.",
        "pr.m2": "Denominator is <b>evaluable stores only</b> (homepage returned 200): {reach} "
                 "of {n} scanned. The remainder are WAF blocks, not failures.",
        "pr.m3": "UCP versions and services are near-identical across stores because platforms "
                 "generate them, so counting who has it is meaningful and comparing versions "
                 "is not.",
        "pr.m4": "robots.txt is a stated rule, not observed behaviour, and not every snapshot "
                 "carries it — older days may show a gap.",
        # ---- /categories 分品类基准（板块 1）------------------------------
        "cat.title": "Agent readiness by category",
        "cat.desc": "Average agent-readiness score, UCP and llms.txt adoption, split by retail "
                    "category. Same {n} stores, re-scanned daily.",
        "cat.intro": "Every store in the list is assigned one category by hand. Categories with "
                     "fewer than 10 evaluable stores are shown but should not be quoted as a "
                     "category benchmark.",
        "cat.th_cat": "Category",
        "cat.th_reach": "Evaluable",
        "cat.th_avg": "Avg score",
        "cat.th_ucp": "UCP",
        "cat.th_llms": "llms.txt",
        "cat.th_all": "All signals",
        "cat.c_apparel": "Apparel",
        "cat.c_shoes": "Shoes",
        "cat.c_beauty": "Beauty & personal care",
        "cat.c_home": "Home & furniture",
        "cat.c_electronics": "Electronics",
        "cat.c_outdoor": "Outdoor & sport",
        "cat.c_food": "Food & drink",
        "cat.c_accessories": "Accessories",
        "cat.c_underwear": "Underwear & socks",
        "cat.c_retail": "Large retailers & marketplaces",
        "cat.c_other": "Other",
        "cat.small": "small sample",
        "cat.method": "Method and limitations (read before quoting)",
        "cat.m1": "Categories are assigned <b>by hand</b> from each store's domain and brand "
                  "(<code>categories.py</code>), snapshot <b>{date}</b>. They are a judgement "
                  "call, not a taxonomy from the stores themselves.",
        "cat.m2": "Denominator is evaluable stores (homepage returned 200), which differs per "
                  "category. Rows marked <i>small sample</i> have fewer than 10 and should not "
                  "be quoted as a benchmark.",
        "cat.m3": "Large retailers and marketplaces are kept in their own row on purpose: they "
                  "sell every category, so mixing them into category rows would distort both.",

        # UCP 端点普查：与首页可达性解耦，按 #867 的 reporting frame 分桶
        "lb.h_census": "UCP endpoint census",
        "lb.census_note": "Counts responses to <code>/.well-known/ucp</code> only, "
                          "<b>independent of whether the homepage was reachable</b> — a storefront "
                          "behind a WAF can still serve the well-known path. \"Could not ask\" and "
                          "\"no\" are reported separately, per the reporting frame proposed in "
                          "<a href=\"https://github.com/Universal-Commerce-Protocol/ucp/discussions/867\">"
                          "ucp#867</a>. Nothing here is an adoption rate.",
        "lb.th_bucket": "Response",
        "lb.b_pos": "200 + parses → positive",
        "lb.b_noparse": "200 but does not parse (could not ask)",
        "lb.b_3xx": "3xx at profile path (not followed)",
        "lb.b_robots": "refused by robots.txt (not requested)",
        "lb.b_404": "404",
        "lb.b_410": "410 Gone",
        "lb.b_403": "403 (refused to us)",
        "lb.b_rate": "429 / 418 / 503",
        "lb.b_err": "could not connect",
        "lb.b_other": "other",
        "lb.h_pos": "Positives",
        "lb.pos_ver": "Versions declared: {versions}.",
        "lb.pos_plat": "Platform recorded per positive: {platforms}.",
        "lb.decision_note": "<b>{n} positives, but {shopify} of them are Shopify</b> — that may be "
                            "one platform decision rather than {shopify} merchant choices. Both "
                            "counts are published because they answer different questions.",
        "lb.pos_hidden": "<b>{n} positives have a homepage that does not return 200</b> "
                         "({hosts}). Their WAFs block the storefront but not the well-known path, "
                         "so any census that gates on homepage reachability drops them silently — "
                         "and they are the largest retailers in the sample.",
        "lb.h_read": "Storefront readability",
        "lb.read_note": "Only the {n} stores whose homepage answered 200 can be scored for content. "
                        "UCP is deliberately <b>not</b> in this table: gating it on homepage "
                        "reachability was hiding {hidden} positives whose WAF blocks the storefront "
                        "but not the well-known path.",
        "lb.f_frame": "<b>Reporting frame.</b> Sampling frame: a hand-built convenience sample of "
                      "{scanned} consumer/DTC storefronts plus the WooCommerce official showcase — "
                      "<b>not a random draw</b>, and skewed towards Shopify, so the aggregate rate "
                      "reflects the platform mix of the sample. Paths checked: "
                      "<code>/.well-known/ucp</code> only, one route, one attempt, no retries, "
                      "redirects followed. Positive criterion: status 200 + parses as JSON + "
                      "<code>ucp.version</code> present.",

        "about.title": "About AgentBI",
        "about.h_what": "What this is",
        "about.p_what": "AgentBI measures how friendly a site is to AI agents: can an agent "
                        "fetch your pages, is your product data machine-readable (JSON-LD "
                        "price / availability), have you deployed a UCP manifest, do you "
                        "publish <code>llms.txt</code>.",
        "about.h_how": "How we crawl",
        "about.li1": "<b>Only when someone submits a URL.</b> No continuous crawling.",
        "about.li2": "User agent is honest and identifiable: "
                     "<code>agentbi/0.1 (+https://agentbi.tech/about; agent-readiness scanner)</code>"
                     " — not disguised as a browser.",
        "about.li3": "One check is about 10 requests to your site and takes 15–20 seconds.",
        "about.li4": "<b>One real scan per domain per 10 minutes</b>; results cached 30 minutes.",
        "about.li5": "Results are published on the <a href=\"/leaderboard\">leaderboard</a>.",
        "about.h_exception": "One exception, explained",
        "about.p_exception": "One step, the multi-UA probe, requests your site with several real "
                        "AI agent identifiers (GPTBot, ClaudeBot, …) and <b>one real browser "
                        "identifier</b>, then compares the responses — to answer \"do you treat "
                        "agents differently from normal visitors\". <b>This only measures "
                        "anything if the identifiers are real</b>, so it is a measurement, not "
                        "anonymous crawling. Every other fetch uses the honest agent above.",
        "about.h_optout": "Don't want to be scanned",
        "about.p_optout": "robots.txt is not honoured automatically yet — known TODO. Two ways out:",
        "about.li_issue": "<b>(preferred) Open an issue</b> with the "
                          "<a href=\"https://github.com/JamesChief/agentbi/issues/new?template=opt-out.yml\">"
                          "\"stop scanning\" template</a> and we add the domain to the blocklist, "
                          "which is checked before fetching.",
        "about.li_email": "Email: <a href=\"mailto:contact@agentbi.tech\">"
                          "<code>contact@agentbi.tech</code></a> — reply \"stop\" and the domain "
                          "is added to the blocklist",
        "about.h_data": "Data",
        "about.p_data": "Results are published on the leaderboard. Only sites returning 200 are "
                        "counted; sites returning non-200 (mostly enterprise WAFs) are absent "
                        "and are not read as \"low agent-readiness\".",
        "about.back": "← Back to scanning",

        "og.site_name": "AgentBI",
        "og.home_title": "AgentBI — Is your site ready for AI agents?",
        "og.home_desc": "86% of Shopify stores already support agentic commerce. WooCommerce: 0%. "
                        "What about yours? Enter a URL, get a report in 15 seconds.",
        "og.lb_title": "AgentBI leaderboard — 225 stores tested for AI-agent readiness",
        "og.lb_desc": "Shopify 86% have UCP deployed, WooCommerce 0%. Your platform decides "
                      "whether shopping agents can find you more than your own effort does.",

        # ---------------------------------------------------------- 报告文案
        "rep.err_unreachable": "Unreachable: {err}",
        "rep.fetch_skipped": "not tested (--no-probe)",
        "rep.fetch_inconclusive": "inconclusive (scanner network restricted, not scored)",
        "rep.fetch_detail": "{ok}/{total} agents can fetch the page, "
                            "{readable} can read product/price data",
        "rep.struct_full": "Product JSON-LD complete",
        "rep.struct_partial": "partial product data",
        "rep.struct_none": "no structured product data found",
        "rep.ucp_deployed": "deployed {v}; services: {ns}, endpoints: {ne}, "
                            "compatible with {nv} earlier versions",
        "rep.ucp_html": "not deployed ({path} returns an HTML page, not a manifest)",
        "rep.ucp_status": "not deployed ({path} returns {status})",
        "rep.llms_full": "present with links",
        "rep.llms_yes": "present",
        "rep.llms_no": "absent",
        "rep.robots_blocking": "blocks {n} agent types",
        "rep.robots_none": "no robots.txt (allow by default)",
        "rep.probe_skipped_note": "multi-UA probe skipped (--no-probe)",
        "rep.header": "Checked {url}",
        "rep.checked_url": "Target  {url}  ({kind})",
        "rep.score": "Score  {score}/100",
        "rep.untested": "   [not tested: {items}]",
        "rep.probe_head": "  multi-UA probe:",
        "rep.readable_short": "readable",
        "rep.blocked_short": "✗ blocked",
        "rep.ucp_head": "  UCP manifest:",
        "rep.ucp_hist": "    version {v}  earlier versions {versions}",
        "rep.service_line": "    service {name}",
        "rep.entry_line": "      {v}  {transport}  {endpoint}",
        "rep.protocols": "  ACP/AP2 probe (unverified): {protos}",
        "rep.fixes_head": "  what to fix:",
        "rep.fix_line": "    [{pri}] {title}\n         {desc}",

        # ---------------------------------------------------------- 修复清单
        "fix.ucp_missing.title": "Deploy a UCP manifest",
        "fix.ucp_missing.desc": "{path} returns {status}. UCP has a first-hand verified "
                                "site-side marker; some Shopify stores already ship it "
                                "(observed version 2026-08-25). Without it, shopping agents "
                                "cannot discover your products or checkout entry point through "
                                "the standard flow.",
        "fix.ucp_single.title": "UCP declares only one version",
        "fix.ucp_single.desc": "Currently {v}. Declaring earlier versions keeps agents that "
                               "have not upgraded working.",
        "fix.llms.title": "Add /llms.txt",
        "fix.llms.desc": "Give agents a plain-text sitemap: key pages plus a one-line "
                         "description. Put it at the site root.",
        "fix.jsonld.title": "Add Product JSON-LD",
        "fix.jsonld.desc": "Embed <script type=\"application/ld+json\"> on product pages with "
                           "@type=Product including name/brand/sku/image/description.",
        "fix.price.title": "Complete the Offer price",
        "fix.price.desc": "In Product.offers provide price, priceCurrency and availability — "
                          "these three are what shopping agents mainly use to decide "
                          "whether something is buyable.",
        "fix.field.title": "Add {field}",
        "fix.field.desc": "Missing structured-data field; agents get an incomplete record.",
        "fix.blocked.title": "Unblock these agents: {agents}",
        "fix.blocked.desc": "robots.txt or your WAF blocks them while the browser UA passes — "
                            "that is blocking agents specifically, and it costs you the agent "
                            "traffic and orders directly.",
        "fix.wildcard.title": "Review robots.txt User-agent: * Disallow: /",
        "fix.wildcard.desc": "The wildcard rule blocks every agent along with everything else.",
        "fix.protos.title": "ACP/AP2 probe hit: {protos}",
        "fix.protos.desc": "(site-side markers not verified first-hand; evidence only, "
                           "not a conclusion)",
        "pri.high": "high",
        "pri.medium": "medium",
        "pri.low": "low",
    },

    # ---------------------------------------------------------------- 中文
    "zh": {
        "site.title": "AgentBI — 你的网站对 AI agent 有多友好",
        "site.sub": "输入网址，看你的网站能被 AI agent 找到、读懂、下单吗。",
        "site.placeholder": "https://your-store.com",
        "site.button": "检测",
        "site.scanning": "检测中，约需 10–20 秒…",
        "site.lb_link": "查看榜单（225 家电商站实测）→",
        "site.tr_link": "趋势",
        "site.cr_link": "爬虫",
        "site.cat_link": "品类",
        "site.pr_link": "信号",
        "site.checks": "检测项：agent 能否抓取 · 产品结构化数据 · UCP 部署与版本 · llms.txt · "
                       "robots。工具开源，数据可复现：",
        "site.about_link": "我们怎么抓站 / 如何让我们不抓你",
        "site.issues_link": "结果有误？来提 issue",
        "site.cached": "（来自缓存）",
        "site.req_failed": "请求失败：{err}",
        "site.err": "✗ {msg}",

        # 订阅。文案刻意不承诺发送节奏——发送通道还没接，承诺了就是骗人。
        "sub.title": "每周摘要",
        "sub.desc_long": "我每天重扫这 225 家站。留下邮箱，每周摘要开始发的时候你会收到第一期："
                         "UCP 版本变化、新部署的站点、以及和上一周的环比。",
        "sub.placeholder": "you@your-store.com",
        "sub.button": "订阅",
        "sub.consent": "只用于发送摘要，不做追踪、不对外共享，随时可退订。",
        "sub.ok": "收到了，已经记下。",
        "sub.err_invalid": "这个邮箱地址看起来不对。",
        "sub.err_rate": "操作太频繁，稍后再试。",
        "sub.err_fail": "我这边出错了。稍后再试，或开个 issue 告诉我。",

        # ---- 榜单条目自助纠错（冷邮那条线留下的唯一正经产出）----------------
        "corr.title": "你的条目不对？",
        "corr.desc": "这份榜单是从外部测的，一定会测错。如果名单里有你的站，告诉我——"
                     "改数据、下架，或者认领。",
        "corr.site": "站点",
        "corr.kind": "你需要什么",
        "corr.k_wrong": "数据有错",
        "corr.k_remove": "把我的站从榜单移除",
        "corr.k_claim": "这个站是我的，联系我",
        "corr.note": "补充说明（可选）",
        "corr.email": "邮箱（可选，只用于回复你）",
        "corr.button": "提交",
        "corr.ok": "收到了，我会看。",
        "corr.err_site": "请从列表里选一个站点。",
        "corr.err_rate": "操作太频繁，稍后再试。",
        "corr.err_fail": "我这边出错了。稍后再试，或开个 issue。",
        "corr.consent": "不做追踪。留邮箱只用于回复这一条。",
        "corr.link": "条目有错？告诉我",

        "dim.fetch": "agent 能否抓取",
        "dim.structured": "产品结构化数据",
        "dim.ucp": "UCP manifest",
        "dim.llms": "llms.txt",
        "dim.robots": "robots.txt",

        "rep.checked": "检测对象",
        "rep.probe": "多 UA 探测",
        "rep.ua": "UA",
        "rep.status": "状态",
        "rep.product": "产品数据",
        "rep.result": "结果",
        "rep.readable": "可读",
        "rep.blocked": "✗ 被拦",
        "rep.ok": "✓",
        "rep.ucp_title": "UCP manifest",
        "rep.ucp_current": "当前版本 {v}，兼容历史版本 {versions}",
        "rep.service": "服务",
        "rep.version": "版本",
        "rep.transport": "传输",
        "rep.fixes": "修复清单",
        "rep.warn": "⚠ {note}",

        "err.bad_url": "URL 不合法（仅支持 http/https）",
        "err.rate": "请求过于频繁，请稍后再试",
        "err.cooldown": "该站点刚被检测过，请 {n} 分钟后再试",
        "err.busy": "现在排队检测的人较多，请 30 秒后重试",

        "lb.title": "AgentBI 榜单",
        "lb.back": "← 检测你的站",
        "lb.by_platform": "按平台对比",
        "lb.th_platform": "平台",
        "lb.th_n": "站数",
        "lb.th_ucp": "UCP",
        "lb.th_product": "产品结构化数据",
        "lb.th_llms": "llms.txt",
        "lb.th_avg": "平均分",
        "lb.method": "方法与局限（引用前请先读）",
        "lb.m1": "数据快照 <b>{date}</b>：共扫描 {scanned} 家电商站，首页返回 200 的 "
                 "<b>{reach}</b> 家（可评估），{unreach} 家返回非 200（其中 {n403} 个是 403）。",
        "lb.m2": "<b>403 是我们的 IP 信誉问题，不是对方站点的配置问题</b>——绝大多数是企业级 WAF "
                 "拦截数据中心出口 IP（Walmart / Macy's / Nordstrom / Costco 等都在其中）。"
                 "加完整浏览器头部实测无法重现。因此本表覆盖的是<b>没有企业 WAF 的站点</b>，不是全行业。",
        "lb.m3": "<b>WooCommerce n={n}</b>，全部来自 WooCommerce 官方 showcase（可抓取的就这么些）。"
                 "这是方向性结论，不是精确比例。",
        "lb.m4": "Shopify 店铺的 <code>llms.txt</code> 与 UCP 多为<b>平台自动生成</b>"
                 "（多个店铺模板逐字节相同）——它是平台分界线，不是站主努力程度的信号。",
        "lb.m5": "评分是<b>启发式</b>的：不做 JS 渲染，也不会真的通过 UCP 下单，"
                 "只验证 manifest 是否存在及其版本。",
        "lb.m6": "较上一次快照（{pdate}）：可评估 {reach_delta}，部署 UCP {ucp_delta}。"
                 "<b>可评估数会随时间波动</b>——同一批站点在不同日期相差十几个是常态"
                 "（对方 WAF 策略与我们的出口 IP 信誉都在变），所以引用本站数字时请带上快照日期。",
        "lb.detail": "明细（可评估 {reach} / 扫描 {scanned}）",
        "lb.th_site": "站点",
        "lb.note_unreach": "{n} 个站点对探测器返回非 200（多为 WAF 拦截），"
                          "不代表其 agent 友好度低，未计入榜单。",
        "lb.no_data": "还没有榜单数据",
        "lb.dash": "—",

        # ---- /trend 历史趋势（板块 2）------------------------------------
        "tr.title": "AI 就绪度趋势",
        "tr.desc": "同一批站点的每日 AI 就绪度快照：平均分、UCP 部署情况、以及日间变化榜。"
                   "每天扫一遍，不做 JS 渲染。",
        "tr.back": "← 检测我的站点",
        "tr.intro": "同一批 {n} 个站点，每天重新扫一遍。这是 AgentBI 里唯一随时间自动增值的部分——"
                    "少一天历史，就永远补不回来。",
        "tr.h_series": "每日快照",
        "tr.h_movers": "变化最大（{pdate} → {date}）",
        "tr.th_date": "日期",
        "tr.th_avg": "平均分",
        "tr.th_reach": "可评估",
        "tr.th_ucp": "已部署 UCP",
        "tr.th_delta": "变化",
        "tr.none": "本区间无。",
        "tr.up": "进步",
        "tr.down": "退步",
        "tr.no_prev": "目前只有一个快照。变化榜需要至少两天的历史——这个页面会从这里开始自己填满。",
        "tr.no_data": "还没有历史数据。",
        "tr.method": "方法与局限（引用前请先读）",
        "tr.m1": "每一行是同一批 {n} 个站点的一次每日快照，约每天 03:30 CST 扫一遍，不做 JS 渲染。",
        "tr.m2": "<b>平均分</b>只统计可评估站点（首页返回 200）。可评估数量每天会随 WAF 拦截波动，"
                 "引用平均分时请连它的日期与样本量一起给出。",
        "tr.m3": "403 是<b>我们</b>出口 IP 的信誉问题，不是站点配置有问题。今天被拦的站点明天可能又评上了"
                 "——请把这条序列当趋势读，不要当对某个单站的结论。",
        "tr.m4": "评分是<b>启发式</b>的：只检查 UCP manifest 是否存在及其版本，不会真的下单。",
        "tr.api_note": "单站历史提供 JSON 接口："
                       "<code>/api/site-history?site=https://example.com</code>",
        # ---- /crawlers 爬虫准入普查（板块 4）------------------------------
        "cr.title": "AI 爬虫准入普查",
        "cr.desc": "多少零售站在 robots.txt 里封锁了各个 AI 爬虫。同一批 {n} 个站点，每天重扫。",
        "cr.intro": "robots.txt 是一家店决定「要不要让 AI 爬虫读」的地方。这里统计同一批 {n} 个站点"
                    "（其中 {m} 个提供了 robots.txt）里，各爬虫被 <code>Disallow: /</code> 的次数。",
        "cr.th_agent": "爬虫",
        "cr.th_blocked": "被封锁于",
        "cr.th_pct": "占比",
        "cr.wildcard": "有 <b>{n}</b> 个站对 <code>*</code> 写了 <code>Disallow: /</code>——"
                       "那会拦掉所有爬虫，不只是 AI。",
        "cr.detail": "哪些站封锁了哪些爬虫",
        "cr.th_blocked_list": "被封锁的爬虫",
        "cr.none": "本批样本里没有任何一个站对受追踪的爬虫写了封锁规则。",
        "cr.method": "方法与局限（引用前请先读）",
        "cr.m1": "统计每个站 robots.txt 里匹配 {k} 个已知 AI 爬虫 token 的 <code>Disallow: /</code> "
                 "规则。快照日期 <b>{date}</b>。",
        "cr.m2": "robots.txt 里的封锁是<b>书面规则，不是实测行为</b>——有些站虽然允许，WAF 照样拦；"
                 "而扫描器遇到的 403 是我们出口 IP 的信誉问题，不是对方的规则。",
        "cr.m3": "没有 robots.txt 的站不计入分母：没有文件等于默认放行，不等于封锁。",
        "cr.m4": "每天重扫，这些数字会随各站改文件而变。引用时请带上快照日期。",
        # ---- /protocols 信号采用度（板块 3）------------------------------
        "pr.title": "AI 就绪信号采用度",
        "pr.desc": "多少站真正发布了各项机器可读信号——UCP、llms.txt、商品结构化数据——"
                   "以及同时具备全部的有多稀少。",
        "pr.intro": "基于 {date} 快照里 {n} 个可评估站点。只发布其中一项，对 agent 来说仍然不可用，"
                    "所以最后一行才是关键。",
        "pr.th_signal": "信号",
        "pr.th_n": "站数",
        "pr.th_pct": "占比",
        "pr.s_ucp": "已部署 UCP manifest",
        "pr.s_llms": "存在 llms.txt",
        "pr.s_jsonld": "商品 JSON-LD",
        "pr.s_price": "…含 price",
        "pr.s_availability": "…含 availability",
        "pr.s_robots_ok": "robots.txt 未封锁任何 AI 爬虫",
        "pr.all_title": "具备全部信号的站点",
        "pr.all_note": "{reach} 个站里只有 <b>{n}</b> 个（{pct}）同时发布了全部 {k} 项信号，"
                       "其余都是部分具备。",
        "pr.h_series": "这些占比怎么变的",
        "pr.method": "方法与局限（引用前请先读）",
        "pr.m1": "信号读自各站首页与 <code>/.well-known/</code> 路径。快照 <b>{date}</b>，"
                 "不做 JS 渲染。",
        "pr.m2": "分母<b>只含可评估站点</b>（首页返回 200）：扫描 {n} 个里的 {reach} 个。"
                 "其余是 WAF 拦截，不算失败。",
        "pr.m3": "各站的 UCP 版本与 services 几乎一模一样，因为是平台生成的——"
                 "所以统计「谁有」有意义，比较版本没有。",
        "pr.m4": "robots.txt 是书面规则，不是实测行为；而且并非每个快照都带这个字段，"
                 "较早的日期可能显示为空白。",
        # ---- /categories 分品类基准（板块 1）------------------------------
        "cat.title": "分品类 AI 就绪度基准",
        "cat.desc": "按零售品类拆分的平均分、UCP 与 llms.txt 采用率。同一批 {n} 个站点，每天重扫。",
        "cat.intro": "清单里每个站的品类是<b>人工判定</b>的。可评估站点不足 10 个的品类照样列出，"
                     "但不该当作品类基准来引用。",
        "cat.th_cat": "品类",
        "cat.th_reach": "可评估",
        "cat.th_avg": "平均分",
        "cat.th_ucp": "UCP",
        "cat.th_llms": "llms.txt",
        "cat.th_all": "全信号",
        "cat.c_apparel": "服装",
        "cat.c_shoes": "鞋",
        "cat.c_beauty": "美妆个护",
        "cat.c_home": "家居家具",
        "cat.c_electronics": "3C 电子",
        "cat.c_outdoor": "户外运动",
        "cat.c_food": "食品饮料",
        "cat.c_accessories": "配件",
        "cat.c_underwear": "内衣袜",
        "cat.c_retail": "大型零售商与平台",
        "cat.c_other": "其他",
        "cat.small": "样本小",
        "cat.method": "方法与局限（引用前请先读）",
        "cat.m1": "品类是依据各站域名与品牌<b>人工判定</b>的（见 <code>categories.py</code>），"
                  "快照 <b>{date}</b>。这是判断，不是站点自己申报的分类。",
        "cat.m2": "分母是可评估站点（首页返回 200），各类目不同。标注<i>样本小</i>的行不足 10 个，"
                  "不该当基准引用。",
        "cat.m3": "大型零售商与平台单独成行，是刻意的：它们什么品类都卖，混进品类行会两边都失真。",

        # UCP 端点普查：与首页可达性解耦，按 #867 的 reporting frame 分桶
        "lb.h_census": "UCP 端点普查",
        "lb.census_note": "只统计 <code>/.well-known/ucp</code> 的响应，"
                          "<b>与首页是否可达无关</b>——被 WAF 拦住首页的站点，"
                          "well-known 路径照样可能返回内容。按 "
                          "<a href=\"https://github.com/Universal-Commerce-Protocol/ucp/discussions/867\">"
                          "ucp#867</a> 提出的报告框架，「无法询问」与「没有」分开报。"
                          "这里没有任何一个数字是采用率。",
        "lb.th_bucket": "响应",
        "lb.b_pos": "200 且可解析 → 阳性",
        "lb.b_noparse": "200 但解析不了（无法询问）",
        "lb.b_3xx": "profile 路径返回 3xx（未跟随）",
        "lb.b_robots": "被 robots.txt 拒绝（未发起请求）",
        "lb.b_404": "404",
        "lb.b_410": "410 Gone",
        "lb.b_403": "403（拒绝我们）",
        "lb.b_rate": "429 / 418 / 503",
        "lb.b_err": "连不上",
        "lb.b_other": "其他",
        "lb.h_pos": "阳性明细",
        "lb.pos_ver": "声明的版本：{versions}。",
        "lb.pos_plat": "逐条记录平台：{platforms}。",
        "lb.decision_note": "<b>{n} 个阳性里有 {shopify} 个是 Shopify</b>——这可能只是"
                            "一个平台决策，而不是 {shopify} 个商户各自的选择。"
                            "两个数字都公布，因为它们回答的是不同的问题。",
        "lb.pos_hidden": "<b>有 {n} 个阳性的首页不返回 200</b>（{hosts}）。"
                         "它们的 WAF 拦首页但不拦 well-known 路径——"
                         "任何用首页可达性做闸门的普查都会把它们静默丢掉，"
                         "而它们恰恰是样本里最大的零售商。",
        "lb.h_read": "站点可读性",
        "lb.read_note": "只有首页返回 200 的 {n} 家能就内容打分。UCP <b>故意不放在这张表里</b>——"
                        "用首页可达性做闸门，会把 {hidden} 个阳性藏起来："
                        "它们的 WAF 拦首页，但不拦 well-known 路径。",
        "lb.f_frame": "<b>报告框架。</b>抽样框：{scanned} 个消费类/DTC 店铺的手工便利样本，"
                      "外加 WooCommerce 官方 showcase——<b>不是随机抽样</b>，且偏向 Shopify，"
                      "所以汇总比例反映的是样本的平台构成。检查路径：只查 "
                      "<code>/.well-known/ucp</code>，单路径、单次尝试、不重试、跟进重定向。"
                      "阳性判据：状态 200 + 可解析为 JSON + 含 <code>ucp.version</code>。",

        "about.title": "关于 AgentBI",
        "about.h_what": "这是什么",
        "about.p_what": "AgentBI 检测一个网站对 AI agent 的友好程度：agent 能不能抓到页面、商品数据"
                        "能不能被机器读懂（JSON-LD 的价格/库存）、有没有部署 UCP manifest、"
                        "有没有 <code>llms.txt</code>。",
        "about.h_how": "我们怎么抓",
        "about.li1": "<b>只在有人提交网址时才抓</b>，不是全网持续爬取。",
        "about.li2": "用户代理标识为 "
                     "<code>agentbi/0.1 (+https://agentbi.tech/about; agent-readiness scanner)</code>，"
                     "不伪装成浏览器。",
        "about.li3": "单次检测对同一站点发起约 10 个请求，耗时 15–20 秒。",
        "about.li4": "<b>同一域名 10 分钟内只真扫一次</b>，结果缓存 30 分钟。",
        "about.li5": "结果公开在<a href=\"/leaderboard\">榜单</a>里。",
        "about.h_exception": "有一处例外，说明一下",
        "about.p_exception": "检测里有一步是「多 UA 探测」：用几个真实 AI agent 的标识"
                        "（GPTBot、ClaudeBot 等）和<b>一个真实浏览器的标识</b>各请求一次你的站点，"
                        "对比返回是否不同——这是为了回答「你的站有没有把 AI agent 和正常访客"
                        "区别对待」。<b>这一步必须是真实标识才测得出来</b>，"
                        "所以这里是测量工具，不是匿名抓取。除这一步外，"
                        "所有内容抓取都用上面那个诚实的用户代理。",
        "about.h_optout": "不想被扫",
        "about.p_optout": "目前尚未实现 robots.txt 自动遵从——这是已知的待办。可用的退出通道有两个：",
        "about.li_issue": "<b>（推荐）开一个 issue</b>："
                          "<a href=\"https://github.com/JamesChief/agentbi/issues/new?template=opt-out.yml\">"
                          "「要求停止扫描」模板</a>，把域名加进屏蔽清单，抓取前会检查。",
        "about.li_email": "邮件：<a href=\"mailto:contact@agentbi.tech\">"
                          "<code>contact@agentbi.tech</code></a>，回复 stop 即加入屏蔽清单",
        "about.h_data": "数据",
        "about.p_data": "检测结果会被公开收录进榜单。榜单只统计返回 200 的站点；对探测器返回非 200 的"
                        "站点（多为企业级 WAF 拦截）不会出现在榜单里，也不会被解读为「该站 "
                        "agent 友好度低」。",
        "about.back": "← 返回检测",

        "og.site_name": "AgentBI",
        "og.home_title": "AgentBI — 你的网站对 AI agent 有多友好",
        "og.home_desc": "Shopify 店铺 86% 已支持 agent 商务，WooCommerce 0%。你的站呢？"
                        "输入网址，15 秒出报告。",
        "og.lb_title": "AgentBI 榜单 — 225 家电商站 agent 友好度实测",
        "og.lb_desc": "Shopify 86% 已部署 UCP，WooCommerce 0%。"
                      "平台差异比站主努力更能决定你能不能被 shopping agent 找到。",

        "rep.err_unreachable": "无法访问：{err}",
        "rep.fetch_skipped": "未测（--no-probe）",
        "rep.fetch_inconclusive": "不可判定（探测器网络受限，不计分）",
        "rep.fetch_detail": "{ok}/{total} 个 agent 可取到页面，{readable} 个能读到产品/价格数据",
        "rep.struct_full": "Product JSON-LD 完整",
        "rep.struct_partial": "有部分产品数据",
        "rep.struct_none": "未找到结构化产品数据",
        "rep.ucp_deployed": "已部署 {v}，{ns} 个服务、{ne} 个 endpoint，兼容 {nv} 个历史版本",
        "rep.ucp_html": "未部署（{path} 返回 HTML 页面，非 manifest）",
        "rep.ucp_status": "未部署（{path} 返回 {status}）",
        "rep.llms_full": "有且含链接",
        "rep.llms_yes": "有",
        "rep.llms_no": "无",
        "rep.robots_blocking": "拦 {n} 类 agent",
        "rep.robots_none": "无 robots.txt（默认放行）",
        "rep.probe_skipped_note": "已跳过多 UA 探测（--no-probe）",
        "rep.header": "检测 {url}",
        "rep.checked_url": "检测对象  {url}  ({kind})",
        "rep.score": "得分  {score}/100",
        "rep.untested": "   [未测: {items}]",
        "rep.probe_head": "  多 UA 探测:",
        "rep.readable_short": "可读",
        "rep.blocked_short": "✗ 被拦",
        "rep.ucp_head": "  UCP manifest:",
        "rep.ucp_hist": "    version {v}  历史版本 {versions}",
        "rep.service_line": "    service {name}",
        "rep.entry_line": "      {v}  {transport}  {endpoint}",
        "rep.protocols": "  ACP/AP2 探针（未核实）: {protos}",
        "rep.fixes_head": "  修复清单:",
        "rep.fix_line": "    [{pri}] {title}\n         {desc}",

        "fix.ucp_missing.title": "部署 UCP manifest",
        "fix.ucp_missing.desc": "{path} 返回 {status}。UCP 已有一手核实的站点侧标识，"
                                "Shopify 部分店铺已自动部署（实测版本 2026-08-25）。"
                                "缺它意味着 shopping agent 无法按标准流程发现你的商品与下单入口。",
        "fix.ucp_single.title": "UCP 只声明单一版本",
        "fix.ucp_single.desc": "当前 {v}。多声明历史版本可兼容尚未升级的 agent。",
        "fix.llms.title": "加 /llms.txt",
        "fix.llms.desc": "给 agent 一份纯文本站点地图：核心页面 + 一句话说明。放站点根目录。",
        "fix.jsonld.title": "加 Product JSON-LD",
        "fix.jsonld.desc": "商品页嵌 <script type=\"application/ld+json\">，@type=Product，"
                           "含 name/brand/sku/image/description。",
        "fix.price.title": "补齐 Offer 价格",
        "fix.price.desc": "Product.offers 里给 price、priceCurrency、availability——"
                          "shopping agent 主要靠这三个字段判断是否可买。",
        "fix.field.title": "补 {field}",
        "fix.field.desc": "结构化数据字段缺失，agent 读到的信息不完整。",
        "fix.blocked.title": "放行被拦的 agent: {agents}",
        "fix.blocked.desc": "robots.txt 或 WAF 把这些 agent 挡了，且浏览器 UA 没被挡——"
                            "属于只挡 agent，会直接损失 agent 带来的流量与订单。",
        "fix.wildcard.title": "检查 robots.txt 的 User-agent: * Disallow: /",
        "fix.wildcard.desc": "通配规则会一并挡住所有 agent。",
        "fix.protos.title": "ACP/AP2 探针命中: {protos}",
        "fix.protos.desc": "（站点侧标识尚未一手核实，仅作证据，不作为结论）",
        "pri.high": "高",
        "pri.medium": "中",
        "pri.low": "低",
    },
}


def t(key, lang=DEFAULT, **kw):
    """取值；缺 key 静默回落到英文（加文案时两个语言都要加）。"""
    s = STR.get(lang, {}).get(key) or STR[DEFAULT].get(key, key)
    return s.format(**kw) if kw else s


_PH = re.compile(r"\{\{(\w[\w.]*)\}\}")


def render_template(text, lang):
    """把模板里的 {{key}} 换成当前语言的文案。"""
    return _PH.sub(lambda m: t(m.group(1), lang), text)
