# AgentBI

**Is your website reachable, readable, and purchasable by an AI agent?**

- Web: <https://agentbi.tech> — paste a URL, get a report
- CLI: `agentbi https://your-store.com`

Agentic commerce protocols (UCP / ACP / AP2) shipped in 2025–2026. This answers a
much more boring question: **how many sites have actually deployed any of it**, and
what does a single site need to fix.

---

## What it checks

| Check | How |
|---|---|
| Can an agent fetch you? | Re-requests the page with 6 real agent UAs (GPTBot, ClaudeBot, PerplexityBot, …) plus one browser UA as the control group, and compares responses |
| Is your product data machine-readable? | Product JSON-LD with `price` / `availability` / `brand`. Homepages usually have none, so it discovers a product page first |
| `llms.txt` | Present, and not a soft-404 (SPA / catch-all routes return 200 + HTML for any path) |
| UCP manifest | `GET /.well-known/ucp`, parses version + services + transport |
| robots.txt | Does it disallow known agents? |

Output is a 0–100 score plus a prioritized fix list.

Scoring is **heuristic**. It is for seeing the gap, not for auditing a site.

---

## Install

```bash
pip install agentbi           # or: uvx agentbi <url>  (nothing installed permanently)

agentbi https://your-store.com          # human-readable report
agentbi https://your-store.com --json   # machine-readable
agentbi https://your-store.com --no-probe   # static checks only, no multi-UA probing
```

From a clone (no install): `python3 agentbi.py https://your-store.com` — same flags.

Web version (stdlib only):

```bash
python3 serve.py --port 8000     # serves web/ + /api/check + /leaderboard
```

---

## Limitations — read before quoting any number

These are the ones that matter; the leaderboard page says the same thing.

1. **No JS rendering.** Client-rendered content is invisible to this scanner.
2. **It does not place an order.** A UCP manifest is checked for existence and version,
   not for actually completing a checkout.
3. **Coverage is ~50%, and it is our problem, not the sites'.** In the 2026-10-05 batch,
   115 of 225 stores were evaluable; 78 returned 403. That is datacenter IP reputation
   hitting enterprise WAFs. Full browser headers were tried and did not reproduce.
   *The data covers stores without an enterprise WAF, not the industry.*
4. **WooCommerce n=8.** It is every site harvestable from WooCommerce's own showcase.
   Read it as a direction, not a percentage.
5. **`llms.txt` is often platform-generated.** Allbirds, Death Wish Coffee and Ombraz have
   byte-identical templates. On Shopify it is a platform dividing line, not a signal of effort.

---

## Data

**The run is daily and the raw result is public:**
<https://agentbi.tech/batch.json> — one file, no key, 225 stores, every field we
measure (including the per-row `probed_host` / `settled_host` / `host_unsettled`
and the UCP status, content-type, 3xx target and cache headers behind each
outcome). Rendered at <https://agentbi.tech/leaderboard>.

That file is **today's run only**. `batch.json` in this repo is a dated snapshot,
not the live one — check `generated_at` before quoting anything from it.

Headline as of the 2026-10-13 run: 225 stores scanned, 130 evaluable (homepage
returned 200), avg score 51. Of those, Shopify 68 → 57 with UCP (84%),
WooCommerce 10 → 0, SalesforceCC 7 → 0, unclassified 45 → 1.

If you are reporting UCP numbers against a shared frame, note that our positive
is `/.well-known/ucp` answering 200, **parsing as JSON** and **declaring
`ucp.version`** — the parse-only count is published separately as `ucp_parsed`,
because the two are not the same measurement and can diverge.

---

## Language

English by default (the audience is store owners, mostly non-Chinese).
`?lang=zh` on the site, `--lang zh` on the CLI. All user-facing strings live in
`agentbi_strings.py` — **add keys in both languages**, a missing key silently falls back to English.

## Crawling behaviour

- Content is fetched **only when someone submits a URL**. No continuous crawling.
- User agent is honest and identifiable:
  `agentbi/0.1 (+https://agentbi.tech/about; agent-readiness scanner)`
- The single exception is the multi-UA probe, which must use real agent identifiers
  to measure differential treatment. That step is documented on `/about`.
- ~10 requests per check, 15–20s. One real scan per domain per 10 minutes; results cached 30 min.
- Want out? <contact@agentbi.tech>.

---

## License

MIT, except `batch.json` data which you are free to use with attribution.
