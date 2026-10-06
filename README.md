# AgentBI

**Is your website reachable, readable, and purchasable by an AI agent?**

- Web: <https://agentbi.tech> — paste a URL, get a report
- CLI: `python3 agentbi.py https://your-store.com`

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
pip install requests          # the only dependency
python3 agentbi.py https://your-store.com          # human-readable report
python3 agentbi.py https://your-store.com --json   # machine-readable
python3 agentbi.py https://your-store.com --no-probe   # static checks only, no multi-UA probing
```

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

`batch.json` — 225 online stores scanned 2026-10-05 (115 evaluable), with per-site
platform, score, UCP version, JSON-LD and llms.txt findings. Rendered at
<https://agentbi.tech/leaderboard>.

Headline: Shopify 69 stores → 59 with UCP (86%), avg 78. WooCommerce 8 → 0, avg 28.
Custom stacks 35 → 1 (avg 14). Two stores were one UCP version behind.

---

## Language

English by default (the audience is store owners, mostly non-Chinese).
`?lang=zh` on the site, `--lang zh` on the CLI. All user-facing strings live in
`strings.py` — **add keys in both languages**, a missing key silently falls back to English.

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
