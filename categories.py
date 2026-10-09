#!/usr/bin/env python3
"""给扫描清单打品类标签。

用法：
    python3 categories.py                 # 输出分类结果 + 未分类清单
    python3 categories.py --uncategorized # 只输出未分类的（补规则时看这个）

品类是"分品类基准页"的前提。这份映射是**人工维护的资产**——
自动分类只认域名特征，认不出来的宁可留空（标 Other），也不能猜，
否则基准页上的数字是假的。

新增站点后跑一次 --uncategorized，把没认出来的补进 RULES。
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# 品类 -> (正则,)。按 LABELS 顺序匹配，先命中者胜，所以更具体的要放前面。
RULES = [
    # ---- 1. 大型零售商/平台。不是单一品类，单独一类，必须放最前面 ----
    ("retail", [
        r"walmart\.com", r"target\.com", r"costco\.com", r"nordstrom\.com",
        r"macys\.com", r"kohls\.com", r"homedepot\.com", r"lowes\.com",
        r"ikea\.com", r"amazon\.com", r"ebay\.com", r"aliexpress\.com",
        r"jd\.com", r"bol\.com", r"cdiscount\.com", r"otto\.de",
        r"etsy\.com", r"coolblue\.nl", r"johnlewis\.com", r"argos\.co\.uk",
        r"muji\.com", r"leroymerlin\.fr", r"mediamarkt\.de",
        r"currys\.co\.uk", r"rei\.com", r"dickssportinggoods\.com",
        r"sephora\.com", r"ulta\.com", r"gamestop\.com", r"chewy\.com",
        r"petco\.com", r"tractorsupply\.com", r"acehardware\.com",
        r"microcenter\.com", r"newegg\.com", r"bhphotovideo\.com",
        r"adorama\.com", r"decathlon\.fr", r"zalando\.com", r"aboutyou\.de",
        r"marksandspencer\.com", r"next\.co\.uk", r"farfetch\.com",
        r"net-a-porter\.com", r"ssense\.com", r"mrporter\.com",
        r"bestbuy\.com", r"overstock\.com", r"wayfair\.com",
        r"kithandkin\.co\.uk", r"drop\.com",
        r"theiconic\.com\.au", r"kogan\.com", r"catch\.com\.au",
        r"bunnings\.com\.au", r"well\.ca", r"bookshop\.org",
        r"blackwells\.co\.uk", r"wordery\.com", r"notonthehighstreet\.com",
        r"drawnandquarterly\.com",
        r"depop\.com", r"vestiairecollective\.com", r"onlynaturalpet\.com",
        r"polestar\.com",
    ]),
    # ---- 2. 美妆个护 ----
    ("beauty", [
        r"glossier\.com", r"colourpop\.com", r"kyliecosmetics\.com",
        r"beardbrand\.com", r"theordinary\.com", r"paulaschoice\.com",
        r"tatcha\.com", r"youthtothepeople\.com", r"herbivorebotanicals\.com",
        r"biossance\.com", r"drunkelephant\.com", r"supergoop\.com",
        r"kiehls\.com", r"aveda\.com", r"lush\.com", r"gruum\.com",
        r"beauty", r"cosmetic", r"skincare", r"makeup", r"cipherskincare\.com",
    ]),
    # ---- 3. 内衣袜 ----
    ("underwear", [
        r"thirdlove\.com", r"cuup\.com", r"bombas\.com", r"underwear",
        r"lingerie",
    ]),
    # ---- 4. 鞋 ----
    ("shoes", [
        r"allbirds\.com", r"clarks\.com", r"crocs\.com", r"drmartens\.com",
        r"timberland\.com", r"newbalance\.com", r"asics\.com",
        r"keenfootwear\.com", r"vivaia\.com",
        r"shoe", r"sneaker", r"boot", r"footwear",
    ]),
    # ---- 5. 户外运动装备（在服装之前判，否则 patagonia 会被 apparel 吃掉）----
    ("outdoor", [
        r"patagonia\.com", r"thenorthface\.com", r"arcteryx\.com",
        r"columbia\.com", r"hellyhansen\.com", r"salomon\.com",
        r"merrell\.com", r"osprey\.com", r"yeti\.com", r"hydroflask\.com",
        r"cotopaxi\.com", r"kuiu\.com", r"voormi\.com",
        r"blackdiamondequipment\.com", r"petzl\.com", r"mammut\.com",
        r"haglofs\.com", r"fjallraven\.com", r"bulk\.com",
        r"jensonusa\.com", r"chainreactioncycles\.com", r"wiggle\.com",
        r"evanscycles\.com", r"cycl", r"bike",
        r"outdoor", r"sport", r"fitness", r"camp", r"hike",
    ]),
    # ---- 6. 服装 ----
    ("apparel", [
        r"gymshark\.com", r"chubbiesshorts\.com", r"everlane\.com",
        r"taylorstitch\.com", r"buckmason\.com", r"fashionnova\.com",
        r"paragonfitwear\.com", r"hiut\.co", r"gap\.com", r"zara\.com",
        r"uniqlo\.com", r"asos\.com", r"boohoo\.com", r"shein\.com",
        r"h-m\.com|hm\.com", r"freepeople\.com", r"urbanoutfitters\.com",
        r"anthropologie\.com", r"madewell\.com", r"jcrew\.com",
        r"lulus\.com", r"revolve\.com", r"puma\.com", r"underarmour\.com",
        r"cupshe\.com", r"shopcider\.com", r"halara",
        r"aritzia\.com", r"lululemon\.com", r"mackage\.com",
        r"sunspel\.com", r"sunspel\.co\.uk", r"orlebarbrown\.com",
        r"zozotown\.com", r"beams\.co\.jp", r"wolfandbadger\.com",
        r"trouva\.com", r"theoutnet\.com", r"uniqlo\.cn",
        r"outlier\.nyc", r"westernrise\.com", r"ministryofsupply\.com",
        r"mackweldon\.com", r"untuckit\.com", r"bonobos\.com",
        r"rhone\.com", r"trueclassictees\.com",
        r"apparel", r"cloth", r"fashion", r"jean", r"shirt", r"dress",
        r"bombassaddles\.com",
    ]),
    # ---- 7. 家居家具 ----
    ("home", [
        r"casper\.com", r"brooklinen\.com", r"westelm\.com",
        r"potterybarn\.com", r"worldmarket\.com", r"containerstore\.com",
        r"surlatable\.com", r"article\.com", r"burrow\.com",
        r"crateandbarrel\.com", r"williams-sonoma\.com", r"wayfair\.com",
        r"meblostan\.pl", r"muista\.eu", r"lamarzoccousa\.com",
        r"joybird\.com", r"cb2\.com", r"dwr\.com", r"hermanmiller\.com",
        r"steelcase\.com",
        r"home", r"furniture", r"mattress", r"decor", r"kitchen",
    ]),
    # ---- 8. 食品饮料 ----
    ("food", [
        r"deathwishcoffee\.com", r"lacolombe\.com", r"drinktrade\.com",
        r"burlapandbarrel\.com", r"diasporaco\.com", r"huel\.com",
        r"helloyumi\.com", r"mammamiaitaly\.com", r"brodo\.com",
        r"vanleeuwenicecream\.com", r"jococups\.com",
        r"coffee", r"food", r"snack", r"tea", r"chocolate", r"yarn",
    ]),
    # ---- 9. 3C 电子 ----
    ("electronics", [
        r"tesla\.com", r"anker\.com", r"ugreen\.com", r"roborock\.com",
        r"govee\.com", r"ecoflow\.com", r"lego\.com", r"nintendo\.com",
        r"store\.playstation\.com", r"keychron\.com", r"twelvesouth\.com",
        r"tech", r"gadget", r"phone", r"laptop", r"audio",
    ]),
    # ---- 10. 配件/眼镜/手表/包 ----
    ("accessories", [
        r"ridge\.com", r"mvmt\.com", r"peakdesign\.com", r"ombraz\.com",
        r"warbyparker\.com", r"fellowproducts\.com",
        r"oliviaburton\.com", r"monicavinader\.com", r"astleyclarke\.com",
        r"watch", r"bag", r"wallet", r"eyewear", r"glasses",
    ]),
]

LABELS = [k for k, _ in RULES]
OTHER = "other"


def categorize(url):
    """返回品类。认不出返回 'other'——宁可留空也不猜。"""
    host = re.sub(r"^https?://", "", url).split("/")[0].lower()
    host = re.sub(r"^www\d*\.", "", host)
    for label, pats in RULES:
        for p in pats:
            if re.search(p, host):
                return label
    return OTHER


def load_sites(path=None):
    path = path or os.path.join(HERE, "sites.txt")
    return [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]


def main():
    sites = load_sites(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None)
    res = {s: categorize(s) for s in sites}
    counts = {}
    for v in res.values():
        counts[v] = counts.get(v, 0) + 1

    if "--uncategorized" in sys.argv:
        for s, v in res.items():
            if v == OTHER:
                print(re.sub(r"^https?://", "", s).replace("www.", "").rstrip("/"))
        print(f"\n# 未分类 {counts.get(OTHER, 0)} / {len(sites)}", file=sys.stderr)
        return

    print(f"总计 {len(sites)} 个站")
    for k in LABELS + [OTHER]:
        print(f"  {k:<14} {counts.get(k, 0):>4}")
    print()
    from collections import defaultdict
    g = defaultdict(list)
    for s, v in res.items():
        g[v].append(re.sub(r"^https?://", "", s).replace("www.", "").rstrip("/"))
    for k in LABELS + [OTHER]:
        if not g[k]:
            continue
        print(f"--- {k} ({len(g[k])}) ---")
        print("  " + ", ".join(sorted(g[k])[:30]))
        if len(g[k]) > 30:
            print(f"  …还有 {len(g[k]) - 30} 个")
        print()


if __name__ == "__main__":
    main()
