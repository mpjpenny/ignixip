#!/usr/bin/env python3
"""Build indexable HTML pages for GitHub Pages.

Edit data/ips.tsv or data/asns.tsv, then run:

    python3 scripts/build_pages.py

Weekly refresh of ASN names from RDAP (keeps the previous text if RDAP fails):

    python3 scripts/build_pages.py --refresh
"""

import argparse
import html
import json
import csv
import sys
import urllib.request
from datetime import date
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://ignixip.com"
TODAY = date.today().isoformat()

TOOLS = [
    {
        "slug": "ip-lookup",
        "tab": "ip",
        "embed": "ip",
        "title": "IP address lookup",
        "h1": "IP address lookup",
        "description": "Look up any IPv4 or IPv6 address. See the network owner, location, and AbuseIPDB score. Free, no signup.",
        "lead": "Type an IP address to see who announces it, where it is geolocated, and whether AbuseIPDB has recent reports.",
        "placeholder": "8.8.8.8",
        "button": "Look up",
        "body": "An IP lookup answers a practical question: which network is this address on, and does it have a reputation problem? ignixip queries public routing and geolocation data in your browser and shows the organisation, location, and AbuseIPDB confidence.",
        "faqs": [
            ("What does an IP lookup show?", "The network organisation, a city-level location, the hostname when one is published, and an AbuseIPDB confidence score when that service responds."),
            ("Is the location exact?", "No. Geolocation is approximate, usually city or region, and it is often the location of the network operator rather than a person."),
            ("Can I look up my own address?", "Yes. The What is my IP page shows the address this site sees, and you can open it here for the full report."),
        ],
    },
    {
        "slug": "blacklist-check",
        "tab": "bl",
        "embed": "blacklist",
        "title": "IP blacklist check",
        "h1": "IP blacklist check",
        "description": "Check an IPv4 address against SpamCop, Barracuda, and UCEPROTECT, plus AbuseIPDB. Spamhaus is not queried.",
        "lead": "See whether an address is listed on the DNS blacklists this page can query, and what AbuseIPDB currently reports.",
        "placeholder": "8.8.8.8",
        "button": "Check",
        "body": "A blacklist check asks DNS-based lists whether they publish the address. This page queries SpamCop, Barracuda, and UCEPROTECT, plus AbuseIPDB. Spamhaus requires a licensed feed and is not checked here, so a clear result is not a Spamhaus clearance.",
        "faqs": [
            ("Does this include Spamhaus?", "No. Spamhaus does not answer public resolver queries reliably, and ignixip does not use a licensed feed. Those rows are marked not checked on the full lookup."),
            ("What does a listing mean?", "A listing means that list currently publishes the address. It can be a policy listing, a shared address, or a report of spam. Read the list name before treating it as abuse."),
            ("How current is the result?", "The check runs in your browser when you open or submit the form, so it is not a cached snapshot."),
        ],
    },
    {
        "slug": "dns-lookup",
        "tab": "dns",
        "embed": "dns",
        "title": "DNS lookup",
        "h1": "DNS lookup",
        "description": "Look up A, AAAA, MX, NS, and TXT records for any domain. Free DNS tool from ignixip.",
        "lead": "Query public DNS for a domain and read the records that mail and web servers use.",
        "placeholder": "example.com",
        "button": "Look up",
        "body": "DNS lookup shows the addresses, mail servers, name servers, and text records published for a domain. ignixip asks a public resolver from your browser and lists the answers it receives.",
        "faqs": [
            ("Which record types are shown?", "A, AAAA, MX, NS, and TXT. The full DNS tool on the homepage also requests CNAME."),
            ("Can I check a mail domain?", "Yes. MX and TXT records are the ones that matter for mail delivery and for SPF."),
            ("Why might a record be missing?", "The domain may not publish that type, or the resolver may have failed. Try the full DNS tool if an answer looks incomplete."),
        ],
    },
    {
        "slug": "asn-lookup",
        "tab": "asn",
        "embed": "asn",
        "title": "ASN lookup",
        "h1": "ASN lookup",
        "description": "Look up an autonomous system number. See the registered name of the network operator. Free ASN tool.",
        "lead": "Enter an ASN such as AS15169 to see the name published in the registry.",
        "placeholder": "AS15169",
        "button": "Look up",
        "body": "An autonomous system number identifies a network on the public Internet. This page reads the registration name from RDAP. The static ASN pages on ignixip add a short description and a country for the operators we publish.",
        "faqs": [
            ("What is an ASN?", "It is a number assigned to a network operator, such as an ISP, a cloud provider, or a university."),
            ("How do I write one?", "AS15169 and 15169 are the same network. The form accepts either."),
            ("Where do the ASN pages come from?", "A curated list is built into static HTML so search engines can index them. The form still fetches a live RDAP record."),
        ],
    },
    {
        "slug": "dmarc-check",
        "tab": "dns",
        "embed": "dmarc",
        "title": "DMARC and mail DNS check",
        "h1": "DMARC check",
        "description": "Look up the DNS records a domain publishes for mail, including TXT records used by SPF and DMARC. Free.",
        "lead": "Enter a domain to read the TXT and MX records that mail authentication depends on.",
        "placeholder": "example.com",
        "button": "Check DNS",
        "body": "DMARC and SPF are published as DNS TXT records. This page loads the domain's TXT and MX records so you can see whether a policy is present. For a plain-English reading of an aggregate report file, use the DMARC report tool.",
        "faqs": [
            ("What should I look for?", "A TXT record starting with v=spf1, and a TXT record at _dmarc.example.com starting with v=DMARC1. This quick form shows TXT records on the domain itself."),
            ("Does this parse a DMARC report?", "No. Paste an aggregate report into the DMARC report tool. This page is the DNS half of the check."),
            ("Why check MX as well?", "MX records name the servers that receive mail. A domain with no MX and no SPF is not set up to send or receive mail in the usual way."),
        ],
    },
    {
        "slug": "header-analyzer",
        "tab": "headers",
        "embed": "headers",
        "title": "Email header analyser",
        "h1": "Email header analyser",
        "description": "Paste email headers and pull out the IPv4 addresses in Received lines. Then open each address in ignixip.",
        "lead": "Paste a header block. The page lists IPv4 addresses it finds so you can look each one up.",
        "placeholder": "Paste Received headers…",
        "button": "Find addresses",
        "textarea": True,
        "body": "Received headers record the path an email took. The useful part for a reputation check is often an IP address in those lines. This page extracts IPv4 addresses locally in your browser. Nothing is uploaded.",
        "faqs": [
            ("Are headers uploaded?", "No. The scan runs in the page. Only a later lookup of an address contacts ignixip's data sources."),
            ("Which addresses matter?", "Start with the earliest public address that is not your own mail provider's internal network. The full header tool traces the order."),
            ("What about IPv6?", "This extractor looks for IPv4. Use the full header tool for a longer trace."),
        ],
    },
    {
        "slug": "bulk-check",
        "tab": "bulk",
        "embed": "bulk",
        "title": "Bulk IP check",
        "h1": "Bulk IP check",
        "description": "Preview up to five IPv4 addresses and their network owners. The full bulk tool checks up to 25 after a free email signup.",
        "lead": "Paste addresses. This page previews the first five. The full tool handles up to 25.",
        "placeholder": "8.8.8.8\n1.1.1.1",
        "button": "Preview",
        "textarea": True,
        "body": "Bulk check is for a short list of addresses from a log or a header, not a whole spam feed. The preview asks for the published organisation of up to five addresses. A free account on the full tool raises that to 25.",
        "faqs": [
            ("How many addresses can I check?", "This page previews five. The full bulk tool accepts 25 per request after you confirm an email address."),
            ("Does the preview include blacklists?", "No. It shows the network owner. Open an address for the reputation check."),
            ("Is the list uploaded?", "Each preview address is looked up individually from your browser. Do not paste addresses you are not allowed to check."),
        ],
    },
]


def read_tsv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def esc(value):
    return html.escape(value or "", quote=True)


def watch_cta(target, kinds):
    """Static 'Watch this address' card. kinds is blacklist and/or dns."""
    safe_target = esc(target)
    if "dns" in kinds:
        detail = (
            "Free email when the SPF, DMARC, DKIM or MX records for %s change, "
            "or when it is listed or delisted on a public blacklist. "
            "We only write when something changes, after you confirm."
        ) % safe_target
    else:
        detail = (
            "Free email when %s is listed or delisted on a public blacklist. "
            "We only write when something changes, after you confirm."
        ) % safe_target
    href = "/watch/?target=%s&kinds=%s" % (quote(target, safe=""), quote(",".join(kinds), safe=","))
    return """<aside class="watch-cta">
    <div>
        <p class="watch-kicker">Free email alert</p>
        <h2>Watch this address</h2>
        <p>%s</p>
    </div>
    <a class="ix-btn pri" href="%s">Watch %s</a>
</aside>
""" % (detail, esc(href), safe_target)


def footer():
    return """
<footer>
    <div class="wrap">
        <div class="fgrid">
            <div>
                <a class="logo" href="/"><span class="ix">IX</span>ignixip</a>
                <p class="footer-blurb">Free IP, DNS and blacklist intelligence. A community tool by Ignix.</p>
            </div>
            <div>
                <h4>Tools</h4>
                <ul>
                    <li><a href="/tools/ip-lookup/">IP lookup</a></li>
                    <li><a href="/tools/dns-lookup/">DNS lookup</a></li>
                    <li><a href="/tools/asn-lookup/">ASN lookup</a></li>
                    <li><a href="/tools/blacklist-check/">Blacklist check</a></li>
                    <li><a href="/tools/dmarc-check/">DMARC check</a></li>
                    <li><a href="/tools/header-analyzer/">Header analyser</a></li>
                    <li><a href="/tools/bulk-check/">Bulk check</a></li>
                </ul>
            </div>
            <div>
                <h4>Network</h4>
                <ul>
                    <li><a href="/ip/8.8.8.8/">8.8.8.8</a></li>
                    <li><a href="/ip/1.1.1.1/">1.1.1.1</a></li>
                    <li><a href="/asn/AS15169/">AS15169 Google</a></li>
                    <li><a href="/asn/AS13335/">AS13335 Cloudflare</a></li>
                    <li><a href="/my-ip.html">What is my IP</a></li>
                </ul>
            </div>
            <div>
                <h4>More</h4>
                <ul>
                    <li><a href="/watch/">Watch</a></li>
                    <li><a href="/privacy/">Privacy</a></li>
                    <li><a href="https://ignix.co.uk">Ignix</a></li>
                    <li><a href="/api.html">API</a></li>
                    <li><a href="/guide.html">Blacklist guide</a></li>
                    <li><a href="/dmarc.html">DMARC reports</a></li>
                    <li><a href="/">Home</a></li>
                </ul>
            </div>
        </div>
        <div class="legal"><span>© 2026 Ignix. All rights reserved.</span><span>Data sources: public DNS, RDAP, AbuseIPDB</span></div>
    </div>
</footer>
"""


def header():
    return """
<header>
    <div class="wrap nav">
        <a class="logo" href="/"><span class="ix">IX</span>ignixip</a>
        <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-links" onclick="var open=document.body.classList.toggle('nav-open');this.setAttribute('aria-expanded',open?'true':'false')">Menu</button>
        <nav class="links" id="site-links" onclick="document.body.classList.remove('nav-open')">
            <a href="/">Lookup</a>
            <a href="/tools/ip-lookup/">Tools</a>
            <a href="/watch/">Watch</a>
            <a href="/my-ip.html">What is my IP</a>
            <a href="/#faq">FAQ</a>
            <a href="/api.html">API</a>
        </nav>
        <a class="nav-cta" href="/tools/bulk-check/">Bulk check — free</a>
    </div>
</header>
"""


def json_ld(obj):
    return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c")


def faq_block(faqs):
    items = []
    html_bits = []
    for q, a in faqs:
        items.append({"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}})
        html_bits.append("<details><summary>%s</summary><p>%s</p></details>" % (esc(q), esc(a)))
    return items, "\n".join(html_bits)


def page(title, description, canonical, body, graph, extra_scripts=""):
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>%s</title>
    <meta name="description" content="%s">
    <link rel="canonical" href="%s">
    <meta property="og:title" content="%s">
    <meta property="og:description" content="%s">
    <meta property="og:url" content="%s">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary">
    <link rel="stylesheet" href="/site.css">
    <script type="application/ld+json">%s</script>
</head>
<body>
%s
<main class="seo"><div class="wrap">
%s
</div></main>
%s
%s<script src="/embed.js"></script>
</body>
</html>
""" % (esc(title), esc(description), esc(canonical), esc(title), esc(description), esc(canonical), json_ld(graph), header(), body, footer(), extra_scripts)


def widget(kind, value, placeholder, button, textarea=False, auto=False):
    field = (
        '<textarea data-query rows="6" placeholder="%s">%s</textarea>' % (esc(placeholder), esc(value))
        if textarea
        else '<input data-query value="%s" placeholder="%s" aria-label="%s" autocomplete="off">' % (esc(value), esc(placeholder), esc(placeholder))
    )
    return """
<div class="widget" data-embed="%s" data-auto="%s">
    <form class="search" action="/">
        %s
        <button class="ix-btn pri" type="submit">%s</button>
    </form>
    <div data-results></div>
</div>
""" % (esc(kind), "1" if auto else "0", field, esc(button))


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ip_page(row, asn_link):
    ip = row["ip"].strip()
    name = row["name"].strip()
    about = row["about"].strip()
    canonical = "%s/ip/%s/" % (ORIGIN, ip)
    title = "%s %s — IP lookup | ignixip" % (ip, name)
    description = "%s (%s). %s Run a live lookup for the current organisation and AbuseIPDB score." % (ip, name, about)
    faqs = [
        ("What is %s?" % ip, about),
        ("Who publishes %s?" % name, "%s is the service name we use for this address. The live lookup below shows the organisation currently announced for it." % name),
        ("How do I see blacklist status?", "Open the full report from the result card. Spamhaus is not part of the quick check on this page."),
    ]
    faq_json, faq_html = faq_block(faqs)
    facts = [
        ("Address", esc(ip)),
        ("Known as", esc(name)),
    ]
    if asn_link:
        facts.append(("Network", '<a href="/asn/%s/">%s</a>' % (esc(asn_link), esc(asn_link))))
    bits = ["<dt>%s</dt><dd>%s</dd>" % (esc(k), v) for k, v in facts]
    body = """
<h1>%s</h1>
<p class="lead">%s</p>
<dl class="seo-dl">%s</dl>
%s
<h2>Live lookup</h2>
%s
<h2>Questions</h2>
%s
""" % (esc("%s — %s" % (ip, name)), esc(about), "".join(bits), watch_cta(ip, ["blacklist"]), widget("ip", ip, "IP address", "Look up", auto=True), faq_html)
    graph = [
        {"@type": "WebPage", "@id": canonical, "url": canonical, "name": title, "description": description},
        {"@type": "FAQPage", "mainEntity": faq_json},
    ]
    return page(title, description, canonical, body, {"@context": "https://schema.org", "@graph": graph})


def asn_page(row):
    num = str(row["asn"]).strip()
    label = "AS" + num
    name = row["name"].strip()
    country = row["country"].strip()
    about = row["about"].strip()
    canonical = "%s/asn/%s/" % (ORIGIN, label)
    title = "%s %s — ASN lookup | ignixip" % (label, name)
    description = "%s is %s, %s. %s" % (label, name, country, about)
    faqs = [
        ("Who operates %s?" % label, "%s is registered as %s, %s. %s" % (label, name, country, about)),
        ("Which country is listed?", "We publish %s for %s. The live RDAP card shows the registry name returned when you load the page." % (country, name)),
        ("How is this different from an IP lookup?", "An ASN is the whole network. An IP lookup is one address inside some network. IP pages link here when we know the ASN."),
    ]
    faq_json, faq_html = faq_block(faqs)
    bits = "".join("<dt>%s</dt><dd>%s</dd>" % (esc(k), esc(v)) for k, v in (("ASN", label), ("Operator", name), ("Country", country)))
    body = """
<h1>%s</h1>
<p class="lead">%s</p>
<dl class="seo-dl">%s</dl>
<h2>Live registration lookup</h2>
%s
<h2>Questions</h2>
%s
""" % (esc("%s — %s" % (label, name)), esc(about), bits, widget("asn", label, "AS15169", "Look up", auto=True), faq_html)
    graph = [
        {"@type": "WebPage", "@id": canonical, "url": canonical, "name": title, "description": description},
        {"@type": "FAQPage", "mainEntity": faq_json},
    ]
    return page(title, description, canonical, body, {"@context": "https://schema.org", "@graph": graph})


def tool_page(tool):
    canonical = "%s/tools/%s/" % (ORIGIN, tool["slug"])
    title = "%s | ignixip" % tool["title"]
    faq_json, faq_html = faq_block(tool["faqs"])
    body = """
<h1>%s</h1>
<p class="lead">%s</p>
<p>%s</p>
<h2>Use the tool</h2>
%s
<h2>Questions</h2>
%s
""" % (esc(tool["h1"]), esc(tool["lead"]), esc(tool["body"]), widget(tool["embed"], "", tool["placeholder"], tool["button"], textarea=tool.get("textarea", False), auto=False), faq_html)
    graph = [
        {
            "@type": "WebApplication",
            "name": "ignixip " + tool["h1"],
            "url": canonical,
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Web",
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
            "description": tool["description"],
        },
        {"@type": "FAQPage", "mainEntity": faq_json},
    ]
    extra = '<script src="/watch-cta.js"></script>\n' if tool.get("embed") in ("dns", "dmarc") else ""
    return page(title, tool["description"], canonical, body, {"@context": "https://schema.org", "@graph": graph}, extra)


IP_ASN = {
    "8.8.8.8": "AS15169", "8.8.4.4": "AS15169",
    "1.1.1.1": "AS13335", "1.0.0.1": "AS13335", "1.1.1.2": "AS13335", "1.1.1.3": "AS13335",
    "9.9.9.9": "AS19281", "9.9.9.10": "AS19281", "149.112.112.112": "AS19281",
    "208.67.222.222": "AS36692", "208.67.220.220": "AS36692", "208.67.222.123": "AS36692", "208.67.220.123": "AS36692",
    "151.101.1.1": "AS54113", "151.101.65.1": "AS54113", "151.101.129.1": "AS54113", "151.101.193.1": "AS54113",
}


def refresh_asns(rows):
    for row in rows:
        url = "https://rdap.org/autnum/" + row["asn"]
        try:
            with urllib.request.urlopen(url, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            name = (payload.get("name") or "").strip()
            if name:
                row["name"] = name.split(" - ")[0][:80]
                row["about"] = "%s operates %s. Registry name: %s." % (row["name"], "AS" + row["asn"], name[:120])
                print("refreshed", row["asn"], row["name"])
        except Exception as exc:
            print("keep", row["asn"], exc.__class__.__name__)
    return rows


def write_tsv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="Update ASN names from RDAP")
    args = parser.parse_args()
    ips = read_tsv(ROOT / "data" / "ips.tsv")
    asns = read_tsv(ROOT / "data" / "asns.tsv")
    if args.refresh:
        asns = refresh_asns(asns)
        write_tsv(ROOT / "data" / "asns.tsv", asns, ["asn", "name", "country", "about"])
    asn_ids = {"AS" + row["asn"] for row in asns}
    ip_urls = []
    for row in ips:
        asn = IP_ASN.get(row["ip"], "")
        if asn not in asn_ids:
            asn = ""
        write(ROOT / "ip" / row["ip"] / "index.html", ip_page(row, asn))
        ip_urls.append(ORIGIN + "/ip/%s/" % row["ip"])
    asn_urls = []
    for row in asns:
        write(ROOT / "asn" / ("AS" + row["asn"]) / "index.html", asn_page(row))
        asn_urls.append(ORIGIN + "/asn/AS%s/" % row["asn"])
    tool_urls = []
    for tool in TOOLS:
        write(ROOT / "tools" / tool["slug"] / "index.html", tool_page(tool))
        tool_urls.append(ORIGIN + "/tools/%s/" % tool["slug"])
    index = {
        "ips": {row["ip"]: True for row in ips},
        "asns": {"AS" + row["asn"]: True for row in asns},
    }
    write(ROOT / "indexed.js", "window.IGNIX_INDEX = %s;\n" % json.dumps(index, separators=(",", ":")))
    static = [
        ORIGIN + "/",
        ORIGIN + "/watch/",
        ORIGIN + "/privacy/",
        ORIGIN + "/my-ip.html",
        ORIGIN + "/check.html",
        ORIGIN + "/dmarc.html",
        ORIGIN + "/mail-auth.html",
        ORIGIN + "/guide.html",
        ORIGIN + "/threats.html",
        ORIGIN + "/summary.html",
        ORIGIN + "/search.html",
        ORIGIN + "/api.html",
    ]
    locs = static + tool_urls + ip_urls + asn_urls
    urlset = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for loc in locs:
        urlset.append("  <url><loc>%s</loc><lastmod>%s</lastmod></url>" % (esc(loc), TODAY))
    urlset.append("</urlset>\n")
    (ROOT / "sitemap.xml").write_text("\n".join(urlset), encoding="utf-8")
    robots = ROOT / "robots.txt"
    text = robots.read_text(encoding="utf-8") if robots.exists() else "User-agent: *\nAllow: /\n"
    if "Sitemap:" not in text:
        text = text.rstrip() + "\nSitemap: https://ignixip.com/sitemap.xml\n"
    robots.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print("ips", len(ips), "asns", len(asns), "tools", len(TOOLS), "urls", len(locs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
