#!/usr/bin/env python3
"""Passive Katana URL inventory, classification, and offline explorer.

No HTTP requests are made. Python 3.9+; standard library only.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

CATEGORY_NAMES = (
    "idor", "sqli", "xss", "ssrf", "redirect", "authentication",
    "admin", "access_control", "api", "upload", "download",
    "sensitive_files", "debug", "business_logic", "dynamic_endpoints",
    "javascript", "parameters",
)

STATIC_RE = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|mp3|avi)$", re.I)
JS_RE = re.compile(r"\.(?:js|mjs)$", re.I)
DYNAMIC_RE = re.compile(r"\.(?:action|do|jsp|jspx|ashx|php|aspx|asmx|svc|jsf|faces|cgi|pl|cfm)(?:;|/|$)", re.I)
UUID_OR_ID_RE = re.compile(r"/(?:[0-9]{2,}|[a-f0-9]{8}-[a-f0-9-]{27,})(?:/|$)", re.I)

ID_PARAMS = set("id uid userid user_id uuid account_id accountid customerid tenantid orgid order_id document_id recordid ownerid invoiceid referenceid transactionid".split())
SQLI_PARAMS = set("id uid pid search query category sort filter product item record where order".split())
XSS_PARAMS = set("q search query keyword message name input text html content description title feedback comment".split())
SSRF_PARAMS = set("url uri target dest destination proxy feed webhook endpoint image_url imageurl source link host domain remote fetch".split())
REDIRECT_PARAMS = set("redirect redirect_uri next return returnurl return_url continue callback goto return_to redirecturl".split())
FILE_PARAMS = set("file filepath filename path template document page include resource locale lang".split())

PATH_PATTERNS = {
    "authentication": r"login|logout|signin|signup|sign-in|sign-up|register|password|forgot|reset|auth|oauth|saml|openid|jwt|jwks|otp|mfa|2fa|totp|session|token|refresh|revoke|verify|activate|rescuepassword|sso",
    "admin": r"admin|dashboard|manage|console|backend|internal|private|staff|administrator",
    "access_control": r"permission|privilege|access|role|policy|group|membership|invite|impersonate|delegate|approve|assign",
    "api": r"/api(?:/|$)|/rest(?:/|$)|/v[0-9]+(?:/|$)|graphql|graphiql|swagger|openapi|api-docs|wsdl|soap|jsonrpc|xmlrpc|/rpc/|/batch",
    "upload": r"upload|attachment|import|multipart|filemanager|file-manager",
    "download": r"download|export|attachment|filemanager",
    "sensitive_files": r"\.env|\.git(?:/|$)|\.svn(?:/|$)|\.ds_store|\.htaccess|\.htpasswd|\.(?:bak|backup|old|sql|db|sqlite|log|conf|ini|zip|tar|gz|map|ya?ml)(?:/|$)|application\.properties|web\.config|wp-config\.php|dockerfile|composer\.json|package\.json",
    "debug": r"debug|trace|actuator|heapdump|threaddump|jolokia|jmx|metrics|prometheus|server-status|health|config|staging|/test(?:/|$)|/dev(?:/|$)",
    "business_logic": r"payment|checkout|cart|order|invoice|coupon|discount|wallet|balance|transfer|refund|subscription|amount|price|quantity|redeem|withdraw|deposit|limit|confirm|cancel|approve|reject|freeze|unfreeze",
}
COMPILED_PATTERNS = {tag: re.compile(pattern, re.I) for tag, pattern in PATH_PATTERNS.items()}
HIGH_CATEGORIES = {"sensitive_files", "admin", "authentication", "upload", "access_control", "business_logic"}


def classify(path: str, parameter_names: tuple[str, ...]) -> list[str]:
    """Identify review categories; matches are NOT evidence of vulnerabilities."""
    names = {name.lower() for name in parameter_names}
    categories = set()
    if parameter_names:
        categories.add("parameters")
    if JS_RE.search(path):
        categories.add("javascript")
    if DYNAMIC_RE.search(path):
        categories.add("dynamic_endpoints")
    if names & ID_PARAMS or UUID_OR_ID_RE.search(path):
        categories.add("idor")
    if names & SQLI_PARAMS:
        categories.add("sqli")
    if names & XSS_PARAMS:
        categories.add("xss")
    if names & SSRF_PARAMS:
        categories.add("ssrf")
    if names & REDIRECT_PARAMS:
        categories.add("redirect")
    if names & FILE_PARAMS:
        categories.add("download")
    for tag, pattern in COMPILED_PATTERNS.items():
        if pattern.search(path):
            categories.add(tag)
    return sorted(categories)


def priority(tags: list[str]) -> str:
    tag_set = set(tags)
    if tag_set & HIGH_CATEGORIES:
        return "High"
    if tag_set - {"javascript", "parameters"} or "parameters" in tag_set:
        return "Medium"
    return "Low"


def write_lines(path: Path, lines: set[str] | list[str]) -> None:
    entries = sorted(lines)
    path.write_text("\n".join(entries) + ("\n" if entries else ""), encoding="utf-8")


def csv_safe(value: str) -> str:
    """Prevent spreadsheet formula execution in exported fields."""
    value = str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def new_node() -> dict:
    return {"folders": {}, "pages": []}


def make_tree(rows: list[dict]) -> dict:
    sites = {}
    for item in rows:
        path = item["path"]
        segments = [segment for segment in path.split("/") if segment]
        if path == "/":
            folders, leaf = [], "(root)"
        elif path.endswith("/"):
            folders, leaf = segments, "(index)"
        else:
            folders, leaf = segments[:-1], segments[-1]
        node = sites.setdefault(item["host"], new_node())
        for folder in folders:
            node = node["folders"].setdefault(folder, new_node())
        node["pages"].append((leaf, item))
    return sites


def label(leaf: str, item: dict) -> str:
    params = " ?" + ", ".join(item["params"]) if item["params"] else ""
    return leaf + params


def text_tree(sites: dict) -> str:
    lines = []

    def walk(node: dict, prefix: str = "") -> None:
        entries = [("folder", name, child) for name, child in sorted(node["folders"].items())]
        entries.extend(("page", name, data) for name, data in sorted(node["pages"]))
        for index, (kind, name, value) in enumerate(entries):
            last = index == len(entries) - 1
            connector = "└── " if last else "├── "
            if kind == "folder":
                lines.append(prefix + connector + name + "/")
                walk(value, prefix + ("    " if last else "│   "))
            else:
                lines.append(prefix + connector + label(name, value) + f" [{value['priority']}]")

    for host, node in sorted(sites.items()):
        lines.append(host)
        walk(node)
        lines.append("")
    return "\n".join(lines)


def render_html(sites: dict, rows: list[dict]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)

    def render(node: dict, depth: int = 0) -> str:
        parts = []
        for name, child in sorted(node["folders"].items()):
            opened = " open" if depth == 0 else ""
            parts.append(f'<details class="folder"{opened}><summary>📁 {esc(name)}/</summary>'
                         + render(child, depth + 1) + "</details>")
        for leaf, item in sorted(node["pages"]):
            tags = ", ".join(item["tags"]) or "Uncategorized"
            search = " ".join((item["host"], item["path"], *item["params"], *item["tags"])).lower()
            parts.append(
                f'<div class="endpoint {item["priority"].lower()}" '
                f'data-priority="{esc(item["priority"])}" '
                f'data-categories="{esc("|".join(item["tags"]))}" '
                f'data-search="{esc(search)}">'
                f'<div class="endpoint-name">📄 {esc(label(leaf, item))}</div>'
                f'<small>{esc(item["priority"])} review priority · {esc(tags)} · '
                f'{item["variants"]} URL variant(s)</small></div>'
            )
        return "\n".join(parts)

    sections = "\n".join(
        f'<details class="folder host" open><summary>🌐 {esc(host)}</summary>{render(node)}</details>'
        for host, node in sorted(sites.items())
    )
    counts = Counter(r["priority"] for r in rows)
    options = "\n".join(
        f'<option value="{esc(tag)}">{esc(tag)} ({sum(tag in r["tags"] for r in rows)})</option>'
        for tag in CATEGORY_NAMES
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Katana URL Explorer</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;font-family:system-ui,Arial,sans-serif;background:#f5f7fb;color:#182230}
header{background:#172b4d;color:#fff;padding:24px 30px}header h1{margin:0 0 6px}header p{margin:0;opacity:.85}
main{max-width:1300px;margin:auto;padding:24px}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}
.stat{background:white;border-radius:10px;padding:16px;border:1px solid #e3e7ef}.stat strong{display:block;font-size:25px}.stat span{color:#64748b;font-size:13px}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;background:#fff;padding:16px;border-radius:10px;border:1px solid #e3e7ef;margin-bottom:18px}
input,select{font:inherit;padding:10px;border:1px solid #cbd5e1;border-radius:6px}input{flex:2;min-width:200px}select{flex:1;min-width:150px}
.tree{background:white;padding:20px;border-radius:10px;border:1px solid #e3e7ef}details{margin:6px 0 6px 20px;padding-left:13px;border-left:1px solid #d6dce5}
summary{cursor:pointer;padding:7px 4px;font-weight:600;overflow-wrap:anywhere}.host>summary{font-size:17px}
.endpoint{padding:10px 13px;margin:6px 0 6px 24px;border-left:4px solid #94a3b8;border-radius:6px;background:#f8fafc;overflow-wrap:anywhere}
.endpoint.high{border-color:#dc2626}.endpoint.medium{border-color:#d97706}.endpoint.low{border-color:#64748b}
.endpoint-name{font-weight:500}small{display:block;color:#64748b;font-size:12px;margin-top:5px}[hidden]{display:none!important}
.footer{color:#64748b;font-size:12px;margin-top:20px}@media(max-width:650px){.stats{grid-template-columns:repeat(2,1fr)}main{padding:12px}}
</style></head><body><header><h1>Katana URL Explorer</h1><p>Directory hierarchy · Security categories · Endpoint inventory</p></header>
<main><section class="stats"><div class="stat"><strong>__TOTAL__</strong><span>Endpoint signatures</span></div>
<div class="stat"><strong>__HOSTS__</strong><span>Hosts</span></div>
<div class="stat"><strong>__HIGH__</strong><span>High review priority</span></div>
<div class="stat"><strong>__MEDIUM__</strong><span>Medium review priority</span></div></section>
<section class="toolbar"><input id="search" type="search" placeholder="Search paths, parameters or categories" aria-label="Search endpoints">
<select id="category" aria-label="Filter by category"><option value="all">All categories</option>__OPTIONS__</select>
<select id="priority" aria-label="Filter by priority"><option value="all">All priorities</option><option>High</option><option>Medium</option><option>Low</option></select></section>
<p>Showing <strong id="visible">__TOTAL__</strong> endpoint signatures</p><section class="tree">__TREE__</section>
<p class="footer">Offline URL triage only. Priority is a suggested review order, not a confirmed vulnerability severity. Query values are not included in the HTML.</p></main>
<script>
const search=document.getElementById('search'),category=document.getElementById('category'),priority=document.getElementById('priority');
function filter(){const q=search.value.toLowerCase().trim(),cat=category.value,pr=priority.value;let shown=0;
document.querySelectorAll('.endpoint').forEach(el=>{const cats=el.dataset.categories.split('|');const ok=el.dataset.search.includes(q)&&(cat==='all'||cats.includes(cat))&&(pr==='all'||el.dataset.priority===pr);el.hidden=!ok;if(ok)shown++;});
const active=q!==''||cat!=='all'||pr!=='all';Array.from(document.querySelectorAll('details.folder')).reverse().forEach(folder=>{const visible=folder.querySelector('.endpoint:not([hidden])')!==null;folder.hidden=!visible;if(active&&visible)folder.open=true;});
document.getElementById('visible').textContent=shown;}
search.addEventListener('input',filter);category.addEventListener('change',filter);priority.addEventListener('change',filter);
</script></body></html>""".replace("__TOTAL__", str(len(rows))).replace("__HOSTS__", str(len(sites))).replace("__HIGH__", str(counts["High"])).replace("__MEDIUM__", str(counts["Medium"])).replace("__OPTIONS__", options).replace("__TREE__", sections)


def analyze(input_path: Path, output_path: Path) -> dict:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    category_dir = output_path / "categories"
    category_dir.mkdir(exist_ok=True)
    urls = set()
    for raw in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = raw.strip()
        if url.startswith(("http://", "https://")):
            urls.add(url)

    records: dict[tuple, dict] = {}
    categorized = {name: set() for name in CATEGORY_NAMES}
    interesting, filtered = set(), set()
    rejected = 0
    for url in sorted(urls):
        try:
            split = urlsplit(url)
            # Do not include embedded URL credentials in displayed host.
            host = split.netloc.rsplit("@", 1)[-1].lower()
            if not host:
                rejected += 1
                continue
            path = split.path or "/"
            params = tuple(sorted({key for key, _ in parse_qsl(split.query, keep_blank_values=True)}))
            tags = classify(path, params)
            static = bool(STATIC_RE.search(path))
            javascript = bool(JS_RE.search(path))
            if not static and not javascript:
                filtered.add(url)
            for tag in tags:
                categorized[tag].add(url)
            if not static and not javascript and tags:
                interesting.add(url)
            key = (host, path, params)
            if key not in records:
                records[key] = {"host": host, "path": path, "params": params, "tags": tags, "priority": priority(tags), "variants": 0}
            records[key]["variants"] += 1
        except (ValueError, UnicodeError):
            rejected += 1

    write_lines(output_path / "all_urls.txt", urls)
    write_lines(output_path / "filtered_urls.txt", filtered)
    write_lines(output_path / "interesting_urls.txt", interesting)
    for category, matches in categorized.items():
        write_lines(category_dir / f"{category}.txt", matches)

    rows = sorted(records.values(), key=lambda r: ({"High": 0, "Medium": 1, "Low": 2}[r["priority"]], r["host"], r["path"], r["params"]))
    with (output_path / "url_inventory.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(("Host", "Path", "Parameter Names", "URL Variants", "Review Priority", "Categories"))
        for row in rows:
            writer.writerow((csv_safe(row["host"]), csv_safe(row["path"]), csv_safe(", ".join(row["params"])), row["variants"], row["priority"], ", ".join(row["tags"])))

    sites = make_tree(rows)
    (output_path / "url_tree.txt").write_text(text_tree(sites), encoding="utf-8")
    (output_path / "url_explorer.html").write_text(render_html(sites, rows), encoding="utf-8")
    counts = Counter(row["priority"] for row in rows)
    stats = {"unique_urls": len(urls), "endpoint_signatures": len(rows), "hosts": len(sites), "interesting_urls": len(interesting), "rejected_urls": rejected, "priorities": dict(counts), "categories": {k: len(v) for k, v in categorized.items()}}
    (output_path / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Visualize and categorize existing Katana crawls without network requests.")
    parser.add_argument("input", nargs="?", default="devdolphin_katana", help="Katana URL list (default: devdolphin_katana)")
    parser.add_argument("output", nargs="?", default="katana_results", help="Output directory (default: katana_results)")
    args = parser.parse_args()
    try:
        stats = analyze(Path(args.input), Path(args.output))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"[ERROR] {exc}\n")
    print("[+] Katana URL Explorer completed (offline)")
    print(f"    URLs: {stats['unique_urls']} | Endpoint signatures: {stats['endpoint_signatures']} | Hosts: {stats['hosts']}")
    print(f"    High: {stats['priorities'].get('High', 0)} | Medium: {stats['priorities'].get('Medium', 0)} | Low: {stats['priorities'].get('Low', 0)}")
    print(f"    HTML: {Path(args.output) / 'url_explorer.html'}")
    print(f"    CSV:  {Path(args.output) / 'url_inventory.csv'}")
    print(f"    Tree: {Path(args.output) / 'url_tree.txt'}")
    print(f"    Category filters: {Path(args.output) / 'categories'}")


if __name__ == "__main__":
    main()
