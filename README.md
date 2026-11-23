# Katana URL Explorer

**Turn a ProjectDiscovery Katana crawl into an organized, searchable URL inventory for web and API security assessments.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/) ![No dependencies](https://img.shields.io/badge/dependencies-stdlib_only-brightgreen) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Katana outputs can contain thousands of URLs. Instead of scanning a long text file with `grep` repeatedly, Katana URL Explorer creates an offline **interactive directory tree**, category-specific URL files, a CSV inventory, and a terminal-friendly tree. It does **not** send HTTP requests or exploit vulnerabilities.

## Highlights

- **Offline HTML explorer:** expandable host/folder structure, instant search, category and review-priority filters.
- **17 categories:** IDOR/BOLA, SQLi, XSS, SSRF, redirects, authentication, admin, access control, APIs, uploads, downloads, sensitive files, debug, business logic, dynamic extensions, JavaScript and parameterized URLs.
- **Legacy and enterprise extensions:** `.action`, `.do`, `.jsp`, `.jspx`, `.ashx`, `.php`, `.aspx`, `.asmx`, `.svc`, `.jsf`, `.faces`, `.cgi`, `.pl`, `.cfm`.
- **Export formats:** `url_inventory.csv`, `url_tree.txt`, `interesting_urls.txt`, deduplicated crawl URLs, 17 category files, and `stats.json`.
- **Zero third-party dependencies:** Python standard library only; Bash wrapper included.
- **Privacy-conscious visual reports:** query parameter **names**, not values, appear in the HTML and CSV. Raw URL text files still contain original query values.

> [!IMPORTANT]
> **Keyword matches indicate review candidates, not confirmed vulnerabilities.** Path-derived folders are a visualization of URLs, not proof of real filesystem directories. Test only assets you are authorized to assess.

## Requirements

- Python **3.9+** (standard library only)
- Bash (optional, for the `.sh` launcher)
- Existing Katana crawl output containing one `http://` or `https://` URL per line

## Quick start

Clone the repository and put a crawl file beside the script:

```bash
git clone https://github.com/ArupSEK/katana_analyzer.git
cd katana-url-explorer
```

Generate a crawl with [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana), or use an existing one:

```bash
katana -u https://example.com -d 3 -o devdolphin_katana
```

Analyze it:

```bash
chmod +x katana_analyzer.sh
./katana_analyzer.sh devdolphin_katana
# Or without Bash:
python3 katana_analyzer.py devdolphin_katana
```

Choose another output directory:

```bash
python3 katana_analyzer.py urls.txt custom_results
```

Open the explorer:

```bash
xdg-open katana_results/url_explorer.html    # Linux desktop
open katana_results/url_explorer.html        # macOS
# Windows: double-click the HTML file in Explorer.
```

## Output

```text
katana_results/
├── all_urls.txt             # Deduplicated original URLs (may contain tokens!)
├── filtered_urls.txt        # Static files and JS removed
├── interesting_urls.txt     # Categorized non-static, non-JS URLs
├── url_inventory.csv        # Host, path, parameter names, priority, categories
├── url_tree.txt             # Terminal-readable directory tree
├── url_explorer.html        # Interactive, self-contained browser report
├── stats.json               # Counts by category and priority
└── categories/
    ├── access_control.txt
    ├── admin.txt
    ├── api.txt
    ├── authentication.txt
    ├── business_logic.txt
    ├── debug.txt
    ├── download.txt
    ├── dynamic_endpoints.txt
    ├── idor.txt
    ├── javascript.txt
    ├── parameters.txt
    ├── redirect.txt
    ├── sensitive_files.txt
    ├── sqli.txt
    ├── ssrf.txt
    ├── upload.txt
    └── xss.txt
```

### Example directory tree

Given URLs such as `https://example.com/admin/users/edit.action?id=101` and `https://example.com/api/v1/users/202`:

```text
example.com
├── admin/
│   └── users/
│       └── edit.action ?id [High]
└── api/
    └── v1/
        └── users/
            └── 202 [Medium]
```

The explorer also displays category tags and variant counts. Parameter values are suppressed, so `edit.action?id=101` and `edit.action?id=102` collapse into one *endpoint signature* with a count of 2 (the original URLs remain in text exports).

## Review categories

| Category | Example indicators | Typical manual review |
|---|---|---|
| `idor` | `id`, `user_id`, numeric/UUID path segments | Object-level access checks |
| `sqli` | `id`, `query`, `sort`, `filter` | Input-to-database data flow |
| `xss` | `q`, `message`, `comment`, `search` | Output encoding/context |
| `ssrf` | `url`, `webhook`, `proxy`, `host` | Server-side fetch behavior |
| `redirect` | `next`, `redirect_uri`, `returnUrl` | Redirect validation |
| `authentication` | `login`, `otp`, `jwt`, `sso`, `token` | Session and identity flows |
| `admin` / `access_control` | `admin`, `roles`, `permissions` | Authorization boundaries |
| `api` | `/api/`, `/v1/`, `graphql`, `swagger` | API endpoint inventory |
| `upload` / `download` | `upload`, `attachment`, `file`, `path` | File handling and access |
| `sensitive_files` | `.env`, `.bak`, `.map`, `.git/` | Unintended exposure |
| `debug` | `actuator`, `trace`, `metrics` | Misconfiguration review |
| `business_logic` | `checkout`, `refund`, `coupon` | Workflow/rule enforcement |
| `dynamic_endpoints` | `.action`, `.do`, `.jsp`, `.ashx`, `.php` | Framework-specific routes |
| `javascript` | `.js`, `.mjs` | Client-side route inventory |
| `parameters` | URLs containing query parameters | Additional input mapping |

Review priority is based on coarse path heuristics: **High** for authentication/admin/upload/sensitive files/business logic/access-control keywords, **Medium** for other categorized endpoints or parameters, and **Low** otherwise. It is **not** a CVSS score or a vulnerability finding.

## How to use the HTML explorer

1. Open `katana_results/url_explorer.html` locally in Chrome, Firefox, or Edge.
2. Expand/collapse the inferred URL directories.
3. Type a path, parameter name, hostname, or category into the search field.
4. Select a category (such as `dynamic_endpoints` or `idor`) and review-priority filter.
5. Use the CSV inventory to plan manual testing and record outcomes in your normal VAPT workflow.

## Security and privacy

- The program is **passive**: it only reads input from disk and writes local output files.
- `url_explorer.html` and `url_inventory.csv` omit query **values**, but paths and parameter **names** can still be sensitive.
- `all_urls.txt`, `interesting_urls.txt`, `filtered_urls.txt`, and `categories/*.txt` retain original **full URLs**, which might include secrets/tokens. **Do not commit crawls or output directories.** A `.gitignore` is included for the default paths.
- The HTML report escapes displayed strings and does not load external JavaScript libraries.
- An endpoint match alone does not establish exploitability or even reachability. It does not discover endpoints absent from the crawl, POST-only fields, or client-side routes that require JS analysis.
- Do not publish confidential application data or real customer URLs in screenshots, issues, or pull requests.

## Development and tests

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q katana_analyzer.py
```

Tests cover key URL classifications, dynamic extensions, CSV injection guard, endpoint deduplication, exported files and HTML suppression of query values. GitHub Actions runs the tests on pushes and pull requests.

## Roadmap

Potential improvements include path-template normalization (turning `/users/101` into `/users/{id}`), multi-crawl comparisons, HTTP method metadata imports, and large-crawl lazy rendering.

## License

MIT — see [LICENSE](LICENSE).