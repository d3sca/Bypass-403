# Bypass-403

# usage
options:

-l, --list, help=File with targets (one per line).<br>
-u, --url, help=Single target URL .<br>
-o, --out, default=bypass_results.csv, help=CSV output file.<br>
-c, --concurrency, type=int, default=10, help=Concurrent threads per target.<br>
--timeout, type=float, default=10.0, help=Request timeout seconds.<br>
--delay, type=float, default=0.0, help=Delay between requests (seconds).<br>
-m, --method, choices=METHODS, help=Limit to a single HTTP method.<br>
-H, --headers-file, help=File with additional headers (KEY: VALUE per line).<br>
--extra, nargs=*, help=Extra path variants to try (e.g. '/.php', '/%2e/'.<br>
--user-agent, default=Mozilla/5.0 (compatible; bypass-403-script/1.0, help=User-Agent string).<br>
--proxy, help=HTTP(S proxy (e.g. http://127.0.0.1:8080).<br>
--dry-run, action=store_true, help=Don't send requests, only show planned combos.<br>
--max-per-target, type=int, help=Cap total attempts per target (for safety).<br>

# Examples
you can scan a list of targets:
```
python3 bypass_403.py -l targets.txt -c 30 --timeout 8 --out results.csv
```

or 
a single target:
```
python3 bypass_403.py -u https://example.com/admin -m GET -H extra_headers.txt
```
