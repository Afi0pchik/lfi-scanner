import requests
import argparse
from urllib.parse import urlparse, urlencode
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor
import os

def load_payloads(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def get_common_params():
    return ['file', 'page', 'path', 'dir', 'url', 'doc', 'folder', 'template', 'view']

def build_url(base_url, param, payload):
    return f"{base_url}?{urlencode({param: payload})}"

def scan_url(session, base_url, param, payload):
    url = build_url(base_url, param, payload)
    try:
        response = session.get(url, timeout=6)
        if any(key in response.text.lower() for key in ['root:x', 'failed to open stream', 'no such file', '/bin/bash']):
            return (url, True)
    except requests.RequestException:
        pass
    return (url, False)

def run_scanner(base_url, payloads):
    print("\nLFI SCANNER\n-----------\n")

    params = get_common_params()
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; LFI-Scanner/1.0)",
        "Accept": "*/*"
    })

    hits = []

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(params) * len(payloads))

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            for param in params:
                for payload in payloads:
                    futures.append(executor.submit(scan_url, session, base_url, param, payload))

            for future in futures:
                url, vulnerable = future.result()
                if vulnerable:
                    hits.append(url)
                progress.update(task, advance=1)

    if hits:
        print("\n[+] Vulnerable URLs found:")
        for h in hits:
            print("  ->", h)
    else:
        print("\n[-] No vulnerable parameters found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LFI Scanner CLI")
    parser.add_argument("url", help="Target base URL (e.g., http://site.com/index.php)")
    parser.add_argument("-p", "--payloads", default="payloads_lfi.txt", help="Payloads file path")

    args = parser.parse_args()

    if not os.path.isfile(args.payloads):
        print(f"[!] Payloads file not found: {args.payloads}")
        exit(1)

    run_scanner(args.url, load_payloads(args.payloads))
