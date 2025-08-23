import requests
from tqdm import tqdm
import os

def dir_bruteforce(domain, wordlist_path, verbose=False):
    url = f"http://{domain}"

    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist file not found: {wordlist_path}")
        return []

    print(f"[+] Starting directory brute force on {domain}...")
    found_paths = []

    with open(wordlist_path, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]

    for path in tqdm(paths, desc="Brute-forcing", unit="path"):
        full_url = f"{url}/{path}"
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                print(f"[+] Found: {full_url}")
                found_paths.append(full_url)
            elif response.status_code == 403 and verbose:
                print(f"[!] Forbidden (403): {full_url}")
        except requests.RequestException:
            if verbose:
                print(f"[x] Error accessing: {full_url}")

    print(f"[+] Directory brute force complete. {len(found_paths)} directories found.")
    return found_paths
