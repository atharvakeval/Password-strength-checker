import requests

def dir_bruteforce(domain, wordlist_path, verbose=False):
    url = f"http://{domain}"
    results = []

    with open(wordlist_path, 'r') as f:
        for line in f:
            path = line.strip()
            full_url = f"{url}/{path}"
            try:
                response = requests.get(full_url, timeout=3)
                if response.status_code == 200:
                    print(f"[+] Found: {full_url}")
                    results.append(full_url)
                elif response.status_code == 403 and verbose:
                    print(f"[!] Forbidden (403): {full_url}")
            except Exception as e:
                if verbose:
                    print(f"[!] Error accessing {full_url} -> {e}")
    return results
