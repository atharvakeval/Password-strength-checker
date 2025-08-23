import requests

def dir_bruteforce(domain, wordlist_path, verbose=False):
    url = f"http://{domain}"
    found_paths = []

    try:
        with open(wordlist_path, 'r') as f:
            for line in f:
                path = line.strip()
                full_url = f"{url}/{path}"
                try:
                    response = requests.get(full_url, timeout=3)
                    if response.status_code == 200:
                        if verbose:
                            print(f"[+] Found: {full_url}")
                        found_paths.append(full_url)
                    elif response.status_code == 403:
                        if verbose:
                            print(f"[!] Forbidden (403): {full_url}")
                except requests.RequestException:
                    # Silently pass connection errors, timeouts, etc.
                    continue
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {wordlist_path}")
    return found_paths
