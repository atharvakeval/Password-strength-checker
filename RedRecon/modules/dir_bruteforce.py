import requests
from yaspin import yaspin

def dir_bruteforce(domain, wordlist_path, verbose=False):
    url = f"http://{domain}"
    found_paths = []

    try:
        with open(wordlist_path, 'r') as f, yaspin(text="Running directory brute force...", color="cyan") as spinner:
            for line in f:
                path = line.strip()
                full_url = f"{url}/{path}"
                try:
                    response = requests.get(full_url, timeout=3)
                    if response.status_code == 200:
                        found_paths.append(full_url)
                        if verbose:
                            print(f"[+] Found: {full_url}")
                    elif response.status_code == 403:
                        if verbose:
                            print(f"[!] Forbidden (403): {full_url}")
                except requests.RequestException:
                    # silently skip errors like connection refused or timeout
                    pass
            spinner.ok("✔")
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {wordlist_path}")
    except Exception as e:
        print(f"[-] Directory brute force error: {e}")

    return found_paths
