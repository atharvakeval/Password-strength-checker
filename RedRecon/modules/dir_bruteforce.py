def dir_bruteforce(domain, wordlist_path):
    url = f"http://{domain}"
    with open(wordlist_path, 'r') as f:
        for line in f:
            path = line.strip()
            full_url = f"{url}/{path}"
            try:
                response = requests.get(full_url, timeout=3)
                if response.status_code == 200:
                    print(f"[+] Found: {full_url}")
                elif response.status_code == 403:
                    print(f"[!] Forbidden (403): {full_url}")
            except Exception:
                pass
