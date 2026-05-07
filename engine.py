import json
import os
import requests
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

class ShovelEngine:
    def __init__(self, dork_file="dorks.json"):
        self.dork_library = self._load_dorks(dork_file)

    def _load_dorks(self, filepath):
        if not os.path.exists(filepath):
            return {"Error": [f"Could not find {filepath}. Please ensure it exists."]}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"Error": ["Failed to parse dorks.json. Check formatting."]}

    def generate_queries(self, target):
        results = {}
        for category, queries in self.dork_library.items():
            results[category] = [q.replace("{target}", target) for q in queries]
        return results

    def analyze_headers(self, target):
        results = {}
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(f"http://{target}", headers=headers, timeout=10, verify=False, allow_redirects=True)
            
            results["Server"] = response.headers.get("Server", "Hidden/Unknown")
            results["X-Powered-By"] = response.headers.get("X-Powered-By", "Not Disclosed")
            results["Strict-Transport-Security"] = "Present" if "Strict-Transport-Security" in response.headers else "MISSING"
            results["X-Frame-Options"] = response.headers.get("X-Frame-Options", "MISSING")
            
            return results
            
        except requests.exceptions.RequestException as e:
            return {"Error": f"Could not connect to target: {type(e).__name__}"}

    def enumerate_subdomains(self, target):
        subdomains = set()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shovel-OSINT/3.0'}
        session = requests.Session()

        try:
            crt_url = f"https://crt.sh/?q=%25.{target}&output=json"
            response = session.get(crt_url, headers=headers, timeout=25)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        clean_sub = sub.strip().lower()
                        if not clean_sub.startswith('*') and clean_sub.endswith(target) and clean_sub != target:
                            subdomains.add(clean_sub)
        except Exception:
            pass 

        if not subdomains:
            try:
                ht_url = f"https://api.hackertarget.com/hostsearch/?q={target}"
                response = session.get(ht_url, headers=headers, timeout=15)
                
                if response.status_code == 200 and "error" not in response.text.lower():
                    for line in response.text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if sub.endswith(target) and sub != target:
                                subdomains.add(sub)
            except Exception as e:
                return [f"Error: All enumeration sources failed. Last error: {str(e)}"]

        return sorted(list(subdomains))

    def probe_subdomain(self, subdomain):
        """Worker function to probe a single subdomain."""
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shovel-OSINT/3.0'}
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            # Use a strict 5-second timeout. If a server takes longer, it's not a viable target right now.
            response = requests.get(f"http://{subdomain}", headers=headers, timeout=5, verify=False, allow_redirects=True)
            return {
                "subdomain": subdomain,
                "status": response.status_code,
                "server": response.headers.get("Server", "Unknown"),
                "redirects_to": response.url if response.history else "None"
            }
        except requests.exceptions.RequestException:
            return {"subdomain": subdomain, "status": "DEAD", "server": "N/A", "redirects_to": "N/A"}

    def mass_fingerprint(self, subdomains, max_threads=15):
        """Spins up multiple threads to concurrently probe an array of subdomains."""
        # Filter out error messages if the enumeration failed
        valid_subs = [s for s in subdomains if not s.startswith("Error")]
        if not valid_subs: return []

        results = []
        # ThreadPoolExecutor is the professional standard for concurrent I/O operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_sub = {executor.submit(self.probe_subdomain, sub): sub for sub in valid_subs}
            for future in concurrent.futures.as_completed(future_to_sub):
                try:
                    results.append(future.result())
                except Exception as e:
                    pass

        # Sort the results: Live endpoints first, Dead endpoints last
        return sorted(results, key=lambda x: (x['status'] == "DEAD", x['subdomain']))

    def shodan_recon(self, ip, api_key):
        if not api_key:
            return {"Error": "No Shodan API key provided."}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return {
                    "Organization": data.get("org", "Unknown"),
                    "Operating System": data.get("os", "Unknown"),
                    "Open Ports": data.get("ports", []),
                    "Vulnerabilities": data.get("vulns", [])
                }
            elif response.status_code == 401:
                return {"Error": "Invalid Shodan API key."}
            elif response.status_code == 403:
                return {"Error": "Access Denied. Check Shodan account tier and query credits."}
            elif response.status_code == 404:
                return {"Error": "No data found for this IP on Shodan."}
            else:
                return {"Error": f"Shodan API returned status code: {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"Error": f"Shodan API request failed: {str(e)}"}