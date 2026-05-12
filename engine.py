# LICENSE: THE SHOVEL
# This software is developed for educational and authorized offensive security reconnaissance.
# Commercial use or unauthorized copying of this code into other projects is strictly prohibited.

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
        
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        protocols = [f"https://{target}", f"http://{target}"]
        
        for url in protocols:
            try:
                response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
                results["Server"] = response.headers.get("Server", "Hidden/Unknown")
                results["X-Powered-By"] = response.headers.get("X-Powered-By", "Not Disclosed")
                results["Strict-Transport-Security"] = "Present" if "Strict-Transport-Security" in response.headers else "MISSING"
                results["X-Frame-Options"] = response.headers.get("X-Frame-Options", "MISSING")
                return results
            except requests.exceptions.RequestException:
                continue 
                
        return {"Error": "Target firewall blocked both HTTP and HTTPS probes."}

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
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shovel-OSINT/3.0'}
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
        valid_subs = [s for s in subdomains if not s.startswith("Error")]
        if not valid_subs: return []
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_sub = {executor.submit(self.probe_subdomain, sub): sub for sub in valid_subs}
            for future in concurrent.futures.as_completed(future_to_sub):
                try:
                    results.append(future.result())
                except Exception:
                    pass
        return sorted(results, key=lambda x: (x['status'] == "DEAD", x['subdomain']))

    def _fuzz_worker(self, url, baseline_length=None):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shovel-OSINT/3.1'}
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            content_len = len(response.content)
            
            if baseline_length and abs(content_len - baseline_length) < 5: 
                return None

            if response.status_code in [200, 403]:
                return {
                    "url": url,
                    "status": response.status_code,
                    "content_length": content_len
                }
        except requests.exceptions.RequestException:
            pass
        return None

    def active_fuzzing(self, fingerprint_data, max_threads=20):
        payloads = ['/.env', '/.git/config', '/robots.txt', '/phpinfo.php', '/server-status', '/.DS_Store']
        live_subs = [s['subdomain'] for s in fingerprint_data if s['status'] != "DEAD"]
        
        baselines = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_url = {}
            for sub in live_subs:
                http_url = f"http://{sub}/this_is_a_fake_file_shovel_test"
                https_url = f"https://{sub}/this_is_a_fake_file_shovel_test"
                future_to_url[executor.submit(requests.get, http_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False, allow_redirects=False)] = http_url
                future_to_url[executor.submit(requests.get, https_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False, allow_redirects=False)] = https_url
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    resp = future.result()
                    if resp.status_code == 200:
                        baselines[url] = len(resp.content)
                    else:
                        baselines[url] = None
                except Exception:
                    baselines[url] = None

        urls_to_test = []
        for sub in live_subs:
            base_http = baselines.get(f"http://{sub}/this_is_a_fake_file_shovel_test")
            base_https = baselines.get(f"https://{sub}/this_is_a_fake_file_shovel_test")
            for payload in payloads:
                urls_to_test.append((f"http://{sub}{payload}", base_http))
                urls_to_test.append((f"https://{sub}{payload}", base_https))

        results = []
        if not urls_to_test: return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_url = {executor.submit(self._fuzz_worker, url, baseline): url for url, baseline in urls_to_test}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    results.append(res)
                    
        return sorted(results, key=lambda x: (x['status'], x['url']))

    def identity_osint(self, target, api_key):
        """Queries Hunter.io for employee emails and organizational data."""
        if not api_key:
            return {"Error": "No Hunter.io API key provided. Skipping Identity OSINT."}
            
        url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={api_key}"
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json().get("data", {})
                emails = data.get("emails", [])
                
                results = []
                for entry in emails:
                    results.append({
                        "email": entry.get("value", "Unknown"),
                        "first_name": entry.get("first_name", "Unknown"),
                        "last_name": entry.get("last_name", "Unknown"),
                        "position": entry.get("position", "Unknown"),
                        "department": entry.get("department", "Unknown")
                    })
                return {"pattern": data.get("pattern", "Unknown"), "contacts": results}
                
            elif response.status_code == 401:
                return {"Error": "Invalid Hunter.io API key."}
            elif response.status_code == 429:
                return {"Error": "Hunter.io rate limit exceeded or free queries depleted."}
            else:
                return {"Error": f"Hunter.io API returned status code: {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"Error": f"Hunter.io API request failed: {str(e)}"}