# LICENSE: THE SHOVEL
# This software is developed for educational and authorized offensive security reconnaissance.
# Commercial use or unauthorized copying of this code into other projects is strictly prohibited.

import argparse
import sys
import socket
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from engine import ShovelEngine
from database import DatabaseManager

console = Console()

def print_banner():
    banner = r"""
  ___________.__             _________.__                     .__   
  \__    ___/|  |__   ____  /   _____/|  |__   _______  __  ____|  |  
    |    |   |  |  \_/ __ \ \_____  \ |  |  \ /  _ \  \/ /_/ __ \  |  
    |    |   |   Y  \  ___/ /        \|   Y  (  <_> )   / \  ___/  |__
    |____|   |___|  /\___  >_______  /|___|  /\____/ \_/   \___  >____/
                  \/     \/        \/      \/                  \/     
                 OSINT Reconnaissance Engine
    """
    console.print(Panel(Text(banner, style="bold cyan", justify="center")))

def validate_target(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def export_results(target, data, format_type):
    filename = f"{target}_recon.{format_type}"
    try:
        if format_type == "json":
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        return filename
    except Exception as e:
        console.print(f"[!] Export failed: {e}", style="bold red")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="THE SHOVEL - Professional OSINT Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-t", "--target", help="The target domain to scan (e.g., example.com)", required=True)
    parser.add_argument("-o", "--output", help="Export results to a file (currently supports 'json')", choices=["json"], required=False)
    parser.add_argument("-s", "--shodan", help="Shodan API Key for passive infrastructure mapping", required=False)
    
    args = parser.parse_args()
    target = args.target

    print_banner()

    with console.status(f"[bold yellow]Validating domain resolution for {target}...", spinner="dots"):
        target_ip = validate_target(target)
        if not target_ip:
            console.print(f"[!] Target {target} failed DNS resolution. Aborting scan.", style="bold red")
            sys.exit(1)
            
    console.print(f"[+] Target Validated: {target} resolves to {target_ip}", style="bold green")

    with console.status(f"[bold green]Executing Mass Fingerprinting & High-Value Path Fuzzing...", spinner="bouncingBar"):
        db = DatabaseManager()
        engine = ShovelEngine()
        
        target_id = db.upsert_target(target)
        header_data = engine.analyze_headers(target)
        dork_data = engine.generate_queries(target)
        subdomains = engine.enumerate_subdomains(target)
        
        fingerprint_data = engine.mass_fingerprint(subdomains)
        fuzzer_data = engine.active_fuzzing(fingerprint_data)
        
        shodan_data = None
        if args.shodan:
            shodan_data = engine.shodan_recon(target_ip, args.shodan)

    console.print(f"[+] Target locked in local database (ID: {target_id})\n", style="bold green")

    # --- DISPLAY ACTIVE RECON (HEADERS) ---
    header_table = Table(title="[ACTIVE RECON] Server Infrastructure & Security Headers", title_style="bold yellow", border_style="yellow")
    header_table.add_column("Header Directive", style="cyan", justify="right")
    header_table.add_column("Value", style="white")
    for key, value in header_data.items():
        val_style = "bold red" if value == "MISSING" else "white"
        header_table.add_row(key, f"[{val_style}]{value}[/{val_style}]")
    console.print(header_table)
    console.print("")

    # --- DISPLAY PASSIVE RECON (DORKS) ---
    for category, queries in dork_data.items():
        clean_category = category.encode('ascii', 'ignore').decode('ascii').strip()
        dork_table = Table(title=f"[PASSIVE RECON] Category: {clean_category}", title_style="bold magenta", show_header=False, border_style="cyan")
        dork_table.add_column("Query", style="white")
        for q in queries:
            dork_table.add_row(q)
        console.print(dork_table)
        console.print("")

    # --- DISPLAY SUBDOMAIN FINGERPRINTING ---
    if not fingerprint_data:
        console.print("[!] No valid subdomains discovered to fingerprint.\n", style="bold yellow")
    else:
        live_subs = [s for s in fingerprint_data if s['status'] != "DEAD"]
        dead_subs = len(fingerprint_data) - len(live_subs)
        sub_table = Table(title=f"[ACTIVE RECON] Live Subdomain Fingerprints ({len(live_subs)} Alive, {dead_subs} Dead)", title_style="bold blue", border_style="blue")
        sub_table.add_column("Subdomain", style="cyan")
        sub_table.add_column("Status", style="green", justify="center")
        sub_table.add_column("Server Tech", style="yellow")
        sub_table.add_column("Redirect Target", style="magenta")
        for entry in live_subs[:20]:
            status_color = "green" if str(entry['status']).startswith('2') else "red"
            sub_table.add_row(entry['subdomain'], f"[{status_color}]{entry['status']}[/{status_color}]", entry['server'][:30], entry['redirects_to'][:40])
        console.print(sub_table)
        console.print("")

    # --- DISPLAY ACTIVE FUZZER RESULTS ---
    if fuzzer_data:
        fuzz_table = Table(title=f"[VULN HUNTER] High-Value Path Exposures ({len(fuzzer_data)} Hits)", title_style="bold red", border_style="red")
        fuzz_table.add_column("Exposed URL", style="white")
        fuzz_table.add_column("Status", style="cyan", justify="center")
        fuzz_table.add_column("Content Length", style="yellow", justify="right")
        
        for hit in fuzzer_data:
            # 200 OK is a critical finding. 403 Forbidden means it exists but we need bypass tactics.
            status_style = "bold red" if hit['status'] == 200 else "bold yellow"
            fuzz_table.add_row(hit['url'], f"[{status_style}]{hit['status']}[/{status_style}]", str(hit['content_length']))
            
        console.print(fuzz_table)
        console.print("")
    else:
        console.print("[+] Path Fuzzer found no exposed default files on live targets.\n", style="bold green")

    if args.output:
        master_export_payload = {
            "target": target,
            "ip_address": target_ip,
            "active_recon_headers": header_data,
            "passive_recon_dorks": dork_data,
            "fingerprinted_subdomains": fingerprint_data,
            "fuzzer_exposures": fuzzer_data
        }
        export_file = export_results(target, master_export_payload, args.output)
        if export_file:
            console.print(f"[+] Master results exported to {export_file}", style="bold cyan")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[!] Scan aborted by user.", style="bold red")
        sys.exit(1)