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

    with console.status(f"[bold green]Executing Active & Passive Reconnaissance...", spinner="bouncingBar"):
        db = DatabaseManager()
        engine = ShovelEngine()
        
        target_id = db.upsert_target(target)
        header_data = engine.analyze_headers(target)
        dork_data = engine.generate_queries(target)
        subdomains = engine.enumerate_subdomains(target)
        
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

    # --- DISPLAY SHODAN INFRASTRUCTURE MAP ---
    if shodan_data:
        if "Error" in shodan_data:
            console.print(f"[bold red][!] Shodan Recon Failed: {shodan_data['Error']}[/bold red]\n")
        else:
            shodan_table = Table(title=f"[PASSIVE RECON] Shodan Infrastructure Map ({target_ip})", title_style="bold green", border_style="green")
            shodan_table.add_column("Metric", style="cyan", justify="right")
            shodan_table.add_column("Data", style="white")
            
            shodan_table.add_row("Organization", str(shodan_data.get("Organization")))
            shodan_table.add_row("Operating System", str(shodan_data.get("Operating System")))
            
            ports = shodan_data.get("Open Ports", [])
            shodan_table.add_row("Open Ports", ", ".join(map(str, ports)) if ports else "None detected")
            
            vulns = shodan_data.get("Vulnerabilities", [])
            shodan_table.add_row("CVE Vulnerabilities", ", ".join(vulns) if vulns else "None publicly known")
            
            console.print(shodan_table)
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

    # --- DISPLAY PASSIVE RECON (SUBDOMAINS) ---
    if not subdomains:
        console.print("[!] No subdomains discovered or API returned empty results.\n", style="bold yellow")
    elif subdomains[0].startswith("Error"):
        console.print(f"[bold red][!] {subdomains[0]}[/bold red]\n")
    else:
        display_limit = 15
        total_subs = len(subdomains)
        sub_table = Table(title=f"[PASSIVE RECON] Discovered Subdomains ({total_subs} Total)", title_style="bold blue", border_style="blue")
        sub_table.add_column("Subdomain", style="cyan")
        for sub in subdomains[:display_limit]:
            sub_table.add_row(sub)
        console.print(sub_table)
        if total_subs > display_limit:
            console.print(f"[italic cyan]...and {total_subs - display_limit} more. Check JSON export for full list.[/italic cyan]")
        console.print("")

    if args.output:
        master_export_payload = {
            "target": target,
            "ip_address": target_ip,
            "shodan_recon": shodan_data,
            "active_recon_headers": header_data,
            "passive_recon_dorks": dork_data,
            "discovered_subdomains": subdomains
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