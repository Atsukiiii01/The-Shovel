import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import urllib.parse
import datetime

# --- App Config ---
APP_TITLE = "Shutter OSINT - Recon Dashboard"
APP_SIZE = "1150x800" 
THEME_DARK = "#1e1e1e"
THEME_ACCENT = "#007acc"

class DorkTool:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_SIZE)
        
        # Initialize the visual styles
        self._init_styles()
        self.root.configure(bg=THEME_DARK)

        # Tab Layout
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Tab 1: Discovery
        self.tab_discovery = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_discovery, text="   🔎 Discovery Mode   ")
        self._build_discovery_ui()

        # Tab 2: Analysis
        self.tab_analysis = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_analysis, text="   🧠 Deep Analysis   ")
        self._build_analysis_ui()

        # Status Footer
        self.status_var = tk.StringVar(value="System ready. Waiting for target...")
        self._build_statusbar()

    def _init_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark Theme Colors & Font Config
        style.configure("TFrame", background=THEME_DARK)
        style.configure("TLabel", background=THEME_DARK, foreground="#e0e0e0", font=("Segoe UI", 11))
        style.configure("TButton", background=THEME_ACCENT, foreground="white", borderwidth=0, font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[('active', '#005f9e')])
        style.configure("TEntry", fieldbackground="#252526", foreground="white", padding=8)
        
        # Tabs
        style.configure("TNotebook", background=THEME_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background="#2d2d30", foreground="#d4d4d4", padding=[20, 8], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[('selected', THEME_ACCENT)])

    # =========================================================
    # TAB 1: DISCOVERY LOGIC
    # =========================================================
    def _build_discovery_ui(self):
        # Header Section
        header = ttk.Frame(self.tab_discovery, padding="25 25 25 10")
        header.pack(fill=tk.X)

        ttk.Label(header, text="TARGET DOMAIN / KEYWORD:", font=("Segoe UI", 9, "bold"), foreground="#888").pack(anchor=tk.W)

        input_box = ttk.Frame(header)
        input_box.pack(fill=tk.X, pady=(8, 0))

        # Larger input font
        self.target_var = tk.StringVar(value="example.com")
        entry = ttk.Entry(input_box, textvariable=self.target_var, font=("Consolas", 14))
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 15))

        ttk.Button(input_box, text="GENERATE QUERIES", command=self.run_generation, width=22).pack(side=tk.LEFT)

        # Results List Section
        results_area = ttk.Frame(self.tab_discovery, padding="25 0 25 25")
        results_area.pack(fill=tk.BOTH, expand=True)

        scroller = ttk.Scrollbar(results_area)
        scroller.pack(side=tk.RIGHT, fill=tk.Y)

        # Listbox 
        self.dork_list = tk.Listbox(
            results_area, 
            yscrollcommand=scroller.set, 
            bg="#252526", 
            fg="#d4d4d4",
            selectbackground=THEME_ACCENT, 
            selectforeground="white", 
            font=("Consolas", 12),  
            borderwidth=0, 
            highlightthickness=0
        )
        self.dork_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroller.config(command=self.dork_list.yview)
        
        self.dork_list.bind('<Double-1>', self.on_dork_click)

    def get_query_data(self, target):
        return {
            "🌐 Infrastructure & Recon": [
                f"site:{target} intitle:\"index of\"",
                f"link:{target} -site:{target}",
                f"related:{target}",
                f"site:{target} inurl:api OR inurl:v1 OR inurl:v2",
                f"cache:{target}"
            ],
            "📂 Public Files & Leaks": [
                f"site:{target} ext:pdf OR ext:xlsx OR ext:docx",
                f"site:{target} ext:sql OR ext:dbf OR ext:env",
                f"site:{target} ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf",
                f"site:{target} \"confidential\" OR \"top secret\""
            ],
            "🔐 Admin Portals & Login": [
                f"site:{target} inurl:login OR inurl:admin",
                f"site:{target} inurl:cpanel OR inurl:whm",
                f"site:{target} inurl:wp-admin",
                f"site:{target} intitle:\"login\" -inurl:https"
            ],
            "🔢 Numeric Data & IDs": [
                f"site:{target} \"invoice\" 1000...99999",
                f"site:{target} \"phone\" OR \"contact\"",
                f"patent {target}",
                f"fcc {target}"
            ],
            "📰 Social & Groups": [
                f"site:groups.google.com \"{target}\"",
                f"insubject:\"{target}\"",
                f"author:\"@{target}\""
            ]
        }

    def run_generation(self):
        target = self.target_var.get().strip()
        if not target: 
            return

        self.dork_list.delete(0, tk.END)
        data_map = self.get_query_data(target)
        
        for category, items in data_map.items():
            self.dork_list.insert(tk.END, f"--- {category} ---")
            self.dork_list.itemconfig(tk.END, {'fg': '#569cd6'})
            
            for item in items:
                self.dork_list.insert(tk.END, item)
            
            self.dork_list.insert(tk.END, "")

        self.status_var.set(f"Generated search vectors for: {target}")

    def on_dork_click(self, event):
        selection = self.dork_list.curselection()
        if not selection: return
        
        query_text = self.dork_list.get(selection[0])
        if query_text.startswith("---") or not query_text.strip(): return
        
        url = f"https://www.google.com/search?q={urllib.parse.quote(query_text)}"
        webbrowser.open(url)

    # =========================================================
    # TAB 2: ANALYSIS LOGIC
    # =========================================================
    def _build_analysis_ui(self):
        pad = ttk.Frame(self.tab_analysis, padding="25")
        pad.pack(fill=tk.BOTH, expand=True)
        
        lbl = ttk.Label(pad, text="ANALYZE ARTIFACT (Email, Username, URL, IP):", font=("Segoe UI", 10, "bold"), foreground="#888")
        lbl.pack(anchor=tk.W)
        
        # Larger input font
        self.pivot_entry = ttk.Entry(pad, font=("Consolas", 14))
        self.pivot_entry.pack(fill=tk.X, pady=(8, 20))
        
        # Tools Grid
        grid_frame = ttk.Frame(pad)
        grid_frame.pack(fill=tk.BOTH, expand=True)
        
        # Col 1
        c1 = ttk.LabelFrame(grid_frame, text=" 📧 Email & ID ", padding="15")
        c1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self._add_btn(c1, "Google Account Check", "epieos")
        self._add_btn(c1, "Breach Data (HIBP)", "hibp")
        self._add_btn(c1, "Reputation Check", "emailrep")

        # Col 2
        c2 = ttk.LabelFrame(grid_frame, text=" 👤 Username ", padding="15")
        c2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8)
        self._add_btn(c2, "Cross-Site Check (NameChk)", "namechk")
        self._add_btn(c2, "Github User", "github")
        self._add_btn(c2, "Twitter Advanced", "twitter")

        # Col 3
        c3 = ttk.LabelFrame(grid_frame, text=" 💾 Technical ", padding="15")
        c3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))
        self._add_btn(c3, "Exif Metadata", "metadata")
        self._add_btn(c3, "VirusTotal Scan", "virustotal")
        self._add_btn(c3, "Wayback Machine", "wayback")

        # Validation Tools
        helper_frame = ttk.LabelFrame(pad, text=" 🛠️ Validation Tools ", padding="20")
        helper_frame.pack(fill=tk.X, pady=25)
        
        ttk.Button(helper_frame, text="Strict Search (Quotes)", command=self.do_strict_search).pack(side=tk.LEFT, pady=5)
        ttk.Button(helper_frame, text="Whois Lookup", command=lambda: self.run_tool("whois")).pack(side=tk.LEFT, padx=15, pady=5)

    def _add_btn(self, parent, text, code):
        ttk.Button(parent, text=text, command=lambda: self.run_tool(code)).pack(fill=tk.X, pady=4)

    def run_tool(self, tool_code):
        data = self.pivot_entry.get().strip()
        if not data:
            self.status_var.set("⚠️ Input required for analysis.")
            return

        urls = {
            "epieos": f"https://epieos.com/?q={data}",
            "hibp": f"https://haveibeenpwned.com/account/{data}",
            "emailrep": f"https://emailrep.io/query/{data}",
            "namechk": f"https://namechk.com/username/{data}",
            "github": f"https://github.com/{data}",
            "twitter": f"https://twitter.com/search?q={data}&f=user",
            "virustotal": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(data)}",
            "wayback": f"https://web.archive.org/web/*/{data}",
            "whois": f"https://who.is/whois/{data}"
        }

        if tool_code == "metadata":
            if "http" in data:
                webbrowser.open(f"http://exif.regex.info/exif.cgi?imgurl={data}")
            else:
                messagebox.showinfo("URL Needed", "Please paste a direct image/PDF URL for metadata analysis.")
            return

        if tool_code in urls:
            webbrowser.open(urls[tool_code])
            self.status_var.set(f"Opening {tool_code}...")

    def do_strict_search(self):
        data = self.pivot_entry.get().strip()
        if not data: return
        webbrowser.open(f"https://www.google.com/search?q={urllib.parse.quote(f'"{data}"')}")

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding="5")
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(bar, textvariable=self.status_var, bg=THEME_DARK, fg="#999", font=("Segoe UI", 10), anchor=tk.W).pack(fill=tk.X)

if __name__ == "__main__":
    root = tk.Tk()
    app = DorkTool(root)
    root.mainloop()