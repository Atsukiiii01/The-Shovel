# Shovel OSINT - User Guide

This guide outlines the standard workflow for using Shutter OSINT to conduct passive reconnaissance.

## 🟢 Phase 1: Discovery (Finding the Data)

The **Discovery Mode** tab is your starting point. It uses "Google Dorks" (advanced search operators) to find exposed assets indexed by search engines.

1.  **Enter Target:**
    * In the "TARGET DOMAIN" box, type the website you are auditing (e.g., `tesla.com` or `nasa.gov`).
    * *Tip:* You can also use a specific keyword or company name.

2.  **Generate Queries:**
    * Click **GENERATE QUERIES**. The tool will populate the list with categorized search vectors.

3.  **Execute Search:**
    * **Double-click** any item in the list to open it immediately in your default browser.
    * *Workflow Tip:* Start with the **Infrastructure** category to map the network, then move to **Public Files** to look for information leaks.

---

## 🔵 Phase 2: Analysis (Pivoting)

Once you find an interesting piece of data (an artifact) in Phase 1, switch to the **Deep Analysis** tab. This is where you turn raw data into intelligence.

### Scenario A: You found an email address
* **Input:** Paste the email into the "ANALYZE ARTIFACT" box.
* **Action:** * Click **Google Account Check** to see if the email is linked to a Google Maps profile (often reveals physical location/real name).
    * Click **Breach Data** to see if the email has been involved in past password leaks.

### Scenario B: You found a suspicious username (e.g., `dev_admin_01`)
* **Input:** Paste the username.
* **Action:** * Click **Cross-Site Check** to see if this user uses the same handle on GitHub, Twitter, or Reddit.
    * *Why?* Developers often reuse usernames on personal accounts that may contain more info.

### Scenario C: You found a PDF or Image link
* **Input:** Paste the direct URL (link) to the file.
* **Action:** * Click **Exif Metadata**.
    * *Result:* This opens an external viewer that reads the hidden data inside the file (e.g., "Created by: John Doe", "Software: Adobe Photoshop CS6").

---

## 🛠️ Validation Tools

Use the **Validation Tools** section at the bottom of the Analysis tab to filter out noise.

* **Strict Search:**
    * Use this if you are getting too many unrelated results. It wraps your search in quotes (`"query"`) to force Google to find that *exact* phrase only.
* **Whois Lookup:**
    * Use this to check if a domain is actually owned by your target or if it is an imposter/phishing site.