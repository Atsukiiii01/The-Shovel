<div align="center">

# THE SHOVEL
**Advanced OSINT & Attack Surface Mapping**

```text
  ___________.__             _________.__                     .__   
  \__    ___/|  |__   ____  /   _____/|  |__   _______  __  ____|  |  
    |    |   |  |  \_/ __ \ \_____  \ |  |  \ /  _ \  \/ /_/ __ \  |  
    |    |   |   Y  \  ___/ /        \|   Y  (  <_> )   / \  ___/  |__
    |____|   |___|  /\___  >_______  /|___|  /\____/ \_/   \___  >____/
                  \/     \/        \/      \/                  \/     
```
</div>

A high-speed, concurrent OSINT framework designed for automated perimeter analysis, credential leakage discovery, and professional reporting.

##  Features v1.1.0
* **Identity OSINT:** Automated extraction of personnel data via Hunter.io integration.
* **Concurrent Fuzzing:** Multi-threaded path discovery with protocol-specific baseline filtering.
* **Auto-Reporting:** Seamless generation of executive Markdown reports from raw intelligence.
* **Modern Packaging:** Full PEP 621 compliance for easy installation.

##  Installation
```bash
git clone https://github.com/Atsukiiii01/The-Shovel.git
cd The-Shovel
pip install -e .
```

##  Usage
```bash
# Execute full recon with automated reporting
shovel -t target.com -H YOUR_HUNTER_API_KEY -o all
```

##  License
Developed for authorized offensive security reconnaissance only. Commercial use or unauthorized copying of this architecture is strictly prohibited.
