<div align="center">

# THE SHOVEL
**OSINT Reconnaissance Engine**

```text
  ___________.__             _________.__                     .__   
  \__    ___/|  |__   ____  /   _____/|  |__   _______  __  ____|  |  
    |    |   |  |  \_/ __ \ \_____  \ |  |  \ /  _ \  \/ /_/ __ \  |  
    |    |   |   Y  \  ___/ /        \|   Y  (  <_> )   / \  ___/  |__
    |____|   |___|  /\___  >_______  /|___|  /\____/ \_/   \___  >____/
                  \/     \/        \/      \/                  \/

A multi-layered reconnaissance framework designed for automated attack surface mapping, concurrent technology stack fingerprinting, and high-value vulnerability fuzzing. Built for speed, accuracy, and operational security.

Core Architecture & Capabilities

THE SHOVEL transitions from passive intelligence gathering to active, concurrent perimeter analysis within a single execution pipeline.

Active Perimeter Analysis: Bypasses basic WAF drops with multi-protocol probing (HTTPS to HTTP fallback) to extract server infrastructure and missing security headers.

Passive Subdomain Enumeration: Queries Certificate Transparency logs (crt.sh) with intelligent, silent failover to HackerTarget API routing for resilient data extraction.

Concurrent Mass Fingerprinting: Utilizes concurrent.futures to validate live endpoints across massive subdomain datasets in seconds, automatically filtering dead nodes and logging redirect chains.

Calibrated Path Fuzzing: Implements strict, protocol-specific Soft-404 baseline filtering. Evaluates custom error page byte-lengths to eradicate false positives before hunting for exposed /.env, /.git/config, phpinfo.php, and server-status files.

Persistent Target Tracking: Local SQLite database integration automatically tracks domain scans and target history (configured to bypass Git tracking for OpSec).

Structured Intelligence Export: Generates hierarchical JSON payloads for seamless ingestion into broader vulnerability management pipelines.

*Installation*

# Clone the repository
git clone [https://github.com/Atsukiiii01/The-Shovel.git](https://github.com/Atsukiiii01/The-Shovel.git)

# Navigate to directory
cd The-Shovel

# Install requirements (requests, rich, urllib3)
pip install -r requirements.txt

*Usage*
Execute THE SHOVEL via the command line interface.

Standard Execution & JSON Export:
python3 main.py -t example.com -o json

Workflow Sequence:

Validates target DNS resolution.

Extracts core HTTP/HTTPS headers.

Enumerates passive subdomains and Google Dorks.

Mass-fingerprints live endpoints concurrently.

Establishes Soft-404 baselines and fuzzes live endpoints for critical exposures.

Exports structured intelligence to <target>_recon.json.

License & Disclaimer
THE SHOVEL is developed strictly for educational purposes and authorized offensive security reconnaissance.
Commercial use, resale, or unauthorized copying of this architecture into other projects is strictly prohibited. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Only scan targets you have explicit permission to test.