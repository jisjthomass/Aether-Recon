# ◈ Aether Recon v14.5 [Fully Web Based Tool] [PHP]

**Aether Recon** is an advanced, web-based Open-Source Intelligence (OSINT) and network reconnaissance framework built entirely in PHP and JavaScript. Designed for bug bounty hunters, penetration testers, and OSINT investigators, it maps digital footprints, extracts leaked secrets, and visualizes attack surfaces in real-time.

What makes Aether Recon unique is its **resource-efficient architecture**. It utilizes client-driven AJAX pagination, micro-chunking, and intelligent egress fallback mechanisms to bypass strict execution timeouts and outbound port blocks found on free-tier shared hosting environments (like x10hosting).

## 🔥 Core Features

### 🕵️‍♂️ Attack Surface & Vulnerability Mapping
*   **Subdomain Takeover Detection:** Validates dangling CNAME records against 15+ known vulnerable service fingerprints (GitHub Pages, Heroku, S3, Vercel, etc.).
*   **Advanced API Key & Secret Hunting:** Extracts and filters high-confidence credentials (AWS, Stripe, GitHub, Slack) from HTML, JavaScript, source maps, `.env` files, and Wayback Machine archives.
*   **JWT Discovery & Misconfiguration:** Probes endpoints for leaked JSON Web Tokens, decodes claims, and tests for critical `alg:none` bypass vulnerabilities.
*   **Sensitive Endpoint Discovery:** A stealthy, chunked path-brute engine to locate exposed admin panels, `.git` configurations, and database dumps.
*   **Cloud Bucket Sniping:** Permutation-based brute-forcing to discover publicly accessible or misconfigured AWS S3, Google Cloud Storage, and Azure blobs.
*   **CORS & TLS Auditing:** Automated Origin reflection checks, wildcard ACAO flagging, and deep SSL/TLS certificate chain evaluation.

### 🌐 Deep OSINT & Identity Tracking
*   **User OSINT Dossiers:** Scrapes 30+ social platforms to build identity profiles, extracting linked emails, crypto wallets, and cross-platform links.
*   **Origin IP Unmasking:** Correlates historical DNS (SecurityTrails, HackerTarget) and Censys TLS fingerprints to bypass WAFs/CDNs and locate origin servers.
*   **Document Metadata Extraction:** Parses remote PDF and Office documents for leaked internal author names, software versions, and internal file paths.
*   **Active Tracking (Honeypot):** Generates traceable link endpoints and "Canary" Word documents (`.docx`) to capture WebRTC internal mDNS/IP leaks, VPN usage, and browser fingerprints.

### ⚙️ Engine & Architecture
*   **Interactive Link Analysis:** Visualizes target infrastructure, subdomains, open ports, and identity footprints using dynamic `vis-network` physics graphs.
*   **Stealth Mode:** Implements randomized modern User-Agents, delayed micro-batching, timing jitter, and optional SOCKS5 proxy routing to evade WAFs.
*   **Temporal Diff Engine:** Compares current scans against historical team-vault data to instantly flag newly opened ports, new subdomains, or newly leaked secrets.
*   **Investigation Packs:** Exports clean, executive-level JSON, PDF, and `.txt` wordlists of all discovered intelligence.

## ⚠️ Disclaimer
Aether Recon is developed for educational and authorized security research purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning targets.
