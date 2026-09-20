# 🦅 Aether Recon v14.6

Aether Recon is a comprehensive, self-hosted OSINT and reconnaissance platform. It combines deep surface scanning with a powerful identity tracking engine, all accessible via a sleek, modular web interface.

## 🚀 Features
* **Cloud Bucket Sniping:** Actively hunts for misconfigured S3, GCS, and Azure storage.
* **Wayback Archive Secret Hunting:** Extracts secrets from historical CDX snapshots.
* **API Key & JWT Extraction:** Deep analysis of frontend JavaScript and source maps for leaked credentials.
* **Identity Dossiers:** Unmasks usernames across 30+ platforms, extracting emails, crypto wallets, and phone numbers.
* **Honeypot Tracking Links:** Generates disguised links that capture detailed visitor telemetrics (WebRTC local IPs, VPN detection, etc.).
* **Temporal Diff Engine:** Automatically compares new scans against historical data to highlight attack surface changes.
* **Subdomain Takeover Detection:** Fingerprints CNAME records for vulnerable cloud services.

## 🛠️ Installation

### Requirements
* PHP 8.0+ (with `curl` and `pdo_mysql` extensions)
* MySQL or MariaDB

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/aether-recon.git
cd aether-recon
```

### 2. Configure the Environment
Copy the example environment file and fill in your database credentials and API keys.
```bash
cp .env.example .env
```
*Note: Do not commit your `.env` file!*

### 3. Database Setup
Create the database and user as defined in your `.env` file. (The application will automatically create the necessary tables on first load).
```sql
CREATE DATABASE obeywevy_osint;
CREATE USER 'obeywevy_osint'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON obeywevy_osint.* TO 'obeywevy_osint'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Run the Application
Point your web server (Nginx/Apache) to the `public/` directory, or use the PHP built-in server for local testing:
```bash
php -S localhost:8080 -t public/
```
Navigate to `http://localhost:8080` and use the Registration Code defined in your `.env` to create your admin account.

## 🔒 Security Notice
This tool is built for authorized security auditing and counterintelligence. Do not use Aether Recon against targets you do not have explicit permission to test.
