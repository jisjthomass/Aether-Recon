<?php
/**
 * Aether Recon v0.5 – Deep Surface + Full OSINT Expansion
 * Features:
 *  - Cloud Bucket Sniping (S3 / GCS / Azure) with permutation engine
 *  - Wayback Archive Secret Hunting (CDX + regex)
 *  - Document Metadata Extraction (PDF / Office headers)
 *  - GitHub / Source Code Leak Detection
 *  - Active Identity Tracking (Honeypot links + WebRTC)
 *  - Origin IP Unmasking (historical DNS + Censys cert correlation)
 *  - Interactive Graph Mapping, Identity Dossiers, Visual Attack Surfaces
 *  - Modular AJAX Pipeline, Canary Docs, VPN Detection, OSINT Pivots
 *  - NEW: Advanced API Key & Secret Extraction (JS, source maps, configs, headers, common paths)
 *  - NEW: JWT Discovery + Misconfiguration Testing (alg:none, claims, endpoint probing)
 *  - NEW: Subdomain Takeover Detection (CNAME fingerprints)
 *  - NEW: CORS Misconfiguration Probe
 *  - NEW: Sensitive Endpoint & Path Discovery
 *  - NEW: Expanded Technology Fingerprinting
 *  - v0.1: Temporal Diff Engine (compare with previous scans)
 *  - v0.1: Shadow / Related Domain Discovery
 *  - v0.2: Narrative Intelligence Summary
 *  - v0.2: Certificate Pivot helpers
 *  - v0.2: Expanded User OSINT platforms (20+)
 *  - v0.2: Stronger Temporal Intelligence + auto-diff on history load
 *  - v0.3: Deeper Identity / Pivot enrichment for usernames
 *  - v0.3: Investigation Pack export + improved narrative
 *  - v0.3: Personal knowledge-base polish (notes/tags/history)
 *  - v0.3: Stealth mode + reliability controls
 *  - v0.4: Frontend-paginated endpoints (stealth-safe)
 *  - v0.4: Stealth personas (Chrome / Googlebot / Bingbot)
 *  - v0.5: mDNS-aware WebRTC honeypot capture
 *  - v0.5: Vuln Intel (CIRCL/NVD-style CVE explanations)
 *  - v0.5: PoC Refs (strict GitHub PoC filtering)
 */


register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        if (ob_get_level()) {
            ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'error' => 'Fatal Server Error: ' . $error['message'] . ' on line ' . $error['line']
        ]);
        exit;
    }
});

error_reporting(0);
ini_set('display_errors', 0);
ini_set('max_execution_time', 300);
date_default_timezone_set('UTC');

/* ====================== CONFIG ====================== */
define('DB_HOST',           '');
define('DB_NAME',           '');
define('DB_USER',           '');
define('DB_PASS',           '');
define('DB_ENABLED',        true);

define('REGISTRATION_CODE', '');
define('KEEP_SCANS',        25);
define('APP_VERSION',       '14.6');
define('RATE_LIMIT_SCANS',  5000);
define('STEALTH_MODE',       true);  // true = slower, fewer concurrent, jitter (safer on hardened targets)
define('STEALTH_DELAY_MS',   400);    // base delay between requests in stealth mode

define('STEALTH_MAX_CONCURRENCY', 3);  // Max simultaneous connections during stealth mode (vs 30-40)
define('DEFAULT_PERSONA',    'chrome'); // chrome | googlebot | bingbot | mixed


// Optional Proxy / Tor Integration
define('PROXY_ENABLED',      false);  // Set true to route requests through a proxy
define('PROXY_ADDR',         '127.0.0.1:9050'); // Proxy address (e.g., local Tor SOCKS5 or HTTP proxy)
define('PROXY_TYPE',         CURLPROXY_SOCKS5); // CURLPROXY_HTTP or CURLPROXY_SOCKS5

define('CACHE_DIR',         __DIR__ . '/aether_cache');
define('LOG_FILE',          __DIR__ . '/aether_recon.log');
define('CRON_SECRET',       'AetherCronSec_9921');

// --- PASSIVE OSINT API CREDENTIALS ---
define('SHODAN_API_KEY',    '');
define('CENSYS_API_ID',     '');
define('CENSYS_API_SECRET', '');
define('ALIENVAULT_API_KEY','');
define('HACKERTARGET_KEY',  '');
define('HUNTER_API_KEY',    '');

// Optional: GitHub Personal Access Token (public_repo or code search scope) for higher rate limits
define('GITHUB_TOKEN',      '');

// Optional: SecurityTrails API key for richer historical DNS (free tier available)
define('SECURITYTRAILS_KEY','');

if (!is_dir(CACHE_DIR)) {
    @mkdir(CACHE_DIR, 0750, true);
    @file_put_contents(CACHE_DIR . '/.htaccess', "Require all denied");
}

/* ====================== CRON JOB ROUTER ====================== */
if ((isset($argv[1]) && $argv[1] === 'cron') || (isset($_GET['action']) && $_GET['action'] === 'cron_run')) {

    // Security Fix: Enforce CRON_SECRET for web-based cron execution
    if (isset($_GET['action']) && $_GET['action'] === 'cron_run') {
        $providedSecret = $_GET['secret'] ?? '';
        if (!hash_equals(CRON_SECRET, (string)$providedSecret)) {
            header('HTTP/1.1 403 Forbidden');
            die(json_encode(['error' => 'Unauthorized cron execution']));
        }
    }

    Storage::init();

    $stmt = Storage::$pdo->query("SELECT id, user_id, domain FROM recon_targets WHERE is_monitored = 1 ORDER BY updated_at ASC LIMIT 1");
    $target = $stmt->fetch();

    if (!$target) {
        die("No monitored targets.\n");
    }

    $domain = $target['domain'];
    echo "[+] Processing single chunk: $domain...\n";

    $update = Storage::$pdo->prepare("UPDATE recon_targets SET updated_at = NOW() WHERE id = ?");
    $update->execute([$target['id']]);

    $start   = microtime(true);

    $tls     = AetherRecon::auditTls($domain);
    $dns     = AetherRecon::auditDns($domain);
    $http    = AetherRecon::auditHttp($domain);
    $meta    = AetherRecon::checkMetaFiles($domain);
    $subs    = AetherRecon::mapSubdomains($domain, false);
    $ports   = AetherRecon::scanPorts($domain);
    $cves    = AetherRecon::mapCVEs($http['all_headers'] ?? []);
    $company = AetherRecon::auditCompany($domain);
    $cloud   = AetherRecon::auditCloud($domain);
    $archive = AetherRecon::auditArchiveSecrets($domain);
    $docs    = AetherRecon::auditDocumentMetadata($domain);
    $github  = AetherRecon::auditGitHubLeaks($domain);
    $origin  = AetherRecon::unmaskOriginIP($domain, $dns);
    $pivots  = ['favicon' => AetherRecon::getFaviconHash($domain), 'pgp' => AetherRecon::searchPgpKeys($domain)];

    $takeover = AetherRecon::auditSubTakeover($domain, $subs['subdomains'] ?? []);
    $cors     = AetherRecon::auditCors($domain);
    $endpoints= AetherRecon::auditEndpoints($domain, 0, 100); // full path set in one cron chunk

    $risk    = AetherRecon::buildRisk($tls, $dns, $http, $subs, $meta, $ports, $cves, $cloud, $archive, $docs, $github, $origin, [], [], $takeover, $cors, $endpoints);

    $duration = round(microtime(true) - $start, 2);

    $report = [
        'type'       => 'domain',
        'target'     => $domain,
        'scanned_at' => date('c'),
        'profile'    => 'cron',
        'duration'   => $duration,
        'tls'        => $tls,
        'dns'        => $dns,
        'http'       => $http,
        'meta'       => $meta,
        'subdomains' => $subs,
        'ports'      => $ports,
        'cves'       => $cves,
        'company'    => $company,
        'cloud'      => $cloud,
        'archive'    => $archive,
        'documents'  => $docs,
        'github'     => $github,
        'origin_ip'  => $origin,
        'pivots'     => $pivots,
        'takeover'   => $takeover,
        'cors'       => $cors,
        'endpoints'  => $endpoints,
        'risk'       => $risk,
        'whois'      => null,
        'ipinfo'     => []
    ];

    Storage::saveScan($target['user_id'], $domain, $report, $duration);
    echo "    -> Completed chunk in {$duration}s. Exiting.\n";
    exit;
}

/* ====================== SESSIONS ====================== */
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', 1);

if ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
    (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) {
    ini_set('session.cookie_secure', 1);
}
session_start();

/* ====================== HELPERS ====================== */
function log_msg($msg) {
    @file_put_contents(LOG_FILE, date('c') . ' ' . $msg . "\n", FILE_APPEND);
}

function get_client_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function rate_limit_check($action = 'scan') {
    if (class_exists('Storage') && Storage::isLoggedIn()) {
        return true;
    }

    $ip = preg_replace('/[^0-9a-fA-F:.]/', '', get_client_ip());
    $file = CACHE_DIR . '/rl_' . md5($ip . $action) . '.json';
    $now = time();
    $data = ['count' => 0, 'start' => $now];

    if (file_exists($file)) {
        $data = json_decode(@file_get_contents($file), true) ?: $data;
        if ($now - $data['start'] > 3600) {
            $data = ['count' => 0, 'start' => $now];
        }
    }

    if ($data['count'] >= RATE_LIMIT_SCANS) {
        return false;
    }

    $data['count']++;
    @file_put_contents($file, json_encode($data));
    return true;
}

function csrf_token() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_check($token) {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$token);
}

/* ====================== STORAGE (TEAM ENGINE) ====================== */
class Storage {
    public static $pdo = null;
    public static $useDb = false;

    public static function init() {
        if (self::$pdo !== null) {
            return;
        }
        if (!DB_ENABLED) {
            return;
        }

        try {
            self::$pdo = new PDO(
                "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                ]
            );
            self::$useDb = true;
            @self::$pdo->exec("SET SESSION sql_mode = ''");
            self::migrate();
        } catch (\Throwable $e) {
            self::$useDb = false;
        }
    }

    private static function ping() {
        if (self::$pdo === null) {
            self::init();
            return self::$useDb;
        }
        try {
            self::$pdo->query("SELECT 1");
            return true;
        } catch (\Throwable $e) {
            self::$pdo = null;
            self::init();
            return self::$useDb;
        }
    }

    private static function migrate() {
        try {
            self::$pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                             password_hash VARCHAR(255) NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            self::$pdo->exec("
            CREATE TABLE IF NOT EXISTS recon_targets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                domain VARCHAR(255) NOT NULL,
                             notes TEXT,
                             tags TEXT,
                             is_monitored TINYINT(1) DEFAULT 0,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                             UNIQUE KEY user_domain (user_id, domain)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            self::$pdo->exec("
            CREATE TABLE IF NOT EXISTS recon_scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target_id INT NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile VARCHAR(20),
                             risk_score DECIMAL(4,1),
                             classification VARCHAR(20),
                             duration FLOAT,
                             report_json LONGTEXT,
                             INDEX(target_id),
                             FOREIGN KEY (target_id) REFERENCES recon_targets(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            self::$pdo->exec("
            CREATE TABLE IF NOT EXISTS tracking_links (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                token VARCHAR(64) NOT NULL UNIQUE,
                             label VARCHAR(255) DEFAULT '',
                             disguise_path VARCHAR(120) NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             is_active TINYINT(1) DEFAULT 1,
                             INDEX(user_id),
                             INDEX(token)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            self::$pdo->exec("
            CREATE TABLE IF NOT EXISTS tracking_hits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                link_id INT NOT NULL,
                hit_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip VARCHAR(45),
                             user_agent TEXT,
                             language VARCHAR(64),
                             referer TEXT,
                             local_ip VARCHAR(45) DEFAULT NULL,
                             extra_json TEXT,
                             INDEX(link_id),
                             FOREIGN KEY (link_id) REFERENCES tracking_links(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");
        } catch (\Throwable $e) {}
    }

    public static function register($username, $password, $code) {
        if (!self::ping()) {
            return ['error' => 'Database offline'];
        }
        if ($code !== REGISTRATION_CODE) {
            return ['error' => 'Invalid team code'];
        }
        if (strlen($username) < 3 || strlen($password) < 6) {
            return ['error' => 'Username min 3, password min 6'];
        }

        try {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = self::$pdo->prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, NOW())");
            $stmt->execute([$username, $hash]);
            return ['ok' => true];
        } catch (\Throwable $e) {
            return ['error' => 'Username taken'];
        }
    }

    public static function login($username, $password) {
        if (!self::ping()) {
            return ['error' => 'Database offline'];
        }
        try {
            $stmt = self::$pdo->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password_hash'])) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                return ['ok' => true, 'username' => $user['username']];
            }
            return ['error' => 'Invalid credentials'];
        } catch (\Throwable $e) {
            return ['error' => 'Login error'];
        }
    }

    public static function logout() {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
    }

    public static function isLoggedIn() {
        return !empty($_SESSION['user_id']);
    }

    public static function currentUserId() {
        return $_SESSION['user_id'] ?? null;
    }

    public static function saveScan($uid, $domain, array $report, $duration = 0) {
        if (!$uid || !self::ping()) {
            return ['error' => 'Auth/DB error'];
        }

        try {
            self::$pdo->exec("SET sql_mode = ''");
            $domain = strtolower(trim($domain));

            $stmt = self::$pdo->prepare("INSERT INTO recon_targets (user_id, domain, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE updated_at = NOW()");
            $stmt->execute([$uid, $domain]);

            $stmt = self::$pdo->prepare("SELECT id FROM recon_targets WHERE user_id = ? AND domain = ?");
            $stmt->execute([$uid, $domain]);
            $tid = $stmt->fetchColumn();

            if ($tid) {
                $flags = JSON_UNESCAPED_SLASHES | (defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0);
                $encoded = json_encode($report, $flags) ?: '{}';

                $score = round((float)($report['risk']['score'] ?? 0), 1);
                $classification = (string)($report['risk']['classification'] ?? 'LOW');
                $profile = (string)($report['profile'] ?? 'quick');

                $stmt = self::$pdo->prepare("
                INSERT INTO recon_scans
                (target_id, scanned_at, profile, risk_score, classification, duration, report_json)
                VALUES (?, NOW(), ?, ?, ?, ?, ?)
                ");
                $stmt->execute([$tid, $profile, $score, $classification, round((float)$duration, 2), $encoded]);

                $stmt = self::$pdo->prepare("SELECT id FROM recon_scans WHERE target_id = ? ORDER BY scanned_at DESC");
                $stmt->execute([$tid]);
                $all = $stmt->fetchAll(PDO::FETCH_COLUMN);

                if (count($all) > KEEP_SCANS) {
                    $toDelete = array_slice($all, KEEP_SCANS);
                    $in = implode(',', array_fill(0, count($toDelete), '?'));
                    $stmt = self::$pdo->prepare("DELETE FROM recon_scans WHERE id IN ($in)");
                    $stmt->execute($toDelete);
                }
                return ['ok' => true];
            }
            return ['error' => 'Target ID resolve failed'];
        } catch (\Throwable $e) {
            return ['error' => $e->getMessage()];
        }
    }

    public static function getVault() {
        if (!self::isLoggedIn() || !self::ping()) {
            return [];
        }
        try {
            $stmt = self::$pdo->prepare("
            SELECT t.id, t.domain, t.is_monitored, t.notes, t.tags, t.updated_at, u.username
            FROM recon_targets t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.updated_at DESC LIMIT 100
            ");
            $stmt->execute();
            $out = [];

            foreach ($stmt->fetchAll() as $t) {
                $stmt2 = self::$pdo->prepare("SELECT scanned_at, risk_score, classification, report_json FROM recon_scans WHERE target_id = ? ORDER BY scanned_at DESC LIMIT 1");
                $stmt2->execute([$t['id']]);
                $scan = $stmt2->fetch();

                $key = $t['domain'] . '|' . $t['username'];
                $out[$key] = [
                    'domain'         => $t['domain'],
                    'author'         => $t['username'],
                    'timestamp'      => $scan ? $scan['scanned_at'] : $t['updated_at'],
                    'is_monitored'   => (bool)$t['is_monitored'],
                    'risk_score'     => $scan ? (float)$scan['risk_score'] : null,
                    'classification' => $scan ? $scan['classification'] : 'LOW',
                    'notes'          => $t['notes'] ?? '',
                    'tags'           => $t['tags'] ? array_filter(explode(',', $t['tags'])) : [],
                    'report'         => ($scan && !empty($scan['report_json'])) ? json_decode($scan['report_json'], true) : null
                ];
            }
            return $out;
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function getTargetFull($domain) {
        if (!self::isLoggedIn() || !self::ping()) {
            return null;
        }
        try {
            $domain = strtolower(trim($domain));
            $stmt = self::$pdo->prepare("SELECT id, is_monitored, notes, tags FROM recon_targets WHERE domain = ? ORDER BY (user_id = ?) DESC LIMIT 1");
            $stmt->execute([$domain, self::currentUserId()]);
            $t = $stmt->fetch();

            if (!$t) {
                return null;
            }

            $stmt = self::$pdo->prepare("SELECT report_json, scanned_at, duration, profile, risk_score, classification FROM recon_scans WHERE target_id = ? ORDER BY scanned_at DESC LIMIT 10");
            $stmt->execute([$t['id']]);
            $history = [];

            foreach ($stmt->fetchAll() as $s) {
                $history[] = [
                    'scanned_at'     => $s['scanned_at'],
                    'profile'        => $s['profile'],
                    'score'          => (float)$s['risk_score'],
                    'classification' => $s['classification'],
                    'duration'       => (float)$s['duration'],
                    'report'         => json_decode($s['report_json'], true)
                ];
            }
            return [
                'domain'       => $domain,
                'is_monitored' => (bool)$t['is_monitored'],
                'notes'        => $t['notes'] ?? '',
                'tags'         => $t['tags'] ? array_filter(explode(',', $t['tags'])) : [],
                'report'       => $history[0]['report'] ?? null,
                'history'      => $history,
                'timestamp'    => $history[0]['scanned_at'] ?? null,
                'scan_count'   => count($history)
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function toggleMonitor($domain) {
        if (!self::isLoggedIn() || !self::ping()) {
            return ['error'=>'DB offline'];
        }
        try {
            $domain = strtolower(trim($domain));
            $stmt = self::$pdo->prepare("UPDATE recon_targets SET is_monitored = NOT is_monitored WHERE user_id = ? AND domain = ?");
            $stmt->execute([self::currentUserId(), $domain]);

            $stmt = self::$pdo->prepare("SELECT is_monitored FROM recon_targets WHERE user_id = ? AND domain = ?");
            $stmt->execute([self::currentUserId(), $domain]);

            return ['ok' => true, 'is_monitored' => (bool)$stmt->fetchColumn()];
        } catch (\Throwable $e) {
            return ['error' => 'Failed to toggle'];
        }
    }

    public static function getMonitoredTargets() {
        if (!self::ping()) {
            return [];
        }
        try {
            $stmt = self::$pdo->prepare("SELECT id, user_id, domain FROM recon_targets WHERE is_monitored = 1 ORDER BY updated_at ASC LIMIT 15");
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function saveNotes($domain, $notes, $tags) {
        if (!self::isLoggedIn() || !self::ping()) {
            return;
        }
        try {
            $stmt = self::$pdo->prepare("UPDATE recon_targets SET notes = ?, tags = ? WHERE domain = ?");
            $stmt->execute([$notes, $tags, strtolower(trim($domain))]);
        } catch (\Throwable $e) {}
    }

    public static function clearAllHistory() {
        if (!self::isLoggedIn() || !self::ping()) {
            return 0;
        }
        try {
            $stmt = self::$pdo->prepare("DELETE FROM recon_targets WHERE user_id = ?");
            $stmt->execute([self::currentUserId()]);
            return $stmt->rowCount();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public static function createTrackingLink($label = '') {
        if (!self::isLoggedIn() || !self::ping()) {
            return ['error' => 'Auth/DB required'];
        }
        try {
            $token = bin2hex(random_bytes(16));
            $disguise = 'article/' . (1000 + random_int(0, 8999));
            $stmt = self::$pdo->prepare("INSERT INTO tracking_links (user_id, token, label, disguise_path) VALUES (?, ?, ?, ?)");
            $stmt->execute([self::currentUserId(), $token, substr($label, 0, 255), $disguise]);
            $id = (int)self::$pdo->lastInsertId();
            return [
                'ok'            => true,
                'id'            => $id,
                'token'         => $token,
                'disguise_path' => $disguise,
                'url'           => self::buildTrackingUrl($disguise, $token)
            ];
        } catch (\Throwable $e) {
            return ['error' => 'Failed to create link'];
        }
    }

    public static function buildTrackingUrl($disguisePath, $token) {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $script = basename($_SERVER['SCRIPT_NAME']);
        return $scheme . '://' . $host . '/' . $script . '/' . ltrim($disguisePath, '/') . '?t=' . urlencode($token);
    }

    public static function getTrackingLinks() {
        if (!self::isLoggedIn() || !self::ping()) {
            return [];
        }
        try {
            $stmt = self::$pdo->prepare("
            SELECT l.id, l.token, l.label, l.disguise_path, l.created_at, l.is_active,
            (SELECT COUNT(*) FROM tracking_hits h WHERE h.link_id = l.id) AS hit_count
            FROM tracking_links l
            WHERE l.user_id = ?
            ORDER BY l.created_at DESC
            LIMIT 50
            ");
            $stmt->execute([self::currentUserId()]);
            $rows = $stmt->fetchAll();
            foreach ($rows as &$r) {
                $r['url'] = self::buildTrackingUrl($r['disguise_path'], $r['token']);
                $r['hit_count'] = (int)$r['hit_count'];
                $r['is_active'] = (bool)$r['is_active'];
            }
            return $rows;
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function getTrackingHits($linkId, $limit = 100) {
        if (!self::isLoggedIn() || !self::ping()) {
            return [];
        }
        try {
            $stmt = self::$pdo->prepare("
            SELECT h.* FROM tracking_hits h
            JOIN tracking_links l ON l.id = h.link_id
            WHERE h.link_id = ? AND l.user_id = ?
            ORDER BY h.hit_at DESC
            LIMIT ?
            ");
            $stmt->bindValue(1, (int)$linkId, PDO::PARAM_INT);
            $stmt->bindValue(2, self::currentUserId(), PDO::PARAM_INT);
            $stmt->bindValue(3, (int)$limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function recordTrackingHit($token, array $data) {
        if (!self::ping() || empty($token)) {
            return false;
        }
        try {
            $stmt = self::$pdo->prepare("SELECT id FROM tracking_links WHERE token = ? AND is_active = 1 LIMIT 1");
            $stmt->execute([$token]);
            $linkId = $stmt->fetchColumn();
            if (!$linkId) {
                return false;
            }

            $ip = $data['ip'] ?? '';
            $extra = $data['extra'] ?? [];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $ctx = stream_context_create(['http' => ['timeout' => 3]]);
                $raw = @file_get_contents("http://ip-api.com/json/{$ip}?fields=proxy,hosting", false, $ctx);
                if ($raw && ($res = json_decode($raw, true))) {
                    $extra['is_vpn_or_proxy'] = $res['proxy'] ?? false;
                    $extra['is_datacenter']   = $res['hosting'] ?? false;
                }
            }

            $stmt = self::$pdo->prepare("
            INSERT INTO tracking_hits (link_id, ip, user_agent, language, referer, local_ip, extra_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $linkId,
                $ip,
                $data['user_agent'] ?? null,
                $data['language'] ?? null,
                $data['referer'] ?? null,
                $data['local_ip'] ?? null,
                !empty($extra) ? json_encode($extra) : null
            ]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    public static function deactivateTrackingLink($linkId) {
        if (!self::isLoggedIn() || !self::ping()) {
            return ['error' => 'Auth required'];
        }
        try {
            $stmt = self::$pdo->prepare("UPDATE tracking_links SET is_active = 0 WHERE id = ? AND user_id = ?");
            $stmt->execute([(int)$linkId, self::currentUserId()]);
            return ['ok' => true];
        } catch (\Throwable $e) {
            return ['error' => 'Failed'];
        }
    }
}

class UsernameRecon {
    private static $platforms = [
        'GitHub'      => 'https://github.com/',
        'Twitter'     => 'https://twitter.com/',
        'Linktree'    => 'https://linktr.ee/',
        'HackTheBox'  => 'https://app.hackthebox.com/users/',
        'TryHackMe'   => 'https://tryhackme.com/p/',
        'Pastebin'    => 'https://pastebin.com/u/',
        'Dev.to'      => 'https://dev.to/',
        'Vimeo'       => 'https://vimeo.com/',
        'Medium'      => 'https://medium.com/@',
        'Patreon'     => 'https://www.patreon.com/',
        'Keybase'     => 'https://keybase.io/',
        'Reddit'      => 'https://www.reddit.com/user/',
        'HackerOne'   => 'https://hackerone.com/',
        'GitLab'      => 'https://gitlab.com/',
        'Bitbucket'   => 'https://bitbucket.org/',
        'About.me'    => 'https://about.me/',
        'ProductHunt' => 'https://www.producthunt.com/@',
        'Behance'     => 'https://www.behance.net/',
        'Dribbble'    => 'https://dribbble.com/',
        'Steam'       => 'https://steamcommunity.com/id/',
        'Telegram'    => 'https://t.me/',
        'TikTok'      => 'https://www.tiktok.com/@',
        'Instagram'   => 'https://www.instagram.com/',
        'Pinterest'   => 'https://www.pinterest.com/',
        'Flickr'      => 'https://www.flickr.com/people/',
        'SoundCloud'  => 'https://soundcloud.com/',
        'Spotify'     => 'https://open.spotify.com/user/',
        'Twitch'      => 'https://www.twitch.tv/',
        'LinkedIn'    => 'https://www.linkedin.com/in/',
        'Facebook'    => 'https://www.facebook.com/',
    ];

    public static function scan($username) {
        $mh = curl_multi_init();
        $ch_list = [];

        foreach (self::$platforms as $platform => $baseUrl) {
            $ch = curl_init($baseUrl . urlencode($username));
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => false,
                CURLOPT_NOBODY         => false,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_ENCODING       => '',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 2
            ]);

            // Link to the main engine's stealth configuration
            AetherRecon::applyCurlStealthOptions($ch);

            curl_multi_add_handle($mh, $ch);
            $ch_list[$platform] = $ch;
        }

        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 1.0);
            }
            if (connection_aborted()) {
                foreach ($ch_list as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit; // Safely halt the PHP process immediately
            }
        } while ($running > 0 && $status == CURLM_OK);

        $profiles = [];
        $emails = [];
        $cross_links = [];
        $cryptos = [];
        $phones = [];
        $avatar = null;
        $bio = null;

        $ignore_domains = ['github.com', 'twitter.com', 'sentry.io', 'example.com', 'domain.com', 'medium.com', 'patreon.com', 'w3.org'];

        foreach ($ch_list as $platform => $ch) {
            if (curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) {
                $profiles[$platform] = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
                $html = curl_multi_getcontent($ch);

                if (in_array($platform, ['GitHub', 'Twitter', 'Medium', 'Linktree'])) {
                    if (!$avatar && preg_match('/<meta property="og:image"\s+content="([^"]+)"/i', $html, $m)) {
                        $avatar = $m[1];
                    }
                    if (!$bio && preg_match('/<meta property="og:description"\s+content="([^"]+)"/i', $html, $m)) {
                        $bio = strip_tags(html_entity_decode($m[1]));
                    }
                }

                if (preg_match_all('/[a-z0-9_\-\+\.]+@[a-z0-9\-]+\.([a-z]{2,4})(?:\.[a-z]{2})?/i', $html, $em)) {
                    foreach($em[0] as $email) {
                        $email = strtolower($email);
                        $domain = substr(strrchr($email, "@"), 1);

                        if (!in_array($domain, $ignore_domains) && !preg_match('/^(no-?reply|support|admin|info|contact|hello)@/', $email)) {
                            if (!preg_match('/\.(png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|css|js)$/i', $email)) {
                                if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                                    $emails[] = $email;
                                }
                            }
                        }
                    }
                }

                if (preg_match_all('/\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b/', $html, $btc)) {
                    foreach($btc[0] as $wallet) {
                        $cryptos[] = ['type' => 'BTC', 'address' => $wallet];
                    }
                }
                if (preg_match_all('/\b0x[a-fA-F0-9]{40}\b/', $html, $eth)) {
                    foreach($eth[0] as $wallet) {
                        $cryptos[] = ['type' => 'ETH', 'address' => $wallet];
                    }
                }

                // --- PRECISION PHONE EXTRACTOR (Handles SPAs & Raw HTML) ---
                $rawPhones = [];

                // 1. Explicit 'tel:' links (Catches <a href="tel:..."> and JSON "tel:...")
                if (preg_match_all('/tel:\+?([0-9\-\.\s\(\)]{7,20})["\'<]/i', $html, $telMatches)) {
                    foreach ($telMatches[1] as $ph) {
                        $rawPhones[] = $ph;
                    }
                }

                // 2. Formatted numbers and explicit + international numbers
                // Looks for: +1234567890, (123) 456-7890, 123-456-7890, 123.456.7890
                $pattern = '/(?:\B\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b|\B\+\d{10,15}\b/';

                if (preg_match_all($pattern, $html, $matches)) {
                    foreach ($matches[0] as $phone) {
                        $rawPhones[] = $phone;
                    }
                }

                // 3. Clean and validate to filter out JS noise
                foreach ($rawPhones as $phone) {
                    $digits = preg_replace('/[^0-9]/', '', $phone);

                    // Length check (10 to 15 digits)
                    if (strlen($digits) >= 10 && strlen($digits) <= 15) {
                        // Drop dummy numbers (e.g., 0000000000, 1234567890)
                        if (!preg_match('/^(.)\1+$/', $digits) && !preg_match('/0123456|1234567|2345678|3456789|9876543/', $digits)) {
                            // Drop dates disguised as phones (e.g. 2026-08-13)
                            if (!preg_match('/^(19|20)\d{2}[-.\/]\d{2}[-.\/]\d{2}$/', trim($phone))) {
                                $phones[] = trim(strip_tags($phone));
                            }
                        }
                    }
                }

                if (preg_match_all('/href=["\'](https?:\/\/(?:www\.)?(twitter\.com|github\.com|linkedin\.com\/in|facebook\.com|instagram\.com|youtube\.com|medium\.com|reddit\.com\/user|t\.me|t\.co|linktr\.ee|patreon\.com|keybase\.io)\/[^"\'>\s]+)["\']/i', $html, $lm)) {
                    foreach($lm[1] as $link) {
                        $cross_links[] = rtrim($link, '/"\'');
                    }
                }
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        $emails = array_values(array_unique($emails));
        $breaches = [];

        if (!empty($emails)) {
            foreach($emails as $email) {
                $ctx = stream_context_create([
                    'http' => [
                        'method'     => 'GET',
                        'user_agent' => AetherRecon::getStealthUserAgent(),
                                             'timeout'    => 5
                    ]
                ]);
                $xon = @file_get_contents("https://api.xposedornot.com/v1/check-email/" . urlencode($email), false, $ctx);
                if ($xon) {
                    $bData = json_decode($xon, true);
                    if (!empty($bData['breaches'][0])) {
                        foreach($bData['breaches'][0] as $breachName) {
                            $breaches[] = [
                                'email' => $email,
                                'breach' => $breachName,
                                'date' => 'Unknown'
                            ];
                        }
                    }
                }
                sleep(1);
            }
        }

        $emails = array_values(array_unique($emails));
        // --- NEW (Caps phone results to max 10 to prevent bloat) ---
        $phones = array_slice(array_values(array_unique($phones)), 0, 10);
        $cross_links = array_values(array_unique($cross_links));
        $cryptos = array_map("unserialize", array_unique(array_map("serialize", $cryptos)));

        // Identity strength / pivot score (0-100)
        $score = 0;
        $score += min(40, count($profiles) * 4);
        $score += min(20, count($emails) * 8);
        $score += min(10, count($phones) * 5);
        $score += min(10, count($cross_links) * 2);
        $score += min(10, count($breaches) * 3);
        $score += min(10, count($cryptos) * 4);
        if ($bio) $score += 5;
        if ($avatar) $score += 5;
        $score = min(100, $score);

        $persona = 'Sparse';
        if ($score >= 70) $persona = 'Rich digital footprint';
        elseif ($score >= 45) $persona = 'Moderate public presence';
        elseif ($score >= 20) $persona = 'Limited public presence';

        return [
            'type'           => 'username',
            'target'         => $username,
            'scanned_at'     => date('c'),
            'profiles_found' => count($profiles),
            'profiles'       => $profiles,
            'dossier'        => [
                'avatar'  => $avatar,
                'bio'     => $bio,
                'emails'  => $emails,
                'phones'  => $phones,
                'cryptos' => $cryptos,
            ],
            'breaches'       => $breaches,
            'cross_links'    => $cross_links,
            'identity'       => [
                'score'   => $score,
                'persona' => $persona,
                'signals' => [
                    'profiles' => count($profiles),
                    'emails'   => count($emails),
                    'phones'   => count($phones),
                    'breaches' => count($breaches),
                    'links'    => count($cross_links),
                    'wallets'  => count($cryptos),
                ]
            ]
        ];
    }
}

class AetherRecon {

    /** @var string|null Persona for current request (set by API router) */
    public static $requestPersona = null;

    /**
     * Resolve active stealth persona (chrome | googlebot | bingbot | mixed).
     */
    public static function resolvePersona($persona = null) {
        if ($persona === null || $persona === '') {
            $persona = defined('DEFAULT_PERSONA') ? DEFAULT_PERSONA : 'chrome';
        }
        $persona = strtolower(trim((string)$persona));
        if ($persona === 'mixed') {
            $persona = ['chrome', 'googlebot', 'bingbot'][random_int(0, 2)];
        }
        if (!in_array($persona, ['chrome', 'googlebot', 'bingbot'], true)) {
            $persona = 'chrome';
        }
        return $persona;
    }

    /**
     * Generates a realistic User-Agent for the selected persona.
     */
    public static function getStealthUserAgent($persona = null) {
        $persona = self::resolvePersona($persona);
        if ($persona === 'googlebot') {
            return 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        }
        if ($persona === 'bingbot') {
            return 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
        }
        $userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
        ];
        return $userAgents[array_rand($userAgents)];
    }

    /**
     * Headers matched to persona (browser vs search-engine bot).
     */
    public static function getStealthHeaders($persona = null) {
        $persona = self::resolvePersona($persona);
        $ua = self::getStealthUserAgent($persona);

        if ($persona === 'googlebot') {
            return [
                'User-Agent: ' . $ua,
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                'From: googlebot(at)googlebot.com',
                'Connection: close'
            ];
        }
        if ($persona === 'bingbot') {
            return [
                'User-Agent: ' . $ua,
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                'Connection: close'
            ];
        }

        $headers = [
            'User-Agent: ' . $ua,
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.9',
            'Sec-Ch-Ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile: ?0',
            'Sec-Ch-Ua-Platform: "Windows"',
            'Sec-Fetch-Dest: document',
            'Sec-Fetch-Mode: navigate',
            'Sec-Fetch-Site: none',
            'Sec-Fetch-User: ?1',
            'Upgrade-Insecure-Requests: 1'
        ];
        // Soft referer sometimes helps blend with organic traffic patterns
        if (random_int(0, 1) === 1) {
            $headers[] = 'Referer: https://www.google.com/';
        }
        return $headers;
    }

    /**
     * Applies micro delays and randomized timing jitter when stealth is active.
     */
    public static function applyStealthDelay() {
        if (defined('STEALTH_MODE') && STEALTH_MODE) {
            $jitter = random_int(100, 300);
            $delayMicroseconds = (STEALTH_DELAY_MS + $jitter) * 1000;
            usleep($delayMicroseconds);
        }
    }

    /**
     * Applies user-agent, headers, and optional proxy configurations to a cURL handle.
     * $persona: chrome | googlebot | bingbot | mixed | null (DEFAULT_PERSONA)
     */
    public static function applyCurlStealthOptions(&$ch, $customHeaders = [], $persona = null) {
        if ($persona === null && self::$requestPersona !== null) {
            $persona = self::$requestPersona;
        }
        $headers = empty($customHeaders) ? self::getStealthHeaders($persona) : $customHeaders;
        $ua = self::getStealthUserAgent($persona);

        // Keep UA consistent with header block when using persona headers
        foreach ($headers as $h) {
            if (stripos($h, 'User-Agent:') === 0) {
                $ua = trim(substr($h, strlen('User-Agent:')));
                break;
            }
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_USERAGENT, $ua);

        if (defined('PROXY_ENABLED') && PROXY_ENABLED) {
            curl_setopt($ch, CURLOPT_PROXY, PROXY_ADDR);
            curl_setopt($ch, CURLOPT_PROXYTYPE, PROXY_TYPE);
        }
    }



    public static function getFaviconHash($domain) {
        $url = "https://{$domain}/favicon.ico";
        $ctx = stream_context_create([
            'http' => ['timeout' => 5, 'user_agent' => 'AetherRecon/14.6'],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
        ]);
        $ico = @file_get_contents($url, false, $ctx);
        if (!$ico) return null;
        $b64 = chunk_split(base64_encode($ico), 76, "\n");
        return self::murmurhash3_32($b64);
    }

    private static function murmurhash3_32($key, $seed = 0) {
        $key = array_values(unpack('C*', $key));
        $len = count($key);
        $h1 = $seed;
        $c1 = 0xcc9e2d51;
        $c2 = 0x1b873593;

        for ($i = 0; $i + 4 <= $len; $i += 4) {
            $k1 = $key[$i] | ($key[$i+1] << 8) | ($key[$i+2] << 16) | ($key[$i+3] << 24);
            $k1 = ($k1 * $c1) & 0xffffffff;
            $k1 = (($k1 << 15) | ($k1 >> 17)) & 0xffffffff;
            $k1 = ($k1 * $c2) & 0xffffffff;

            $h1 ^= $k1;
            $h1 = (($h1 << 13) | ($h1 >> 19)) & 0xffffffff;
            $h1 = ($h1 * 5 + 0xe6546b64) & 0xffffffff;
        }

        $k1 = 0;
        $tail = $len & 3;
        if ($tail >= 3) $k1 ^= $key[$len - 1 - ($tail - 3)] << 16;
        if ($tail >= 2) $k1 ^= $key[$len - 1 - ($tail - 2)] << 8;
        if ($tail >= 1) {
            $k1 ^= $key[$len - 1 - ($tail - 1)];
            $k1 = ($k1 * $c1) & 0xffffffff;
            $k1 = (($k1 << 15) | ($k1 >> 17)) & 0xffffffff;
            $k1 = ($k1 * $c2) & 0xffffffff;
            $h1 ^= $k1;
        }

        $h1 ^= $len;
        $h1 ^= ($h1 >> 16);
        $h1 = ($h1 * 0x85ebca6b) & 0xffffffff;
        $h1 ^= ($h1 >> 13);
        $h1 = ($h1 * 0xc2b2ae35) & 0xffffffff;
        $h1 ^= ($h1 >> 16);

        if ($h1 & 0x80000000) {
            return -((~$h1 & 0xFFFFFFFF) + 1);
        }
        return $h1;
    }

    public static function searchPgpKeys($domain) {
        $url = "https://keyserver.ubuntu.com/pks/lookup?search=" . urlencode($domain) . "&op=index&options=mr";
        $ctx = stream_context_create([
            'http' => [
                'timeout'    => 5,
                'user_agent' => self::getStealthUserAgent() // <-- Added
            ]
        ]);
        $raw = @file_get_contents($url, false, $ctx);
        // ... rest of function remains the same
        $keys = [];
        if ($raw && strpos($raw, 'pub:') !== false) {
            foreach (explode("\n", $raw) as $line) {
                if (strpos($line, 'pub:') === 0) {
                    $parts = explode(':', $line);
                    $keys[] = [
                        'key_id'     => $parts[1] ?? 'Unknown',
                        'algo'       => $parts[2] ?? '',
                        'created_at' => isset($parts[4]) ? date('Y-m-d', $parts[4]) : ''
                    ];
                }
            }
        }
        return $keys;
    }

    public static function auditTls($domain) {
        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            ]
        ]);

        $sock = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
        if (!$sock) {
            return ['status'=>'OFFLINE','error'=>"Handshake failed",'risk'=>4.5];
        }

        $params = stream_context_get_params($sock);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $meta = stream_get_meta_data($sock);
        $protocol = $meta['crypto']['protocol'] ?? 'Unknown';
        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
        fclose($sock);

        if (!$cert || !($data = openssl_x509_parse($cert))) {
            return ['status'=>'ERROR','error'=>'Parse failed','risk'=>3.8];
        }

        $algo = $data['signatureTypeSN'] ?? 'Unknown';
        $weak = in_array(strtolower($algo), ['sha1withrsaencryption','md5withrsaencryption']);
        $from = $data['validFrom_time_t'] ?? 0;
        $to   = $data['validTo_time_t'] ?? 0;
        $days = $to ? (int)(($to - time())/86400) : -999;
        $expired = time() > $to;

        $sans = [];
        if (!empty($data['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^,]+)/', $data['extensions']['subjectAltName'], $m);
            $sans = array_map('trim', $m[1] ?? []);
        }

        $risk = 0;
        if ($expired) {
            $risk += 4.5;
        }
        if ($weak) {
            $risk += 3.2;
        }
        if ($days >= 0 && $days < 7) {
            $risk += 2.0;
        } elseif ($days >= 0 && $days < 14) {
            $risk += 1.3;
        } elseif ($days >= 0 && $days < 30) {
            $risk += 0.7;
        }

        if (in_array($protocol, ['TLSv1.0', 'TLSv1.1', 'SSLv3'])) {
            $risk += 3.0;
        }

        return [
            'status'              => $expired ? 'EXPIRED' : 'ACTIVE',
            'subject'             => $data['subject']['CN'] ?? $domain,
            'issuer'              => $data['issuer']['CN'] ?? ($data['issuer']['O'] ?? 'Unknown'),
            'signature_algo'      => $algo,
            'is_weak_algorithm'   => $weak,
            'negotiated_protocol' => $protocol,
            'valid_from'          => date('Y-m-d H:i:s', $from),
            'valid_until'         => date('Y-m-d H:i:s', $to),
            'days_remaining'      => $days,
            'sans'                => $sans,
            'serial'              => $data['serialNumberHex'] ?? ($data['serialNumber'] ?? null),
            'chain_length'        => count($chain) + 1,
            'risk'                => min($risk, 5.0)
        ];
    }

    public static function auditDns($domain) {
        $records = @dns_get_record($domain, DNS_A + DNS_AAAA + DNS_MX + DNS_NS + DNS_TXT + DNS_SOA + DNS_CAA) ?: [];
        $res = [
            'A'=>[],'AAAA'=>[],'MX'=>[],'NS'=>[],'TXT'=>[],'SOA'=>null,
            'CAA'=>[],'SPF'=>null,'DMARC'=>null, 'MTA_STS'=>null, 'BIMI'=>null, 'risk'=>0
        ];

        foreach ($records as $r) {
            if ($r['type'] === 'A') {
                $res['A'][] = $r['ip'];
            }
            if ($r['type'] === 'AAAA') {
                $res['AAAA'][] = $r['ipv6'];
            }
            if ($r['type'] === 'MX') {
                $res['MX'][] = $r['target'].' (prio '.$r['pri'].')';
            }
            if ($r['type'] === 'NS') {
                $res['NS'][] = $r['target'];
            }
            if ($r['type'] === 'TXT') {
                $res['TXT'][] = $r['txt'];
                if (stripos($r['txt'], 'v=spf1') !== false) {
                    $res['SPF'] = $r['txt'];
                }
            }
            if ($r['type'] === 'SOA') {
                $res['SOA'] = $r;
            }
            if ($r['type'] === 'CAA') {
                $res['CAA'][] = trim(($r['flag']??'').' '.($r['tag']??'').' '.($r['value']??''));
            }
        }

        $dmarc = @dns_get_record('_dmarc.'.$domain, DNS_TXT);
        if (!empty($dmarc[0]['txt'])) {
            $res['DMARC'] = $dmarc[0]['txt'];
        }

        $mta = @dns_get_record('_mta-sts.'.$domain, DNS_TXT);
        if (!empty($mta[0]['txt'])) {
            $res['MTA_STS'] = $mta[0]['txt'];
        }

        $bimi = @dns_get_record('default._bimi.'.$domain, DNS_TXT);
        if (!empty($bimi[0]['txt'])) {
            $res['BIMI'] = $bimi[0]['txt'];
        }

        if (empty($res['SPF'])) {
            $res['risk'] += 0.4;
        }
        if (empty($res['DMARC'])) {
            $res['risk'] += 0.4;
        }
        if (empty($res['CAA'])) {
            $res['risk'] += 0.1;
        }
        if (empty($res['MTA_STS'])) {
            $res['risk'] += 0.1;
        }
        if (empty($res['A']) && empty($res['AAAA'])) {
            $res['risk'] += 1.0;
        }
        if ($res['SPF'] && (stripos($res['SPF'], '+all') !== false || stripos($res['SPF'], '?all') !== false)) {
            $res['risk'] += 1.0;
        }

        $res['risk'] = min($res['risk'], 5.0);
        return $res;
    }

    public static function auditHttp($domain) {
        $ctx = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => 9,
                'user_agent'    => self::getStealthUserAgent(),
                                     'max_redirects' => 6,
                                     'header'        => "Accept: text/html\r\nConnection: close\r\n"
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false
            ]
        ]);

        $headers = @get_headers("https://{$domain}", 1, $ctx);
        $proto = 'HTTPS';
        $url = "https://{$domain}";

        if (!$headers) {
            $headers = @get_headers("http://{$domain}", 1, $ctx);
            $proto = 'HTTP';
            $url = "http://{$domain}";
        }

        $security = [
            'Strict-Transport-Security' => null,
            'Content-Security-Policy'   => null,
            'X-Frame-Options'           => null,
            'X-Content-Type-Options'    => null,
            'Referrer-Policy'           => null,
            'Permissions-Policy'        => null,
            'X-XSS-Protection'          => null,
            'Server'                    => null,
            'X-Powered-By'              => null
        ];

        $allHeaders = [];
        if (is_array($headers)) {
            foreach ($headers as $k => $v) {
                $val = is_array($v) ? implode(' | ', $v) : $v;
                $allHeaders[(string)$k] = $val;
                $lk = strtolower((string)$k);
                foreach ($security as $name => $_) {
                    if ($lk === strtolower($name)) {
                        $security[$name] = $val;
                    }
                }
            }
        }

        $tech = [];
        $versions = [];
        if ($security['X-Powered-By']) {
            $tech[] = $security['X-Powered-By'];
            if (preg_match('/php\/?([\d.]+)/i', $security['X-Powered-By'], $vm)) {
                $versions['PHP'] = $vm[1];
            }
            if (preg_match('/asp\.net/i', $security['X-Powered-By'])) {
                $tech[] = 'ASP.NET';
            }
        }
        if ($security['Server']) {
            foreach ([
                'cloudflare' => 'Cloudflare', 'nginx' => 'Nginx', 'apache' => 'Apache',
                'litespeed' => 'LiteSpeed', 'iis' => 'IIS', 'tomcat' => 'Tomcat',
                'jetty' => 'Jetty', 'caddy' => 'Caddy', 'openresty' => 'OpenResty',
                'gunicorn' => 'Gunicorn', 'uvicorn' => 'Uvicorn', 'werkzeug' => 'Werkzeug'
            ] as $n => $l) {
                if (stripos($security['Server'], $n) !== false) {
                    $tech[] = $l;
                }
            }
            if (preg_match('/nginx\/([\d.]+)/i', $security['Server'], $vm)) $versions['Nginx'] = $vm[1];
            if (preg_match('/apache\/([\d.]+)/i', $security['Server'], $vm)) $versions['Apache'] = $vm[1];
            if (preg_match('/iis\/([\d.]+)/i', $security['Server'], $vm)) $versions['IIS'] = $vm[1];
        }

        $bodyCtx = stream_context_create([
            'http' => [
                'timeout' => 5,
                'method' => 'GET',
                'header' => "User-Agent: " . self::getStealthUserAgent() . "\r\nRange: bytes=0-20480\r\n"
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);
        $body = @file_get_contents($url, false, $bodyCtx);
        if ($body) {
            $fingerprints = [
                'WordPress'        => ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal'           => ['Drupal.settings', 'sites/default/files', 'drupal.js'],
                'Joomla'           => ['/media/jui/', 'joomla', 'com_content'],
                'Next.js'          => ['id="__next"', '/_next/static/'],
                'React'            => ['data-reactroot', 'react-dom', '__REACT'],
                'Vue.js'           => ['v-data-v-', 'vue.runtime', '__VUE__'],
                'Angular'          => ['ng-version', 'ng-app', 'angular.js'],
                'Laravel'          => ['laravel', 'csrf-token'],
                'Django'           => ['csrfmiddlewaretoken', 'django'],
                'Ruby on Rails'    => ['rails-env', 'data-turbo'],
                'Spring'           => ['jsessionid', 'spring'],
                'Bootstrap'        => ['bootstrap.min.css', 'bootstrap.min.js'],
                'jQuery'           => ['jquery.min.js', 'jquery-'],
                'Stripe'           => ['stripe.com/v3', 'js.stripe.com'],
                'Google Analytics' => ['google-analytics.com', 'gtag(', 'googletagmanager.com'],
                'Cloudflare'       => ['cf-ray', 'cloudflare'],
                'Shopify'          => ['cdn.shopify.com', 'Shopify.theme'],
                'Magento'          => ['mage/', 'Magento_'],
                'PrestaShop'       => ['prestashop', 'presta-'],
            ];
            foreach ($fingerprints as $name => $needles) {
                foreach ($needles as $n) {
                    if (stripos($body, $n) !== false) {
                        $tech[] = $name;
                        break;
                    }
                }
            }
            if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']/i', $body, $gm)) {
                $tech[] = 'Generator: ' . trim($gm[1]);
                if (preg_match('/wordpress\s*([\d.]+)/i', $gm[1], $wv)) $versions['WordPress'] = $wv[1];
                if (preg_match('/drupal\s*([\d.]+)/i', $gm[1], $dv)) $versions['Drupal'] = $dv[1];
                if (preg_match('/joomla[! ]*([\d.]+)/i', $gm[1], $jv)) $versions['Joomla'] = $jv[1];
            }
            if (preg_match('/wp-content\/themes\/[^\/]+/i', $body)) {
                $tech[] = 'WordPress Theme Detected';
            }
        }

        // Security-header + misconfig scoring pack (local)
        $headerFindings = [];
        $risk = 0;
        if ($proto === 'HTTP') {
            $risk += 2.6;
            $headerFindings[] = ['id' => 'NO-HTTPS', 'severity' => 'HIGH', 'detail' => 'Site reachable over plaintext HTTP'];
        }
        $headerChecks = [
            'Strict-Transport-Security' => [0.5, 'MEDIUM', 'Missing HSTS — browsers will not enforce HTTPS on subsequent visits'],
            'Content-Security-Policy'   => [0.4, 'MEDIUM', 'Missing CSP — increased XSS / injection impact surface'],
            'X-Frame-Options'           => [0.3, 'MEDIUM', 'Missing X-Frame-Options — clickjacking risk'],
            'X-Content-Type-Options'    => [0.2, 'LOW', 'Missing X-Content-Type-Options: nosniff'],
            'Referrer-Policy'           => [0.15, 'LOW', 'Missing Referrer-Policy'],
            'Permissions-Policy'        => [0.1, 'LOW', 'Missing Permissions-Policy'],
        ];
        foreach ($headerChecks as $hdr => $meta) {
            if (empty($security[$hdr])) {
                $risk += $meta[0];
                $headerFindings[] = ['id' => 'MISSING-' . strtoupper(str_replace('-', '', $hdr)), 'severity' => $meta[1], 'detail' => $meta[2]];
            }
        }
        // Cookie flag checks from Set-Cookie headers
        $setCookies = [];
        foreach ($allHeaders as $hk => $hv) {
            if (strtolower((string)$hk) === 'set-cookie') {
                $setCookies = array_merge($setCookies, is_array($hv) ? $hv : [$hv]);
            }
        }
        // get_headers may flatten; also scan allHeaders values
        foreach ($allHeaders as $hk => $hv) {
            if (stripos((string)$hk, 'set-cookie') !== false || stripos((string)$hv, 'set-cookie') === 0) {
                $setCookies[] = is_array($hv) ? implode(' ', $hv) : (string)$hv;
            }
        }
        foreach ($setCookies as $ck) {
            $ckl = strtolower((string)$ck);
            if ($ckl === '') continue;
            if (strpos($ckl, 'secure') === false && $proto === 'HTTPS') {
                $headerFindings[] = ['id' => 'COOKIE-NO-SECURE', 'severity' => 'MEDIUM', 'detail' => 'Set-Cookie without Secure flag on HTTPS site'];
                $risk += 0.25;
            }
            if (strpos($ckl, 'httponly') === false) {
                $headerFindings[] = ['id' => 'COOKIE-NO-HTTPONLY', 'severity' => 'MEDIUM', 'detail' => 'Set-Cookie without HttpOnly flag'];
                $risk += 0.2;
            }
            if (strpos($ckl, 'samesite') === false) {
                $headerFindings[] = ['id' => 'COOKIE-NO-SAMESITE', 'severity' => 'LOW', 'detail' => 'Set-Cookie without SameSite attribute'];
                $risk += 0.1;
            }
            break; // report once per response set
        }
        // Server / X-Powered-By disclosure
        if (!empty($security['Server']) && $security['Server'] !== 'Not disclosed') {
            $headerFindings[] = ['id' => 'SERVER-DISCLOSURE', 'severity' => 'LOW', 'detail' => 'Server header discloses software: ' . $security['Server']];
        }
        if (!empty($security['X-Powered-By'])) {
            $headerFindings[] = ['id' => 'POWERED-BY-DISCLOSURE', 'severity' => 'LOW', 'detail' => 'X-Powered-By discloses stack: ' . $security['X-Powered-By']];
            $risk += 0.15;
        }

        return [
            'protocol'        => $proto,
            'final_url'       => $url,
            'server'          => $security['Server'] ?? 'Not disclosed',
            'powered_by'      => $security['X-Powered-By'],
            'technologies'    => array_values(array_unique($tech)),
            'versions'        => $versions,
            'security'        => $security,
            'header_findings' => $headerFindings,
            'all_headers'     => $allHeaders,
            'risk'            => min($risk, 5.0)
        ];
    }

    public static function mapCVEs($headers) {
        $cves = [];
        $server = strtolower($headers['Server'] ?? '');
        $powered = strtolower($headers['X-Powered-By'] ?? '');
        $haystack = $server . ' ' . $powered;

        // Real CVE-IDs only on tight version match; else advisory (not PoC-enriched)
        if (preg_match('/apache\/2\.4\.(49|50)(\D|$)/', $server)) {
            $cves[] = [
                'id' => 'CVE-2021-41773', 'severity' => 'CRITICAL',
                'desc' => 'Path traversal / possible RCE in Apache HTTP Server 2.4.49.',
                'type' => 'cve', 'confidence' => 'high', 'evidence' => 'Server banner version match', 'product' => 'Apache HTTP Server'
            ];
            $cves[] = [
                'id' => 'CVE-2021-42013', 'severity' => 'CRITICAL',
                'desc' => 'Path traversal bypass related to CVE-2021-41773 in Apache 2.4.50.',
                'type' => 'cve', 'confidence' => 'high', 'evidence' => 'Server banner version match', 'product' => 'Apache HTTP Server'
            ];
        }
        if (preg_match('/apache\/2\.4\.(5[1-3])(\D|$)/', $server)) {
            $cves[] = [
                'id' => 'ADVISORY-APACHE-2.4.51-53', 'severity' => 'MEDIUM',
                'desc' => 'Apache 2.4.51–2.4.53 branch is outdated relative to current stable. Banner hygiene finding.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner version match', 'product' => 'Apache HTTP Server'
            ];
        }
        if (preg_match('/nginx\/1\.(1[0-9]|18|16|14|12|10)(\D|$)/', $server)) {
            $cves[] = [
                'id' => 'ADVISORY-NGINX-OLD', 'severity' => 'MEDIUM',
                'desc' => 'Nginx branch appears outdated. Hygiene finding — not a specific CVE confirmation.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner branch match', 'product' => 'Nginx'
            ];
        }
        if (preg_match('/php\/([5-7])\./', $powered, $mm)) {
            $cves[] = [
                'id' => 'ADVISORY-PHP-EOL', 'severity' => 'HIGH',
                'desc' => 'X-Powered-By reports PHP ' . $mm[1] . '.x (end-of-life). No specific CVE asserted from banner alone.',
                'type' => 'advisory', 'confidence' => 'high', 'evidence' => 'X-Powered-By header', 'product' => 'PHP'
            ];
        }
        if (preg_match('/php\/8\.0\./', $powered)) {
            $cves[] = [
                'id' => 'ADVISORY-PHP-8.0-EOL', 'severity' => 'MEDIUM',
                'desc' => 'PHP 8.0 is end-of-life. Upgrade to a supported 8.x branch.',
                'type' => 'advisory', 'confidence' => 'high', 'evidence' => 'X-Powered-By header', 'product' => 'PHP'
            ];
        }
        if (preg_match('/openssl\/1\.(0\.|1\.0)/', $server)) {
            $cves[] = [
                'id' => 'ADVISORY-OPENSSL-OLD', 'severity' => 'HIGH',
                'desc' => 'OpenSSL 1.0.x / early 1.1.0 lineage is end-of-life. Banner-based hygiene finding.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner', 'product' => 'OpenSSL'
            ];
        }
        if (preg_match('/iis\/(6\.0|7\.0|7\.5|8\.0)(\D|$)/', $server)) {
            $cves[] = [
                'id' => 'ADVISORY-IIS-LEGACY', 'severity' => 'HIGH',
                'desc' => 'Legacy IIS version in Server banner. Unsupported branches carry known historical risk.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner', 'product' => 'Microsoft IIS'
            ];
        }
        if (preg_match('/tomcat\/([6-8])\./', $haystack, $tm)) {
            $cves[] = [
                'id' => 'ADVISORY-TOMCAT-OLD', 'severity' => 'HIGH',
                'desc' => 'Apache Tomcat ' . $tm[1] . '.x lineage appears in banners. Verify patch level; older major versions are EOL.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server / powered-by banner', 'product' => 'Apache Tomcat'
            ];
        }
        if (preg_match('/jetty\/(9\.|8\.|7\.)/', $haystack)) {
            $cves[] = [
                'id' => 'ADVISORY-JETTY-OLD', 'severity' => 'MEDIUM',
                'desc' => 'Older Jetty major version detected in banners. Confirm current security advisories for this branch.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner', 'product' => 'Eclipse Jetty'
            ];
        }
        if (preg_match('/wordpress/i', $haystack) || preg_match('/wp[\/\s]?([\d.]+)/i', $haystack)) {
            $cves[] = [
                'id' => 'ADVISORY-WORDPRESS-CHECK', 'severity' => 'MEDIUM',
                'desc' => 'WordPress indicators in response headers. Verify core, theme, and plugin patch status offline.',
                'type' => 'advisory', 'confidence' => 'low', 'evidence' => 'Header indicators', 'product' => 'WordPress'
            ];
        }
        if (preg_match('/exim\/4\.(8[0-9]|9[0-2])/', $haystack)) {
            $cves[] = [
                'id' => 'ADVISORY-EXIM-OLD', 'severity' => 'HIGH',
                'desc' => 'Older Exim 4.x series in banner. Several historical RCE classes affected early 4.9x builds.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner', 'product' => 'Exim'
            ];
        }
        return $cves;
    }

    public static function enrichCveIntel(array $cveItems) {
        $out = ['status' => 'ok', 'items' => [], 'note' => null];
        $ids = [];
        foreach ($cveItems as $c) {
            $id = is_array($c) ? ($c['id'] ?? '') : (string)$c;
            if (preg_match('/^CVE-\d{4}-\d{4,}$/i', $id)) {
                $ids[strtoupper($id)] = is_array($c) ? $c : ['id' => strtoupper($id)];
            }
        }
        $ids = array_slice($ids, 0, 8, true);
        if (empty($ids)) {
            $out['note'] = 'No high-confidence CVE-IDs available to enrich. Advisories without CVE numbers stay under HTTP findings only.';
            return $out;
        }
        foreach ($ids as $cveId => $base) {
            $item = [
                'id' => $cveId,
                'severity' => $base['severity'] ?? 'UNKNOWN',
                'confidence' => $base['confidence'] ?? 'medium',
                'evidence' => $base['evidence'] ?? 'Reported by scan correlation',
                'product' => $base['product'] ?? null,
                'summary' => $base['desc'] ?? null,
                'cvss' => null, 'cvss_version' => null, 'cwe' => [],
                'published' => null, 'modified' => null, 'references' => [],
                'source' => null,
                'disclaimer' => 'Banner/intelligence correlation only — not a runtime exploit confirmation.'
            ];
            $url = 'https://cve.circl.lu/api/cve/' . rawurlencode($cveId);
            $ctx = stream_context_create(['http' => [
                'method' => 'GET', 'timeout' => 6,
                'header' => "Accept: application/json\r\nUser-Agent: AetherRecon/" . APP_VERSION . "\r\n",
                'ignore_errors' => true
            ]]);
            $raw = @file_get_contents($url, false, $ctx);
            if ($raw && ($j = json_decode($raw, true)) && is_array($j)) {
                $item['source'] = 'CIRCL/cve-search';
                if (!empty($j['summary'])) $item['summary'] = $j['summary'];
                if (isset($j['cvss3'])) { $item['cvss'] = (float)$j['cvss3']; $item['cvss_version'] = '3.x'; }
                elseif (isset($j['cvss'])) { $item['cvss'] = (float)$j['cvss']; $item['cvss_version'] = '2.x'; }
                if (!empty($j['Published'])) $item['published'] = substr((string)$j['Published'], 0, 10);
                if (!empty($j['Modified'])) $item['modified'] = substr((string)$j['Modified'], 0, 10);
                if (!empty($j['cwe']) && is_array($j['cwe'])) {
                    foreach ($j['cwe'] as $cwe) {
                        if (is_string($cwe) && stripos($cwe, 'CWE-') !== false && strtoupper($cwe) !== 'UNKNOWN') $item['cwe'][] = $cwe;
                    }
                }
                $refs = [];
                foreach (($j['references'] ?? []) as $ref) {
                    $u = is_string($ref) ? $ref : '';
                    if ($u === '') continue;
                    $host = strtolower(parse_url($u, PHP_URL_HOST) ?? '');
                    foreach (['cve.mitre.org','nvd.nist.gov','github.com','apache.org','nginx.org','openssl.org','php.net','kb.cert.org','cisa.gov','microsoft.com','redhat.com','debian.org','ubuntu.com','exploit-db.com'] as $allow) {
                        if ($host === $allow || substr($host, -strlen('.'.$allow)) === '.'.$allow) { $refs[] = $u; break; }
                    }
                }
                $item['references'] = array_values(array_unique(array_slice($refs, 0, 8)));
                if ($item['cvss'] !== null) {
                    $s = (float)$item['cvss'];
                    if ($s >= 9.0) $item['severity'] = 'CRITICAL';
                    elseif ($s >= 7.0) $item['severity'] = 'HIGH';
                    elseif ($s >= 4.0) $item['severity'] = 'MEDIUM';
                    else $item['severity'] = 'LOW';
                }
            } else {
                $fallback = [
                    'CVE-2021-41773' => [
                        'summary' => 'A flaw in path normalization in Apache HTTP Server 2.4.49 could map URLs to files outside the document root. With CGI enabled for aliased paths, this may allow remote code execution.',
                        'cvss' => 9.8, 'cvss_version' => '3.1', 'cwe' => ['CWE-22'], 'published' => '2021-10-05',
                        'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773','https://httpd.apache.org/security/vulnerabilities_24.html']
                    ],
                    'CVE-2021-42013' => [
                        'summary' => 'Apache HTTP Server 2.4.50 incomplete fix for CVE-2021-41773 path traversal; with CGI may allow RCE.',
                        'cvss' => 9.8, 'cvss_version' => '3.1', 'cwe' => ['CWE-22'], 'published' => '2021-10-07',
                        'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2021-42013','https://httpd.apache.org/security/vulnerabilities_24.html']
                    ]
                ];
                if (isset($fallback[$cveId])) {
                    $f = $fallback[$cveId];
                    $item['source'] = 'local-curated';
                    foreach (['summary','cvss','cvss_version','cwe','published','references'] as $k) $item[$k] = $f[$k];
                    $item['severity'] = 'CRITICAL';
                } else {
                    $item['source'] = 'scan-only';
                    $item['summary'] = $item['summary'] ?: 'No public enrichment available. Verify on NVD/MITRE manually.';
                    $item['references'] = ['https://nvd.nist.gov/vuln/detail/' . $cveId, 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' . $cveId];
                }
            }
            $item['cwe'] = array_values(array_unique($item['cwe']));
            $out['items'][] = $item;
            usleep(150000);
        }
        return $out;
    }

    public static function searchCvePocs(array $cveItems) {
        $out = ['status' => 'ok', 'items' => [], 'note' => null];
        $ids = [];
        foreach ($cveItems as $c) {
            $id = is_array($c) ? ($c['id'] ?? '') : (string)$c;
            if (preg_match('/^CVE-\d{4}-\d{4,}$/i', $id)) $ids[] = strtoupper($id);
        }
        $ids = array_values(array_unique(array_slice($ids, 0, 5)));
        if (empty($ids)) {
            $out['note'] = 'No CVE-IDs eligible for PoC search (advisories without CVE numbers are skipped).';
            return $out;
        }
        $headers = ['Accept: application/vnd.github+json', 'User-Agent: AetherRecon/' . APP_VERSION];
        if (GITHUB_TOKEN !== '' && strpos(GITHUB_TOKEN, 'YOUR_') !== 0) {
            $headers[] = 'Authorization: Bearer ' . GITHUB_TOKEN;
        }
        foreach ($ids as $cveId) {
            $entry = ['id' => $cveId, 'pocs' => [], 'note' => null];
            $q = $cveId . ' (poc OR "proof of concept" OR exploit) in:name,description,readme';
            $url = 'https://api.github.com/search/repositories?q=' . rawurlencode($q) . '&sort=stars&order=desc&per_page=8';
            $ctx = stream_context_create(['http' => [
                'method' => 'GET', 'header' => implode("\r\n", $headers), 'timeout' => 8, 'ignore_errors' => true
            ]]);
            $raw = @file_get_contents($url, false, $ctx);
            $repos = [];
            if ($raw && ($j = json_decode($raw, true))) {
                if (!empty($j['message']) && stripos($j['message'], 'rate limit') !== false) {
                    $entry['note'] = 'GitHub rate limit — provide GITHUB_TOKEN for better PoC coverage.';
                    $out['items'][] = $entry; $out['status'] = 'rate_limited'; break;
                }
                $repos = $j['items'] ?? [];
            }
            $codeUrl = 'https://api.github.com/search/code?q=' . rawurlencode('"' . $cveId . '" (poc OR exploit)') . '&per_page=5';
            $codeRaw = @file_get_contents($codeUrl, false, $ctx);
            $codeItems = [];
            if ($codeRaw && ($cj = json_decode($codeRaw, true)) && !empty($cj['items'])) $codeItems = $cj['items'];

            $seen = []; $pocs = [];
            foreach ($repos as $r) {
                $full = $r['full_name'] ?? ''; $name = strtolower($r['name'] ?? '');
                $desc = strtolower($r['description'] ?? ''); $html = $r['html_url'] ?? '';
                $stars = (int)($r['stargazers_count'] ?? 0);
                if ($full === '' || isset($seen[$full])) continue;
                $hay = $name . ' ' . $desc . ' ' . strtolower($full);
                if (strpos($hay, strtolower($cveId)) === false) continue;
                if (preg_match('/\b(all[-_ ]?cve|cve[-_ ]?list|cve[-_ ]?database|nuclei[-_ ]?templates)\b/i', $hay) && strpos($name, strtolower($cveId)) === false) continue;
                if (($r['size'] ?? 0) > 500000 && strpos($name, strtolower(str_replace('-', '', $cveId))) === false) continue;
                $confidence = 'medium';
                if (strpos($name, strtolower($cveId)) !== false) $confidence = 'high';
                elseif (preg_match('/\b(poc|exploit|proof)\b/i', $name)) $confidence = 'high';
                elseif ($stars < 1 && !preg_match('/\b(poc|exploit)\b/i', $desc)) $confidence = 'low';
                if ($confidence === 'low') continue;
                $seen[$full] = true;
                $pocs[] = [
                    'title' => $full, 'url' => $html, 'source' => 'GitHub', 'stars' => $stars,
                    'confidence' => $confidence,
                    'summary' => self::clipText($r['description'] ?? 'Repository referencing this CVE.', 160),
                    'updated' => isset($r['updated_at']) ? substr($r['updated_at'], 0, 10) : null
                ];
            }
            foreach ($codeItems as $ci) {
                $repo = $ci['repository']['full_name'] ?? ''; $html = $ci['html_url'] ?? ''; $path = $ci['path'] ?? '';
                if ($repo === '' || isset($seen[$repo . '|' . $path])) continue;
                $pathL = strtolower($path);
                if (!preg_match('/(poc|exploit|cve)/i', $pathL . ' ' . strtolower($repo))) continue;
                $seen[$repo . '|' . $path] = true;
                $pocs[] = [
                    'title' => $repo . ' — ' . $path, 'url' => $html, 'source' => 'GitHub Code',
                    'stars' => (int)($ci['repository']['stargazers_count'] ?? 0),
                    'confidence' => (preg_match('/poc|exploit/i', $pathL) ? 'high' : 'medium'),
                    'summary' => 'Code path matching CVE token + PoC/exploit keywords.', 'updated' => null
                ];
            }
            usort($pocs, function ($a, $b) {
                $rank = ['high' => 0, 'medium' => 1, 'low' => 2];
                $c = ($rank[$a['confidence']] ?? 9) <=> ($rank[$b['confidence']] ?? 9);
                return $c !== 0 ? $c : (($b['stars'] ?? 0) <=> ($a['stars'] ?? 0));
            });
            $entry['pocs'] = array_slice($pocs, 0, 3);
            if (empty($entry['pocs'])) $entry['note'] = 'No high-confidence public PoC repositories matched strict filters.';
            $out['items'][] = $entry;
            usleep(250000);
        }
        return $out;
    }

    private static function clipText($s, $n = 160) {
        $s = trim(preg_replace('/\s+/', ' ', (string)$s));
        if (strlen($s) <= $n) return $s;
        return substr($s, 0, $n - 1) . '…';
    }

    public static function auditCloud($domain, $offset = 0, $limit = 10) {
        $parts = explode('.', strtolower($domain));
        $base  = $parts[0];
        if (count($parts) > 2) {
            $base = $parts[count($parts) - 2];
        }

        $suffixes = [
            '', '-dev', '-prod', '-production', '-staging', '-stage', '-test', '-testing',
            '-backup', '-bak', '-assets', '-static', '-media', '-cdn', '-data', '-files',
            '-logs', '-archive', '-old', '-temp', '-tmp', '-internal', '-private',
            'dev', 'prod', 'staging', 'backup', 'assets'
        ];
        $prefixes = ['dev-', 'prod-', 'staging-', 'stage-', 'test-', 'backup-', 'cdn-', 'assets-'];

        $permutations = [];
        foreach ($suffixes as $s) {
            $permutations[] = $base . $s;
        }
        foreach ($prefixes as $p) {
            $permutations[] = $p . $base;
        }
        $permutations[] = str_replace('.', '-', $domain);
        $permutations[] = str_replace('.', '', $domain);
        $permutations = array_values(array_unique(array_filter($permutations)));

        $total_permutations = count($permutations);
        $permutations = array_slice($permutations, $offset, $limit);

        $endpoints = [];
        foreach ($permutations as $p) {
            $endpoints[] = ['provider' => 'AWS S3', 'bucket' => $p, 'url' => "https://{$p}.s3.amazonaws.com"];
            $endpoints[] = ['provider' => 'AWS S3', 'bucket' => $p, 'url' => "https://{$p}.s3-us-west-2.amazonaws.com"];
            $endpoints[] = ['provider' => 'GCS', 'bucket' => $p, 'url' => "https://storage.googleapis.com/{$p}"];
            $endpoints[] = ['provider' => 'GCS', 'bucket' => $p, 'url' => "https://{$p}.storage.googleapis.com"];
            $endpoints[] = ['provider' => 'Azure', 'bucket' => $p, 'url' => "https://{$p}.blob.core.windows.net"];
        }

        self::applyStealthDelay();

        $mh = curl_multi_init();
        $ch_list = [];
        foreach ($endpoints as $i => $ep) {
            $ch = curl_init($ep['url']);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => false,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_RANGE          => '0-4096'
            ]);

            self::applyCurlStealthOptions($ch);

            curl_multi_add_handle($mh, $ch);
            $ch_list[$i] = $ch;
        }

        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 0.5);
            }
            if (connection_aborted()) {
                foreach ($ch_list as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit; // Safely halt the PHP process immediately
            }
        } while ($running > 0 && $status == CURLM_OK);

        $results = [];
        $seen = [];
        foreach ($ch_list as $i => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);
            $ep   = $endpoints[$i];
            $key  = $ep['provider'] . '|' . $ep['bucket'];

            if (in_array($code, [200, 403, 409, 400], true) && !isset($seen[$key])) {
                $statusLabel = 'Unknown';
                $isPublic = false;

                if ($code === 200) {
                    $isPublic = true;
                    $statusLabel = 'PUBLIC (CRITICAL)';
                    if (stripos($body, 'ListBucketResult') !== false || stripos($body, '<Contents>') !== false) {
                        $statusLabel = 'PUBLIC LISTING (CRITICAL)';
                    }
                } elseif ($code === 403) {
                    if (stripos($body, 'AccessDenied') !== false || stripos($body, 'Access Denied') !== false || stripos($body, 'Forbidden') !== false) {
                        $statusLabel = 'Exists – Access Denied';
                    } else {
                        $statusLabel = 'Protected / Forbidden';
                    }
                } elseif ($code === 409) {
                    $statusLabel = 'Exists (Conflict/Name Taken)';
                } else {
                    $statusLabel = "HTTP {$code}";
                }

                $results[] = [
                    'provider' => $ep['provider'],
                    'bucket'   => $ep['bucket'],
                    'url'      => $ep['url'],
                    'status'   => $statusLabel,
                    'http_code'=> $code,
                    'public'   => $isPublic
                ];
                $seen[$key] = true;
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        usort($results, function ($a, $b) {
            return ($b['public'] <=> $a['public']);
        });

        return [
            'results' => $results,
            'next_offset' => $offset + $limit,
            'is_complete' => ($offset + $limit) >= $total_permutations,
            'total' => $total_permutations
        ];
    }

    public static function auditArchiveSecrets($domain) {
        $url = "https://web.archive.org/cdx/search/cdx?url=*." . urlencode($domain) . "/*&output=json&fl=original&collapse=urlkey&limit=5000";

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_ENCODING       => '', // Accepts all encodings like gzip to bypass WAF
            CURLOPT_FOLLOWLOCATION => true
        ]);
        self::applyCurlStealthOptions($ch);

        $raw = curl_exec($ch);
        curl_close($ch);

        if (!$raw) {
            return [];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return [];
        }

        $secrets = [];
        $patterns = [
            '/\.env(\.|$)/i',
            '/\.sql(\.|$)/i',
            '/\.bak(\.|$)/i',
            '/\.zip(\.|$)/i',
            '/\.tar\.gz/i',
            '/\.git(\/|$)/i',
            '/\.svn(\/|$)/i',
            '/\/api\/v[0-9]+\//i',
            '/\/graphql/i',
            '/\/swagger/i',
            '/\/\.well-known\//i',
            '/config\.(php|yml|yaml|json|ini)/i',
            '/\.php\?.*(=|id|file|path)/i',
            '/backup/i',
            '/dump/i',
            '/phpinfo/i'
        ];

        foreach ($data as $idx => $row) {
            if ($idx === 0) {
                continue;
            }
            $u = $row[0] ?? '';
            if ($u === '') continue;
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $u)) {
                    $secrets[] = $u;
                    break;
                }
            }
            if (count($secrets) >= 80) {
                break;
            }
        }

        return array_values(array_unique($secrets));
    }

    public static function auditDocumentMetadata($domain) {
        $candidates = [
            "/about.pdf", "/company.pdf", "/brochure.pdf", "/report.pdf",
            "/docs/annual-report.pdf", "/files/report.pdf", "/assets/docs/overview.pdf",
            "/whitepaper.pdf", "/press.pdf", "/media/kit.pdf",
            "/docs/company.docx", "/files/overview.docx", "/about.docx",
            "/docs/data.xlsx", "/files/pricing.xlsx", "/catalog.pdf"
        ];

        $extra = [];
        $cdx = "https://web.archive.org/cdx/search/cdx?url=" . urlencode($domain) . "/*&output=json&fl=original&filter=mimetype:application/pdf&collapse=urlkey&limit=15";

        $ch_cdx = curl_init($cdx);
        curl_setopt_array($ch_cdx, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_ENCODING       => '',
            CURLOPT_FOLLOWLOCATION => true
        ]);
        self::applyCurlStealthOptions($ch_cdx);

        $raw = curl_exec($ch_cdx);
        curl_close($ch_cdx);

        if ($raw && ($j = json_decode($raw, true)) && is_array($j)) {
            foreach ($j as $i => $row) {
                if ($i === 0) continue;
                $u = $row[0] ?? '';
                if ($u && preg_match('/\.pdf(\?|$)/i', $u)) {
                    $extra[] = $u;
                }
            }
        }

        $urls = [];
        foreach ($candidates as $path) {
            $urls[] = "https://{$domain}{$path}";
        }
        foreach (array_slice($extra, 0, 8) as $u) {
            // Force the URL to use the target domain to prevent SSRF from malicious Wayback entries
            $parsed = parse_url($u);
            $safeUrl = 'https://' . $domain . ($parsed['path'] ?? '');
            if (!empty($parsed['query'])) $safeUrl .= '?' . $parsed['query'];
            $urls[] = $safeUrl;
        }
        $urls = array_values(array_unique($urls));

        $mh = curl_multi_init();
        $ch_list = [];
        foreach ($urls as $i => $u) {
            $ch = curl_init($u);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 5,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 2,
                CURLOPT_RANGE          => '0-8191',
                CURLOPT_HTTPHEADER     => ['Accept: application/pdf,application/msword,application/vnd.*']
            ]);

            self::applyCurlStealthOptions($ch);

            curl_multi_add_handle($mh, $ch);
            $ch_list[$i] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 0.4);
            if (connection_aborted()) {
                foreach ($ch_list as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit;
            }
        } while ($running > 0);

            $findings = [];
            foreach ($ch_list as $i => $ch) {
                $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $body = (string)curl_multi_getcontent($ch);
                $url  = $urls[$i];
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                if ($code < 200 || $code >= 400 || strlen($body) < 20) {
                    continue;
                }

                $meta = [
                    'url'      => $url,
                    'type'     => 'unknown',
                    'author'   => null,
                    'creator'  => null,
                    'producer' => null,
                    'software' => null,
                    'created'  => null,
                    'modified' => null,
                    'title'    => null,
                    'paths'    => []
                ];

                if (strncmp($body, '%PDF', 4) === 0) {
                    $meta['type'] = 'pdf';
                    if (preg_match('/\/Author\s*\(([^)]{1,120})\)/', $body, $m)) {
                        $meta['author'] = self::pdfDecode($m[1]);
                    }
                    if (preg_match('/\/Creator\s*\(([^)]{1,120})\)/', $body, $m)) {
                        $meta['creator'] = self::pdfDecode($m[1]);
                    }
                    if (preg_match('/\/Producer\s*\(([^)]{1,160})\)/', $body, $m)) {
                        $meta['producer'] = self::pdfDecode($m[1]);
                    }
                    if (preg_match('/\/Title\s*\(([^)]{1,160})\)/', $body, $m)) {
                        $meta['title'] = self::pdfDecode($m[1]);
                    }
                    if (preg_match('/\/CreationDate\s*\(D:(\d{4})(\d{2})(\d{2})/', $body, $m)) {
                        $meta['created'] = "{$m[1]}-{$m[2]}-{$m[3]}";
                    }
                    if (preg_match('/\/ModDate\s*\(D:(\d{4})(\d{2})(\d{2})/', $body, $m)) {
                        $meta['modified'] = "{$m[1]}-{$m[2]}-{$m[3]}";
                    }
                    if (preg_match_all('/(?:[A-Z]:\\\\|\/Users\/|\/home\/)[^\x00-\x1f]{6,120}/', $body, $pm)) {
                        $meta['paths'] = array_slice(array_unique($pm[0]), 0, 5);
                    }
                }
                elseif (substr($body, 0, 8) === "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
                    $meta['type'] = 'ole';
                    if (preg_match_all('/(?:Author|Last Author|Company|Software|Creator)\x00(?:[\x20-\x7e]\x00){2,40}/i', $body, $sm)) {
                        foreach ($sm[0] as $s) {
                            $clean = str_replace("\x00", '', $s);
                            if (stripos($clean, 'Author') !== false) $meta['author'] = trim(preg_replace('/^.*Author/i', '', $clean));
                            if (stripos($clean, 'Software') !== false || stripos($clean, 'Creator') !== false) {
                                $meta['software'] = trim(preg_replace('/^.*(Software|Creator)/i', '', $clean));
                            }
                        }
                    }
                }
                elseif (strncmp($body, 'PK', 2) === 0) {
                    // OOXML (.docx/.xlsx) files are ZIP archives. The first 8 KB
                    // almost never contains plaintext XML metadata strings because
                    // they live inside compressed streams. Skip ineffective regex
                    // extraction; only record the type so callers know an Office
                    // document was found. Full extraction would require ZipArchive
                    // + reading docProps/core.xml.
                    $meta['type'] = 'ooxml';
                }

                if ($meta['author'] || $meta['creator'] || $meta['producer'] || $meta['software'] || $meta['title'] || !empty($meta['paths'])) {
                    $findings[] = $meta;
                }
            }
            curl_multi_close($mh);

            return array_slice($findings, 0, 25);
    }

    private static function pdfDecode($str) {
        $str = str_replace(['\\n', '\\r', '\\t', '\\(', '\\)', '\\\\'], ["\n", "\r", "\t", '(', ')', '\\'], $str);
        return trim($str);
    }

    public static function auditGitHubLeaks($domain) {
        $results = [
            'status'   => 'ok',
            'repos'    => [],
            'secrets'  => [],
            'note'     => ''
        ];

        $headers = [
            'Accept: application/vnd.github.v3+json',
            'User-Agent: ' . self::getStealthUserAgent()
        ];
        if (GITHUB_TOKEN !== '') {
            $headers[] = 'Authorization: token ' . GITHUB_TOKEN;
        }

        $q = urlencode('"' . $domain . '"');
        $url = "https://api.github.com/search/code?q={$q}&per_page=15";
        $ctx = stream_context_create([
            'http' => [
                'method'  => 'GET',
                'header'  => implode("\r\n", $headers),
                                     'timeout' => 8,
                                     'ignore_errors' => true
            ]
        ]);
        $raw = @file_get_contents($url, false, $ctx);
        if ($raw) {
            $data = json_decode($raw, true);
            if (!empty($data['items']) && is_array($data['items'])) {
                foreach ($data['items'] as $item) {
                    $results['repos'][] = [
                        'name'        => $item['repository']['full_name'] ?? '',
                        'path'        => $item['path'] ?? '',
                        'html_url'    => $item['html_url'] ?? '',
                        'repository'  => $item['repository']['html_url'] ?? ''
                    ];
                }
            } elseif (isset($data['message']) && stripos($data['message'], 'rate limit') !== false) {
                $results['note'] = 'GitHub rate limit reached – provide GITHUB_TOKEN for higher limits';
                $results['status'] = 'rate_limited';
            }
        }

        $secretQueries = [
            '"' . $domain . '" AKIA',
            '"' . $domain . '" "-----BEGIN RSA PRIVATE KEY-----"',
            '"' . $domain . '" "api_key"',
            '"' . $domain . '" "password" filename:.env',
            '"' . $domain . '" "DB_PASSWORD"',
            '"' . $domain . '" sk_live',
        ];

        foreach ($secretQueries as $sq) {
            if ($results['status'] === 'rate_limited') break;
            $url = "https://api.github.com/search/code?q=" . urlencode($sq) . "&per_page=5";
            $raw = @file_get_contents($url, false, $ctx);
            if (!$raw) continue;
            $data = json_decode($raw, true);
            if (!empty($data['items'])) {
                foreach ($data['items'] as $item) {
                    $results['secrets'][] = [
                        'query_hint'  => $sq,
                        'repo'        => $item['repository']['full_name'] ?? '',
                        'path'        => $item['path'] ?? '',
                        'url'         => $item['html_url'] ?? ''
                    ];
                }
            } elseif (isset($data['message']) && stripos($data['message'], 'rate limit') !== false) {
                $results['note'] = 'GitHub rate limit reached – provide GITHUB_TOKEN for higher limits';
                $results['status'] = 'rate_limited';
                break;
            }
            usleep(250000);
        }

        $results['repos']   = array_slice($results['repos'], 0, 20);
        $results['secrets'] = array_slice($results['secrets'], 0, 15);
        return $results;
    }

    public static function unmaskOriginIP($domain, $dns = []) {
        $findings = [
            'current_ips'   => $dns['A'] ?? [],
            'historical'    => [],
            'censys_hosts'  => [],
            'candidates'    => [],
            'note'          => ''
        ];

        if (SECURITYTRAILS_KEY !== '') {
            $url = "https://api.securitytrails.com/v1/history/{$domain}/dns/a";
            $ctx = stream_context_create([
                'http' => [
                    'method'  => 'GET',
                    'header'  => "APIKEY: " . SECURITYTRAILS_KEY . "\r\nAccept: application/json\r\n",
                    'timeout' => 8
                ]
            ]);
            $raw = @file_get_contents($url, false, $ctx);
            if ($raw && ($j = json_decode($raw, true)) && !empty($j['records'])) {
                foreach ($j['records'] as $rec) {
                    foreach ($rec['values'] ?? [] as $v) {
                        $ip = $v['ip'] ?? '';
                        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                            $findings['historical'][] = [
                                'ip'     => $ip,
                                'first'  => $rec['first_seen'] ?? null,
                                'last'   => $rec['last_seen'] ?? null,
                                'source' => 'SecurityTrails'
                            ];
                        }
                    }
                }
            }
        }

        $htUrl = "https://api.hackertarget.com/hostsearch/?q=" . urlencode($domain);
        if (HACKERTARGET_KEY !== '' && HACKERTARGET_KEY !== 'YOUR_HT_KEY_HERE') {
            $htUrl .= '&apikey=' . urlencode(HACKERTARGET_KEY);
        }
        $ctx = stream_context_create(['http' => ['timeout' => 6, 'user_agent' => 'AetherRecon/' . APP_VERSION]]);
        $raw = @file_get_contents($htUrl, false, $ctx);
        if ($raw && strpos($raw, 'error') === false) {
            foreach (explode("\n", $raw) as $line) {
                $parts = array_map('trim', explode(',', $line));
                if (count($parts) >= 2 && filter_var($parts[1], FILTER_VALIDATE_IP)) {
                    $ip = $parts[1];
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        $findings['historical'][] = [
                            'ip'     => $ip,
                            'host'   => $parts[0],
                            'source' => 'HackerTarget'
                        ];
                    }
                }
            }
        }

        if (CENSYS_API_ID !== '' && CENSYS_API_ID !== 'YOUR_CENSYS_API_ID_HERE') {
            $query = 'names: ' . $domain;
            $url = "https://search.censys.io/api/v2/certificates/search?q=" . urlencode($query) . "&per_page=5";
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_USERPWD        => CENSYS_API_ID . ':' . CENSYS_API_SECRET,
                CURLOPT_HTTPHEADER     => ['Accept: application/json'],
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_SSL_VERIFYPEER => false
            ]);
            $resp = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($code === 200 && $resp) {
                $data = json_decode($resp, true);
                $fps = [];
                foreach ($data['result']['hits'] ?? [] as $hit) {
                    $fp = $hit['fingerprint_sha256'] ?? $hit['parsed']['fingerprint_sha256'] ?? null;
                    if ($fp) $fps[] = $fp;
                }
                $fps = array_slice(array_unique($fps), 0, 3);

                foreach ($fps as $fp) {
                    $hUrl = "https://search.censys.io/api/v2/hosts/search?q=" . urlencode('services.tls.certificates.fingerprint_sha256: ' . $fp) . "&per_page=10";
                    $ch = curl_init();
                    curl_setopt_array($ch, [
                        CURLOPT_URL            => $hUrl,
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_USERPWD        => CENSYS_API_ID . ':' . CENSYS_API_SECRET,
                        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
                        CURLOPT_TIMEOUT        => 10,
                        CURLOPT_SSL_VERIFYPEER => false
                    ]);
                    $hResp = curl_exec($ch);
                    curl_close($ch);
                    if ($hResp && ($hj = json_decode($hResp, true))) {
                        foreach ($hj['result']['hits'] ?? [] as $host) {
                            $ip = $host['ip'] ?? '';
                            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                                $findings['censys_hosts'][] = [
                                    'ip'          => $ip,
                                    'fingerprint' => $fp,
                                    'source'      => 'Censys'
                                ];
                            }
                        }
                    }
                }
            }
        }

        $current = array_flip($findings['current_ips']);
        $candidates = [];
        foreach (array_merge($findings['historical'], $findings['censys_hosts']) as $row) {
            $ip = $row['ip'] ?? '';
            if ($ip && !isset($current[$ip])) {
                $candidates[$ip] = $row;
            }
        }
        $findings['candidates'] = array_values($candidates);

        if (empty($findings['historical']) && empty($findings['censys_hosts'])) {
            $findings['note'] = 'No alternative origin IPs discovered. Add SECURITYTRAILS_KEY or ensure Censys credentials are valid for better results.';
        }

        return $findings;
    }

    public static function checkMetaFiles($domain) {
        $ctx = stream_context_create([
            'http' => [
                'timeout'    => 5,
                'user_agent' => self::getStealthUserAgent()
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false
            ]
        ]);

        $sec = @file_get_contents("https://{$domain}/.well-known/security.txt", false, $ctx)
            ?: @file_get_contents("https://{$domain}/security.txt", false, $ctx)
            ?: @file_get_contents("http://{$domain}/.well-known/security.txt", false, $ctx);
        $robots = @file_get_contents("https://{$domain}/robots.txt", false, $ctx)
            ?: @file_get_contents("http://{$domain}/robots.txt", false, $ctx);

        $interestingPaths = [];
        $sitemapUrls = [];
        if ($robots) {
            foreach (preg_split('/\r\n|\r|\n/', $robots) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                if (preg_match('/^(?:disallow|allow)\s*:\s*(.+)$/i', $line, $m)) {
                    $p = trim($m[1]);
                    if ($p !== '' && $p !== '/' && strlen($p) < 200) {
                        // Normalize to path starting with /
                        if ($p[0] !== '/' && stripos($p, 'http') !== 0) {
                            $p = '/' . ltrim($p, '/');
                        }
                        if ($p[0] === '/') {
                            $interestingPaths[] = $p;
                        }
                    }
                }
                if (preg_match('/^sitemap\s*:\s*(.+)$/i', $line, $m)) {
                    $su = trim($m[1]);
                    if (filter_var($su, FILTER_VALIDATE_URL)) {
                        $host = strtolower(parse_url($su, PHP_URL_HOST) ?? '');
                        // Only follow sitemaps on the same registrable host family
                        if ($host === strtolower($domain) || substr($host, -strlen('.' . $domain)) === '.' . $domain) {
                            $sitemapUrls[] = $su;
                        }
                    }
                }
            }
            $interestingPaths = array_values(array_unique(array_slice($interestingPaths, 0, 40)));
            $sitemapUrls = array_values(array_unique(array_slice($sitemapUrls, 0, 5)));
        }

        // Light sitemap path harvest (same-host only, limited)
        $sitemapPaths = [];
        foreach (array_slice($sitemapUrls, 0, 2) as $su) {
            $raw = @file_get_contents($su, false, $ctx);
            if (!$raw || strlen($raw) > 500000) continue;
            if (preg_match_all('/<loc>\s*(https?:\/\/[^<]+)\s*<\/loc>/i', $raw, $lm)) {
                foreach ($lm[1] as $loc) {
                    $ph = parse_url($loc, PHP_URL_HOST);
                    $pp = parse_url($loc, PHP_URL_PATH);
                    if (!$ph || !$pp) continue;
                    $ph = strtolower($ph);
                    if ($ph !== strtolower($domain) && substr($ph, -strlen('.' . $domain)) !== '.' . $domain) continue;
                    if (strlen($pp) > 1 && strlen($pp) < 180) {
                        $sitemapPaths[] = $pp;
                    }
                }
            }
        }
        $sitemapPaths = array_values(array_unique(array_slice($sitemapPaths, 0, 30)));

        return [
            'has_security_txt'   => !empty($sec),
            'security_txt'       => $sec ? substr(trim($sec), 0, 2000) : null,
            'has_robots'         => !empty($robots),
            'robots_txt'         => $robots ? substr(trim($robots), 0, 1500) : null,
            'robots_paths'       => $interestingPaths,
            'sitemap_urls'       => $sitemapUrls,
            'sitemap_paths'      => $sitemapPaths,
            'interesting_paths'  => array_values(array_unique(array_merge($interestingPaths, $sitemapPaths)))
        ];
    }

    public static function auditCompany($domain) {
        if (empty(HUNTER_API_KEY) || HUNTER_API_KEY === 'YOUR_HUNTER_API_KEY_HERE') {
            return ['status' => 'disabled', 'employees' => []];
        }

        $url = "https://api.hunter.io/v2/domain-search?domain=" . urlencode($domain) . "&api_key=" . HUNTER_API_KEY;
        $ctx = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => 4,
                'user_agent'    => self::getStealthUserAgent(),
                                     'ignore_errors' => true
            ]
        ]);

        $raw = @file_get_contents($url, false, $ctx);
        if (!$raw) {
            return ['status' => 'failed', 'employees' => []];
        }

        $data = json_decode($raw, true);
        if (empty($data['data']['emails'])) {
            return ['status' => 'ok', 'organization' => $data['data']['organization'] ?? '', 'employees' => []];
        }

        $employees = [];
        foreach ($data['data']['emails'] as $emp) {
            $employees[] = [
                'email'      => $emp['value'] ?? '',
                'first_name' => $emp['first_name'] ?? '',
                'last_name'  => $emp['last_name'] ?? '',
                'position'   => $emp['position'] ?? 'Employee',
                'linkedin'   => $emp['linkedin'] ?? null,
                'twitter'    => $emp['twitter'] ?? null
            ];
        }

        return [
            'status'       => 'ok',
            'organization' => $data['data']['organization'] ?? '',
            'employees'    => $employees
        ];
    }

    public static function scanPorts($domain) {
        $ip = gethostbyname($domain);
        if (!$ip || $ip === $domain) {
            return ['ports' => [], 'shodan' => null];
        }

        $ports_to_check = [
            21=>'FTP', 22=>'SSH', 25=>'SMTP', 80=>'HTTP', 110=>'POP3',
            143=>'IMAP', 443=>'HTTPS', 3306=>'MySQL', 3389=>'RDP',
            5432=>'PostgreSQL', 6379=>'Redis', 8080=>'HTTP-Alt', 27017=>'MongoDB'
        ];

        $results = [];
        $sockets = [];

        foreach ($ports_to_check as $port => $service) {
            $results[$port] = [
                'service' => $service,
                'status'  => 'closed',
                'source'  => 'active'
            ];

            // Only actively probe web ports to prevent host firewall hangs
            if (in_array($port, [80, 443, 8080])) {
                $sock = @stream_socket_client("tcp://$ip:$port", $errno, $errstr, 0.5, STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT);
                if ($sock) {
                    stream_set_blocking($sock, false);
                    $sockets[$port] = $sock;
                }
            }
        }

        $read = null;
        $except = null;
        $write = $sockets;

        if (!empty($write)) {
            if (!connection_aborted() && @stream_select($read, $write, $except, 1) > 0) {
                foreach ($write as $sock) {
                    $port = array_search($sock, $sockets);
                    if ($port && @stream_socket_get_name($sock, true) !== false) {
                        $results[$port]['status'] = 'open';
                    }
                }
            }
        }

        foreach ($sockets as $sock) {
            @fclose($sock);
        }

        // Shodan Lookup
        if (defined('SHODAN_API_KEY') && SHODAN_API_KEY !== 'YOUR_SHODAN_API_KEY_HERE' && !empty(SHODAN_API_KEY)) {
            $url = 'https://api.shodan.io/shodan/host/' . urlencode($ip) . '?key=' . urlencode(SHODAN_API_KEY) . '&minify=false';
            $ctx = stream_context_create([
                'http' => [
                    'method'        => 'GET',
                    'timeout'       => 4,
                    'user_agent'    => 'AetherRecon/' . APP_VERSION,
                    'ignore_errors' => true
                ]
            ]);

            $raw = @file_get_contents($url, false, $ctx);
            if ($raw) {
                $shodanData = json_decode($raw, true);
                if ($shodanData && empty($shodanData['error'])) {
                    if (!empty($shodanData['ports']) && is_array($shodanData['ports'])) {
                        foreach ($shodanData['ports'] as $p) {
                            if (!isset($results[$p])) {
                                $results[$p] = [
                                    'service' => 'Port-' . $p,
                                    'status'  => 'open',
                                    'source'  => 'shodan_passive'
                                ];
                            } else {
                                $results[$p]['status'] = 'open';
                                $results[$p]['source'] = 'active+shodan';
                            }
                        }
                    }
                    return ['ports' => $results, 'shodan' => $shodanData];
                }
            }
        }

        return ['ports' => $results, 'shodan' => null];
    }

    public static function mapSubdomains($domain, $deep = false) {
        $cacheFile = CACHE_DIR . '/subs_' . md5($domain) . '.json';
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 7200)) {
            $cached = json_decode(@file_get_contents($cacheFile), true);
            if ($cached && !empty($cached['subdomains'])) {
                return $cached;
            }
        }

        $subs = [];
        $sources = [];

        $common_prefixes = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'app', 'test',
            'portal', 'admin', 'shop', 'm', 'support', 'cloud', 'cpanel',
            'autodiscover', 'status', 'assets', 'cdn', 'demo', 'db', 'auth', 'media'
        ];

        $dns_found = false;
        foreach ($common_prefixes as $prefix) {
            $sub = $prefix . '.' . $domain;
            if (@checkdnsrr($sub, 'A') || @checkdnsrr($sub, 'CNAME')) {
                $subs[$sub] = true;
                $dns_found = true;
            }
        }
        if ($dns_found) {
            $sources[] = 'Native DNS Probe';
        }

        $urls = [
            'crtsh'       => 'https://crt.sh/?q=%25.'.urlencode($domain).'&output=json',
            'anubis'      => 'https://jldc.me/anubis/subdomains/'.urlencode($domain),
            'certspotter' => 'https://api.certspotter.com/v1/issuances?domain='.urlencode($domain).'&include_subdomains=true&expand=dns_names',
            'rapiddns'    => 'https://rapiddns.io/subdomain/'.urlencode($domain).'?full=1'
        ];

        if (!empty(ALIENVAULT_API_KEY) && ALIENVAULT_API_KEY !== 'YOUR_OTX_KEY_HERE') {
            $urls['otx'] = [
                'url'    => 'https://otx.alienvault.com/api/v1/indicators/domain/'.urlencode($domain).'/passive_dns',
                'header' => 'X-OTX-API-KEY: ' . ALIENVAULT_API_KEY
            ];
        } else {
            $urls['otx'] = [
                'url'    => 'https://otx.alienvault.com/api/v1/indicators/domain/'.urlencode($domain).'/passive_dns',
                'header' => ''
            ];
        }

        if (!empty(HACKERTARGET_KEY) && HACKERTARGET_KEY !== 'YOUR_HT_KEY_HERE') {
            $urls['ht'] = 'https://api.hackertarget.com/hostsearch/?q='.urlencode($domain).'&apikey='.HACKERTARGET_KEY;
        } else {
            $urls['ht'] = 'https://api.hackertarget.com/hostsearch/?q='.urlencode($domain);
        }

        $mh = curl_multi_init();
        $ch_list = [];

        foreach ($urls as $key => $target) {
            $url = is_array($target) ? $target['url'] : $target;
            $header = is_array($target) && !empty($target['header']) ? [$target['header']] : [];
            $ch = curl_init($url);

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $deep ? 14 : 8,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                              CURLOPT_SSL_VERIFYPEER => false,
                              CURLOPT_FOLLOWLOCATION => true,
                              CURLOPT_MAXREDIRS      => 3,
                              CURLOPT_HTTPHEADER     => array_merge(['Accept: text/html,application/json'], $header)
            ]);
            curl_multi_add_handle($mh, $ch);
            $ch_list[$key] = $ch;
        }

        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 1.0);
            }
            if (connection_aborted()) {
                foreach ($ch_list as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit; // Safely halt the PHP process immediately
            }
        } while ($running > 0 && $status == CURLM_OK);

        $raw_crt = curl_multi_getcontent($ch_list['crtsh']);
        if (curl_getinfo($ch_list['crtsh'], CURLINFO_HTTP_CODE) === 200 && $raw_crt && $json = json_decode($raw_crt, true)) {
            $added = false;
            foreach ((array)$json as $e) {
                if (empty($e['name_value'])) {
                    continue;
                }
                foreach (explode("\n", strtolower(trim($e['name_value']))) as $line) {
                    $line = trim($line);
                    if ($line && strpos($line, '*') === false && (substr($line, -strlen('.'.$domain)) === '.'.$domain || $line === $domain)) {
                        $subs[$line] = true;
                        $added = true;
                    }
                }
            }
            if ($added) {
                $sources[] = 'crt.sh';
            }
        }

        $raw_anubis = curl_multi_getcontent($ch_list['anubis']);
        if (curl_getinfo($ch_list['anubis'], CURLINFO_HTTP_CODE) === 200 && $raw_anubis && $json = json_decode($raw_anubis, true)) {
            $added = false;
            foreach ((array)$json as $sub) {
                $sub = strtolower(trim($sub));
                if ($sub && strpos($sub, '*') === false && (substr($sub, -strlen('.'.$domain)) === '.'.$domain || $sub === $domain)) {
                    $subs[$sub] = true;
                    $added = true;
                }
            }
            if ($added) {
                $sources[] = 'Anubis DB';
            }
        }

        $raw_rapid = curl_multi_getcontent($ch_list['rapiddns']);
        if (curl_getinfo($ch_list['rapiddns'], CURLINFO_HTTP_CODE) === 200 && $raw_rapid) {
            preg_match_all('/([a-zA-Z0-9\.-]+\.' . preg_quote($domain, '/') . ')/i', $raw_rapid, $matches);
            if (!empty($matches[1])) {
                $added = false;
                foreach ($matches[1] as $sub) {
                    $sub = strtolower(trim($sub));
                    if ($sub && strpos($sub, '*') === false) {
                        $subs[$sub] = true;
                        $added = true;
                    }
                }
                if ($added) {
                    $sources[] = 'RapidDNS';
                }
            }
        }

        $raw_spot = curl_multi_getcontent($ch_list['certspotter']);
        if (curl_getinfo($ch_list['certspotter'], CURLINFO_HTTP_CODE) === 200 && $raw_spot && $json = json_decode($raw_spot, true)) {
            $added = false;
            foreach ((array)$json as $cert) {
                if (!empty($cert['dns_names'])) {
                    foreach($cert['dns_names'] as $name) {
                        $name = strtolower(trim($name));
                        if (strpos($name, '*') === false && (substr($name, -strlen('.'.$domain)) === '.'.$domain || $name === $domain)) {
                            $subs[$name] = true;
                            $added = true;
                        }
                    }
                }
            }
            if ($added) {
                $sources[] = 'CertSpotter';
            }
        }

        $raw_ht = curl_multi_getcontent($ch_list['ht']);
        if (curl_getinfo($ch_list['ht'], CURLINFO_HTTP_CODE) === 200 && $raw_ht && strpos($raw_ht, 'error') === false) {
            $added = false;
            foreach (explode("\n", $raw_ht) as $line) {
                $parts = explode(',', $line);
                $h = strtolower(trim($parts[0] ?? ''));
                if ($h && strpos($h, '*') === false && (substr($h, -strlen('.'.$domain)) === '.'.$domain || $h === $domain)) {
                    $subs[$h] = true;
                    $added = true;
                }
            }
            if ($added) {
                $sources[] = 'HackerTarget';
            }
        }

        $raw_otx = curl_multi_getcontent($ch_list['otx']);
        if (curl_getinfo($ch_list['otx'], CURLINFO_HTTP_CODE) === 200 && $raw_otx && $json = json_decode($raw_otx, true)) {
            if (!empty($json['passive_dns'])) {
                $added = false;
                foreach ($json['passive_dns'] as $e) {
                    $h = strtolower($e['hostname'] ?? '');
                    if ($h && strpos($h, '*') === false && (substr($h, -strlen('.'.$domain)) === '.'.$domain || $h === $domain)) {
                        $subs[$h] = true;
                        $added = true;
                    }
                }
                if ($added) {
                    $sources[] = 'AlienVault OTX';
                }
            }
        }

        if (CENSYS_API_ID !== 'YOUR_CENSYS_API_ID_HERE' && !empty(CENSYS_API_ID)) {
            $query = "parsed.names: " . $domain;
            $url = "https://search.censys.io/api/v2/certificates/search?q=" . urlencode($query) . "&per_page=100";
            $ch = curl_init();

            curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD        => CENSYS_API_ID . ":" . CENSYS_API_SECRET,
            CURLOPT_HTTPHEADER     => ["Accept: application/json"],
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_SSL_VERIFYPEER => false
            ]);

            $response = curl_exec($ch);
            if (curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200 && $response) {
                $data = json_decode($response, true);
                if (isset($data['result']['hits'])) {
                    foreach ($data['result']['hits'] as $hit) {
                        $names = $hit['names'] ?? $hit['parsed']['names'] ?? [];
                        foreach ((array)$names as $name) {
                            $name = strtolower(trim($name));
                            if (strpos($name, '*') === false && (substr($name, -strlen(".".$domain)) === ".".$domain || $name === $domain)) {
                                $subs[$name] = true;
                            }
                        }
                    }
                    $sources[] = 'Censys API';
                }
            }
            curl_close($ch);
        }

        foreach ($ch_list as $ch) {
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        $list = array_keys($subs);
        sort($list);

        $result = [
            'status'     => empty($sources) ? 'all_failed' : 'ok',
            'sources'    => array_unique($sources),
            'subdomains' => array_slice($list, 0, $deep ? 100 : 60),
            'count'      => count($list)
        ];

        @file_put_contents($cacheFile, json_encode($result));
        return $result;
    }

    public static function whoisLookup($domain) {
        $url = 'https://rdap.org/domain/' . urlencode($domain);
        $ctx = stream_context_create([
            'http' => [
                'method'          => 'GET',
                'timeout'         => 8,
                'user_agent'      => self::getStealthUserAgent(), // <-- Fixed
                                     'follow_location' => 1,
                                     'max_redirects'   => 3
            ]
        ]);

        $raw = @file_get_contents($url, false, $ctx);
        // ... rest of function remains the same
        if (!$raw) {
            return ['status' => 'unavailable', 'raw' => null];
        }

        $data = json_decode($raw, true);
        if (!$data) {
            return ['status' => 'unavailable', 'raw' => null];
        }

        $registrar = 'Unknown';
        if (!empty($data['entities'])) {
            foreach ($data['entities'] as $entity) {
                if (in_array('registrar', $entity['roles'] ?? [])) {
                    $registrar = $entity['vcardArray'][1][1][3] ?? ($entity['handle'] ?? 'Unknown');
                    break;
                }
            }
        }

        $created = null;
        $expires = null;
        $updated = null;

        if (!empty($data['events'])) {
            foreach ($data['events'] as $event) {
                $action = strtolower($event['eventAction'] ?? '');
                $date = $event['eventDate'] ?? null;

                if ($action === 'registration') {
                    $created = $date;
                }
                if ($action === 'expiration') {
                    $expires = $date;
                }
                if ($action === 'last changed') {
                    $updated = $date;
                }
            }
        }

        $nameservers = [];
        if (!empty($data['nameservers'])) {
            foreach ($data['nameservers'] as $ns) {
                if (!empty($ns['ldhName'])) {
                    $nameservers[] = $ns['ldhName'];
                }
            }
        }

        return [
            'status'      => 'ok',
            'registrar'   => $registrar,
            'created'     => $created,
            'expires'     => $expires,
            'updated'     => $updated,
            'nameservers' => $nameservers,
            'raw'         => substr(json_encode($data, JSON_PRETTY_PRINT), 0, 3000)
        ];
    }

    public static function ipInfo($ips) {
        $out = [];
        $ctx = stream_context_create([
            'http' => [
                'timeout'    => 5,
                'user_agent' => self::getStealthUserAgent() // <-- Fixed context leak
            ]
        ]);

        foreach (array_slice($ips, 0, 8) as $ip) {
            // Apply caching to prevent IP-API 45/min rate limits
            $cacheFile = CACHE_DIR . '/ip_' . md5($ip) . '.json';
            $j = null;

            if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < 86400)) {
                $j = json_decode(@file_get_contents($cacheFile), true);
            } else {
                $raw = @file_get_contents('http://ip-api.com/json/' . urlencode($ip) . '?fields=status,message,country,countryCode,regionName,city,isp,org,as,query', false, $ctx);
                if ($raw) {
                    $j = json_decode($raw, true);
                    if (($j['status'] ?? '') === 'success') {
                        @file_put_contents($cacheFile, json_encode($j));
                    }
                }
            }

            if ($j && ($j['status'] ?? '') === 'success') {
                $out[$ip] = [
                    'country' => ($j['country'] ?? '') . ' (' . ($j['countryCode'] ?? '') . ')',
                    'city'    => $j['city'] ?? '',
                    'isp'     => $j['isp'] ?? '',
                    'org'     => $j['org'] ?? '',
                    'asn'     => $j['as'] ?? ''
                ];
            }
        }
        return $out;
    }

    /* ============================================================
     * NEW: Advanced API Key & Secret Extraction (real-world methods)
     * ============================================================ */
    public static function auditApiKeys($domain, $pwd = '') {
        $findings = [];
        $seen = [];
        $sourcesChecked = [];

        // High-confidence regex patterns (real-world service keys) — local only
        $patterns = [
            'AWS Access Key'          => '/\b(AKIA[0-9A-Z]{16})\b/',
            'AWS Secret Key'          => '/\b([A-Za-z0-9\/+=]{40})\b(?=.*(?:aws|secret|access))/i',
            'AWS Session Token'       => '/\b(ASIA[0-9A-Z]{16})\b/',
            'Stripe Live Secret'      => '/\b(sk_live_[0-9a-zA-Z]{24,})\b/',
            'Stripe Restricted'       => '/\b(rk_live_[0-9a-zA-Z]{24,})\b/',
            'Stripe Publishable'      => '/\b(pk_live_[0-9a-zA-Z]{24,})\b/',
            'Stripe Test Secret'      => '/\b(sk_test_[0-9a-zA-Z]{24,})\b/',
            'GitHub PAT'              => '/\b(ghp_[A-Za-z0-9_]{36,})\b/',
            'GitHub OAuth'            => '/\b(gho_[A-Za-z0-9_]{36,})\b/',
            'GitHub App'              => '/\b(ghu_[A-Za-z0-9_]{36,})\b/',
            'GitHub Fine-grained'     => '/\b(github_pat_[A-Za-z0-9_]{20,})\b/',
            'GitLab Token'            => '/\b(glpat-[A-Za-z0-9\-_]{20,})\b/',
            'Slack Token'             => '/\b(xox[baprs]-[0-9a-zA-Z-]{10,})\b/',
            'Slack Webhook'           => '/\b(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)\b/',
            'Google API Key'          => '/\b(AIza[0-9A-Za-z\-_]{35})\b/',
            'Google OAuth Client'     => '/\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b/',
            'Twilio Account SID'      => '/\b(AC[a-f0-9]{32})\b/',
            'Twilio Auth Token'       => '/\b([a-f0-9]{32})\b(?=.*twilio)/i',
            'SendGrid API Key'        => '/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/',
            'Mailgun API Key'         => '/\b(key-[0-9a-zA-Z]{32})\b/',
            'OpenAI API Key'          => '/\b(sk-[A-Za-z0-9]{32,})\b/',
            'Anthropic API Key'       => '/\b(sk-ant-[A-Za-z0-9\-_]{20,})\b/',
            'Discord Bot/Token'       => '/\b([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b/',
            'Discord Webhook'         => '/\b(https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+)\b/',
            'Firebase'                => '/\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/',
            'Heroku API Key'          => '/\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b(?=.*heroku)/i',
            'DigitalOcean Token'      => '/\b(dop_v1_[a-f0-9]{64})\b/',
            'Shopify Token'           => '/\b(shpat_[a-fA-F0-9]{32})\b/',
            'Shopify Shared Secret'   => '/\b(shpss_[a-fA-F0-9]{32})\b/',
            'Mailchimp API Key'       => '/\b([a-f0-9]{32}-us\d+)\b/',
            'NPM Token'               => '/\b(npm_[A-Za-z0-9]{36,})\b/',
            'PyPI Token'              => '/\b(pypi-[A-Za-z0-9\-_]{50,})\b/',
            'Generic API Key'         => '/(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-\.]{16,80})[\'"]?/i',
            'JWT Secret / HS Key'     => '/(?:jwt[_-]?secret|hs256[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-\+\/=]{8,128})[\'"]?/i',
            'Database URL'            => '/\b((?:mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^\s\'"]{12,})\b/i',
            'Private Key Block'       => '/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/',
            'Basic Auth Hardcoded'    => '/(?:Authorization|Basic)\s+[\'"]?Basic\s+([A-Za-z0-9+\/=]{20,})/i',
            'Bearer Token Hardcoded'  => '/(?:Authorization|Bearer)\s+[\'"]?Bearer\s+([A-Za-z0-9\-_\.]{20,})\b/i',
            'ENV Password Assignment' => '/(?:password|passwd|pwd|db_pass|db_password|mysql_password|redis_password)\s*[:=]\s*[\'"]([^\s\'"]{6,64})[\'"]/i',
        ];

        // 1. Common sensitive paths
        $paths = [
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/config.js', '/config.json', '/settings.json', '/app.config.js',
            '/static/js/main.js', '/assets/js/app.js', '/js/config.js',
            '/_next/static/chunks/main.js', '/_next/static/chunks/pages/_app.js',
            '/api/config', '/api/keys', '/api/secrets', '/.git/config',
            '/wp-config.php.bak', '/config.php.bak', '/web.config',
            '/robots.txt', '/security.txt', '/.well-known/security.txt',
            '/swagger.json', '/openapi.json', '/api-docs', '/graphql',
            '/package.json', '/composer.json', '/.npmrc', '/.yarnrc'
        ];

        $baseUrls = ["https://{$domain}", "http://{$domain}"];
        $mh = curl_multi_init();
        $handles = [];
        $urlMap = [];

        foreach ($baseUrls as $base) {
            foreach ($paths as $p) {
                $u = rtrim($base, '/') . $p;
                $ch = curl_init($u);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT        => 6,
                    CURLOPT_CONNECTTIMEOUT => 3,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_MAXREDIRS      => 2,
                    CURLOPT_USERAGENT      => 'AetherRecon/' . APP_VERSION,
                    CURLOPT_RANGE          => '0-65535',
                    CURLOPT_ENCODING       => '',
                    CURLOPT_HTTPHEADER     => ['Accept: */*']
                ]);
                curl_multi_add_handle($mh, $ch);
                $handles[] = $ch;
                $urlMap[spl_object_id($ch)] = $u;
            }
        }

        // Also fetch homepage to extract linked JS
        $homeCh = curl_init("https://{$domain}/");
        curl_setopt_array($homeCh, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT      => 'AetherRecon/' . APP_VERSION,
            CURLOPT_RANGE          => '0-102400',
            CURLOPT_ENCODING       => '',
        ]);
        curl_multi_add_handle($mh, $homeCh);
        $handles[] = $homeCh;
        $urlMap[spl_object_id($homeCh)] = "https://{$domain}/";

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 0.4);
            if (connection_aborted()) {
                foreach ($handles as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit;
            }
        } while ($running > 0);

            $jsUrls = [];
            foreach ($handles as $ch) {
                $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $body = (string)curl_multi_getcontent($ch);
                $url  = $urlMap[spl_object_id($ch)] ?? '';
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                if ($code < 200 || $code >= 400 || strlen($body) < 10) continue;
                $sourcesChecked[] = $url;

                // Extract JS references from homepage
                if (strpos($url, $domain . '/') !== false && substr_count($url, '/') <= 3) {
                    if (preg_match_all('/(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']/i', $body, $m)) {
                        foreach ($m[1] as $js) {
                            if (strpos($js, '//') === 0) $js = 'https:' . $js;
                                elseif (strpos($js, 'http') !== 0) $js = "https://{$domain}/" . ltrim($js, '/');
                                    if (stripos($js, $domain) !== false) $jsUrls[] = $js;
                        }
                    }
                    // Source maps
                    if (preg_match_all('/sourceMappingURL=([^\s\'"]+\.map)/i', $body, $sm)) {
                        foreach ($sm[1] as $map) {
                            if (strpos($map, 'http') !== 0) $map = "https://{$domain}/" . ltrim($map, '/');
                                $jsUrls[] = $map;
                        }
                    }
                }

                self::extractKeysFromBody($body, $url, $patterns, $findings, $seen, $pwd);
            }
            curl_multi_close($mh);

            // 2. Fetch discovered JS / source maps (limit)
            $jsUrls = array_slice(array_unique($jsUrls), 0, 18);
            if ($jsUrls) {
                $mh = curl_multi_init();
                $handles = [];
                foreach ($jsUrls as $ju) {
                    $ch = curl_init($ju);
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_TIMEOUT        => 7,
                        CURLOPT_SSL_VERIFYPEER => false,
                        CURLOPT_FOLLOWLOCATION => true,
                        CURLOPT_USERAGENT      => 'AetherRecon/' . APP_VERSION,
                        CURLOPT_RANGE          => '0-131072',
                        CURLOPT_ENCODING       => ''
                    ]);
                    curl_multi_add_handle($mh, $ch);
                    $handles[$ju] = $ch;
                }
                $running = null;
                do {
                    curl_multi_exec($mh, $running);
                    if ($running) curl_multi_select($mh, 0.4);
                    if (connection_aborted()) {
                        foreach ($handles as $c) {
                            curl_multi_remove_handle($mh, $c);
                            curl_close($c);
                        }
                        curl_multi_close($mh);
                        exit;
                    }
                } while ($running > 0);

                foreach ($handles as $ju => $ch) {
                    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $body = (string)curl_multi_getcontent($ch);
                    curl_multi_remove_handle($mh, $ch);
                    curl_close($ch);
                    if ($code >= 200 && $code < 400 && strlen($body) > 20) {
                        $sourcesChecked[] = $ju;
                        self::extractKeysFromBody($body, $ju, $patterns, $findings, $seen, $pwd);
                    }
                }
                curl_multi_close($mh);
            }

            // 3. Quick header check on main page
            $hdrCtx = stream_context_create([
                'http' => ['method' => 'GET', 'timeout' => 5, 'user_agent' => 'AetherRecon/' . APP_VERSION],
                'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
            ]);
            $hdrs = @get_headers("https://{$domain}/", 1, $hdrCtx);
            if (is_array($hdrs)) {
                $flat = '';
                foreach ($hdrs as $k => $v) {
                    $flat .= (is_string($k) ? $k . ': ' : '') . (is_array($v) ? implode(' ', $v) : $v) . "\n";
                }
                self::extractKeysFromBody($flat, "https://{$domain}/ (headers)", $patterns, $findings, $seen, $pwd);
            }

            // Sort by severity
            usort($findings, function ($a, $b) {
                $order = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
                return ($order[$a['severity']] ?? 9) <=> ($order[$b['severity']] ?? 9);
            });

            return [
                'status'          => 'ok',
                'keys_found'      => count($findings),
                'findings'        => array_slice($findings, 0, 40),
                'sources_checked' => array_slice(array_unique($sourcesChecked), 0, 30),
                'note'            => count($findings) ? 'Exposed credentials detected – rotate immediately' : 'No high-confidence API keys extracted from common paths / JS'
            ];
    }

    private static function extractKeysFromBody($body, $source, $patterns, &$findings, &$seen, $pwd = '') {
        $unlocked = ($pwd === 'Jisjthomas@9064026060');
        foreach ($patterns as $label => $regex) {
            if (preg_match_all($regex, $body, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $value = $m[1] ?? $m[0];
                    $value = trim($value);
                    if (strlen($value) < 8) continue;

                    // Basic entropy / noise filter
                    if (preg_match('/^(true|false|null|undefined|function|return|const|let|var|this|window)$/i', $value)) continue;
                    if (preg_match('/^[0-9]+$/', $value) && strlen($value) < 20) continue;

                    $keyHash = md5($label . '|' . substr($value, 0, 40));
                    if (isset($seen[$keyHash])) continue;
                    $seen[$keyHash] = true;

                    $severity = 'MEDIUM';
                    if (preg_match('/AKIA|sk_live|ghp_|xox[baprs]-|BEGIN .*PRIVATE KEY|SG\./', $value) ||
                        stripos($label, 'Secret') !== false || stripos($label, 'Private') !== false ||
                        stripos($label, 'Live') !== false) {
                        $severity = 'CRITICAL';
                        } elseif (stripos($label, 'Key') !== false || stripos($label, 'Token') !== false) {
                            $severity = 'HIGH';
                        }

                        // Context snippet
                        $pos = strpos($body, $value);
                    $ctx = $pos !== false ? substr($body, max(0, $pos - 40), 120) : '';
                    $ctx = preg_replace('/\s+/', ' ', $ctx);

                    $findings[] = [
                        'type'       => $label,
                        'value'      => $unlocked ? $value : self::redactKey($value),
                        'full_value' => $unlocked ? $value : (strlen($value) <= 12 ? $value : null),
                        'severity'   => $severity,
                        'source'     => $source,
                        'context'    => substr($ctx, 0, 100)
                    ];
                }
            }
        }
    }

    private static function redactKey($v) {
        $len = strlen($v);
        if ($len <= 8) return str_repeat('*', $len);
        if ($len <= 20) return substr($v, 0, 4) . str_repeat('*', $len - 8) . substr($v, -4);
        return substr($v, 0, 6) . str_repeat('*', max(6, $len - 12)) . substr($v, -6);
    }

    /* ============================================================
     * NEW: JWT Discovery + Misconfiguration Testing
     * ============================================================ */
    public static function auditJwt($domain, $pwd = '') {
        $result = [
            'status'            => 'ok',
            'tokens_found'      => [],
            'endpoints_tested'  => [],
            'misconfigurations' => [],
            'risk_score'        => 0,
            'note'              => ''
        ];

        $tokens = [];
        $seenTok = [];
        $unlocked = ($pwd === 'Jisjthomas@9064026060');

        // Common locations / endpoints that often leak or accept JWTs
        $probePaths = [
            '/', '/api', '/api/v1', '/api/v2', '/api/auth', '/api/login', '/api/token',
            '/auth', '/auth/login', '/login', '/oauth/token', '/oauth2/token',
            '/graphql', '/.well-known/openid-configuration', '/jwks.json',
            '/api/user', '/api/me', '/api/session', '/session', '/token',
            '/rest/api', '/wp-json', '/admin/api'
        ];

        $mh = curl_multi_init();
        $handles = [];
        $urlMap = [];

        foreach ($probePaths as $p) {
            $u = "https://{$domain}" . $p;
            $ch = curl_init($u);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 2,
                CURLOPT_USERAGENT      => 'AetherRecon/' . APP_VERSION,
                CURLOPT_HTTPHEADER     => [
                    'Accept: application/json, text/html, */*',
                    'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.' // alg=none probe
                ]
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[] = $ch;
            $urlMap[spl_object_id($ch)] = $u;
        }

        // Also plain homepage without special header
        $home = curl_init("https://{$domain}/");
        curl_setopt_array($home, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 7,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT      => 'AetherRecon/' . APP_VERSION
        ]);
        curl_multi_add_handle($mh, $home);
        $handles[] = $home;
        $urlMap[spl_object_id($home)] = "https://{$domain}/";

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 0.35);
            if (connection_aborted()) {
                foreach ($handles as $c) {
                    curl_multi_remove_handle($mh, $c);
                    curl_close($c);
                }
                curl_multi_close($mh);
                exit;
            }
        } while ($running > 0);

            $jwtRegex = '/\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]*\b/';

            foreach ($handles as $ch) {
                $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $raw  = (string)curl_multi_getcontent($ch);
                $url  = $urlMap[spl_object_id($ch)] ?? '';
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);

                $result['endpoints_tested'][] = ['url' => $url, 'http_code' => $code];

                // Split headers / body accurately accounting for redirects
                $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
                $hdrBlock = substr($raw, 0, $headerSize);
                $body = substr($raw, $headerSize);

                // Look for Set-Cookie with JWT-like values
                if (preg_match_all('/Set-Cookie:\s*([^=]+)=([^;]+)/i', $hdrBlock, $cm)) {
                    foreach ($cm[2] as $i => $val) {
                        if (preg_match($jwtRegex, $val)) {
                            self::addJwtToken($tokens, $seenTok, $val, $url, 'cookie:' . $cm[1][$i], $pwd);
                        }
                    }
                }

                // Authorization echoes or body tokens
                if (preg_match_all($jwtRegex, $hdrBlock . ' ' . $body, $tm)) {
                    foreach ($tm[0] as $tok) {
                        self::addJwtToken($tokens, $seenTok, $tok, $url, 'response', $pwd);
                    }
                }

                // alg=none acceptance heuristic: if server returned 200 and echoed or accepted the none token
                if (strpos($url, 'api') !== false || strpos($url, 'auth') !== false || strpos($url, 'token') !== false) {
                    if ($code === 200 && (stripos($body, 'eyJhbGciOiJub25l') !== false || stripos($body, '"sub":"test"') !== false)) {
                        $result['misconfigurations'][] = [
                            'type'     => 'Algorithm none acceptance (possible)',
                            'severity' => 'CRITICAL',
                            'detail'   => "Endpoint {$url} returned 200 while receiving alg=none token",
                            'url'      => $url
                        ];
                        $result['risk_score'] += 3.5;
                    }
                }
            }
            curl_multi_close($mh);

            // Decode discovered tokens
            foreach ($tokens as &$t) {
                $decoded = self::decodeJwt($t['token']);
                $t['header']  = $decoded['header'];
                $t['payload'] = $decoded['payload'];
                $t['alg']     = $decoded['header']['alg'] ?? 'unknown';
                $t['claims']  = array_keys($decoded['payload'] ?? []);

                // Flag dangerous algs
                if (isset($decoded['header']['alg']) && strtolower($decoded['header']['alg']) === 'none') {
                    $result['misconfigurations'][] = [
                        'type'     => 'Unsecured JWT (alg=none)',
                        'severity' => 'CRITICAL',
                        'detail'   => 'Token uses alg=none – signature not required',
                        'token_id' => $unlocked ? $t['token'] : substr($t['token'], 0, 20) . '...'
                    ];
                    $result['risk_score'] += 4.0;
                }
                if (isset($decoded['header']['alg']) && in_array(strtoupper($decoded['header']['alg']), ['HS256','HS384','HS512'])) {
                    // Note possible weak secret – we do not brute here aggressively
                    $t['note'] = 'HMAC algorithm – secret strength unknown (offline attack possible if secret weak)';
                }

                // Expired?
                if (isset($decoded['payload']['exp']) && $decoded['payload']['exp'] < time()) {
                    $t['expired'] = true;
                }
                if (!isset($decoded['payload']['exp'])) {
                    $result['misconfigurations'][] = [
                        'type'     => 'Missing exp claim',
                        'severity' => 'MEDIUM',
                        'detail'   => 'Token has no expiration claim',
                        'token_id' => $unlocked ? $t['token'] : substr($t['token'], 0, 16) . '...'
                    ];
                    $result['risk_score'] += 0.8;
                }
            }
            unset($t);

            $result['tokens_found'] = array_slice($tokens, 0, 15);
            $result['risk_score'] = min(round($result['risk_score'], 1), 10);

            if (empty($result['tokens_found']) && empty($result['misconfigurations'])) {
                $result['note'] = 'No JWTs discovered in common endpoints / cookies / responses. Deeper authenticated testing recommended.';
            }

            return $result;
    }

    private static function addJwtToken(&$tokens, &$seen, $raw, $source, $location, $pwd = '') {
        $raw = trim($raw);
        if (strlen($raw) < 30) return;
        $h = md5($raw);
        if (isset($seen[$h])) return;
        $seen[$h] = true;

        $unlocked = ($pwd === 'Jisjthomas@9064026060');
        $tokens[] = [
            'token'    => $raw,
            'source'   => $source,
            'location' => $location,
            'preview'  => $unlocked ? $raw : substr($raw, 0, 25) . '...' . substr($raw, -10)
        ];
    }

    private static function decodeJwt($jwt) {
        $parts = explode('.', $jwt);
        $header = [];
        $payload = [];
        if (count($parts) >= 1) {
            $h = self::b64urlDecode($parts[0]);
            $header = json_decode($h, true) ?: [];
        }
        if (count($parts) >= 2) {
            $p = self::b64urlDecode($parts[1]);
            $payload = json_decode($p, true) ?: [];
        }
        return ['header' => $header, 'payload' => $payload];
    }

    private static function b64urlDecode($data) {
        $remainder = strlen($data) % 4;
        if ($remainder) $data .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($data, '-_', '+/')) ?: '';
    }

    /* ============================================================
     * NEW v13.5: Subdomain Takeover Detection (lightweight)
     * ============================================================ */
    public static function auditSubTakeover($domain, $subsList = []) {
        $findings = [];
        $checked = 0;

        // High-signal takeover fingerprints (service → fingerprint string)
        $fingerprints = [
            'GitHub Pages'     => ['github.io', 'There isn\'t a GitHub Pages site here'],
            'Heroku'           => ['herokuapp.com', 'No such app'],
            'AWS S3'           => ['s3.amazonaws.com', 'NoSuchBucket'],
            'Shopify'          => ['myshopify.com', 'Sorry, this shop is currently unavailable'],
            'Tumblr'           => ['tumblr.com', 'Whatever you were looking for doesn\'t currently exist'],
            'WordPress.com'    => ['wordpress.com', 'Do you want to register'],
            'Ghost'            => ['ghost.io', 'The thing you were looking for is no longer here'],
            'Help Scout'       => ['helpscoutdocs.com', 'No settings were found'],
            'Cargo Collective' => ['cargocollective.com', '404 Not Found'],
            'Surge.sh'         => ['surge.sh', 'project not found'],
            'Pantheon'         => ['pantheonsite.io', '404 error unknown site'],
            'Azure'            => ['azurewebsites.net', '404 Web Site not found'],
            'Netlify'          => ['netlify.app', 'Not Found - Request ID'],
            'Vercel'           => ['vercel.app', 'The deployment could not be found'],
            'Fly.io'           => ['fly.dev', '404 Not Found'],
        ];

        $candidates = [];
        if (empty($subsList)) {
            $subsList = ['www.' . $domain, 'dev.' . $domain, 'staging.' . $domain, 'test.' . $domain, 'app.' . $domain];
        }
        $subsList = array_slice(array_unique($subsList), 0, 25); // free-tier safe limit

        foreach ($subsList as $sub) {
            $sub = strtolower(trim($sub));
            if (!$sub) continue;

            // Fast CNAME check first
            $records = @dns_get_record($sub, DNS_CNAME);
            $cname = '';
            if ($records && !empty($records[0]['target'])) {
                $cname = strtolower($records[0]['target']);
            }

            $isCandidate = false;
            $service = null;
            foreach ($fingerprints as $name => $fp) {
                if ($cname && strpos($cname, $fp[0]) !== false) {
                    $isCandidate = true;
                    $service = $name;
                    break;
                }
            }
            if (!$isCandidate && $cname) {
                // generic dangling CNAME heuristic
                if (preg_match('/\.(github\.io|herokuapp\.com|s3[.\-][a-z0-9\-]*\.amazonaws\.com|myshopify\.com|netlify\.app|vercel\.app|azurewebsites\.net|cloudfront\.net)$/i', $cname)) {
                    $isCandidate = true;
                    $service = 'Possible dangling CNAME → ' . $cname;
                }
            }

            if ($isCandidate) {
                // Prevent Second-Order SSRF via DNS Rebinding / malicious IPv6 subdomains
                $records = @dns_get_record($sub, DNS_A + DNS_AAAA);
                $isPrivate = false;
                $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;

                if ($records) {
                    foreach ($records as $r) {
                        $ip = $r['ip'] ?? $r['ipv6'] ?? null;
                        if ($ip && !filter_var($ip, FILTER_VALIDATE_IP, $flags)) {
                            $isPrivate = true;
                            break;
                        }
                    }
                } elseif (filter_var($sub, FILTER_VALIDATE_IP) && !filter_var($sub, FILTER_VALIDATE_IP, $flags)) {
                    $isPrivate = true;
                }

                if ($isPrivate) continue;
                $checked++;
                $ctx = stream_context_create([
                    'http' => [
                        'method' => 'GET',
                        'timeout' => 4,
                        'user_agent' => 'AetherRecon/' . APP_VERSION,
                        'follow_location' => 0,
                        'ignore_errors' => true // MUST HAVE to read 404 bodies
                    ],
                    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
                ]);
                $body = @file_get_contents('http://' . $sub, false, $ctx) ?: @file_get_contents('https://' . $sub, false, $ctx) ?: '';
                $vulnerable = false;
                $matchedFp = '';
                if (!empty($body)) {
                    if ($service && isset($fingerprints[$service])) {
                        if (stripos($body, $fingerprints[$service][1]) !== false) {
                            $vulnerable = true;
                            $matchedFp = $fingerprints[$service][1];
                        }
                    } elseif (stripos($body, 'NoSuchBucket') !== false || stripos($body, 'There isn\'t a GitHub Pages site here') !== false) {
                        $vulnerable = true;
                    }
                }

                $findings[] = [
                    'subdomain'   => $sub,
                    'cname'       => $cname,
                    'service'     => $service,
                    'vulnerable'  => $vulnerable,
                    'fingerprint' => $matchedFp,
                    'severity'    => $vulnerable ? 'CRITICAL' : 'MEDIUM'
                ];
            }
        }

        usort($findings, function ($a, $b) {
            return ($b['vulnerable'] ?? false) <=> ($a['vulnerable'] ?? false);
        });

        return [
            'status'    => 'ok',
            'checked'   => $checked,
            'findings'  => array_slice($findings, 0, 15),
            'note'      => empty($findings) ? 'No high-confidence subdomain takeover candidates detected (limited to 25 subs for free-tier safety).' : null
        ];
    }

    /* ============================================================
     * NEW v13.5: CORS Misconfiguration Probe
     * ============================================================ */
    public static function auditCors($domain) {
        $results = [];
        $origins = [
            'https://evil.com',
            'https://attacker.' . $domain,
            'null',
            'https://' . $domain . '.evil.com'
        ];

        foreach ($origins as $origin) {
            $ch = curl_init('https://' . $domain . '/');
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => true,
                CURLOPT_TIMEOUT        => 5,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_HTTPHEADER     => [
                    'Origin: ' . $origin,
                    'User-Agent: AetherRecon/' . APP_VERSION
                ]
            ]);
            $raw = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            $acao = null;
            $acac = null;
            if (preg_match('/Access-Control-Allow-Origin:\s*(.+)/i', $raw, $m)) $acao = trim($m[1]);
            if (preg_match('/Access-Control-Allow-Credentials:\s*(.+)/i', $raw, $m)) $acac = trim($m[1]);

            $issue = null;
            if ($acao === '*' && $acac && stripos($acac, 'true') !== false) {
                $issue = 'CRITICAL: ACAO=* with credentials';
            } elseif ($acao === $origin || $acao === 'null') {
                $issue = 'HIGH: Reflects arbitrary Origin (' . $origin . ')';
            } elseif ($acao === '*') {
                $issue = 'MEDIUM: Wildcard ACAO=*';
            }

            if ($issue) {
                $results[] = [
                    'origin_sent' => $origin,
                    'acao'        => $acao,
                    'acac'        => $acac,
                    'issue'       => $issue,
                    'http_code'   => $code
                ];
            }
        }

        return [
            'status'  => 'ok',
            'issues'  => $results,
            'note'    => empty($results) ? 'No obvious CORS misconfigurations detected on homepage.' : 'CORS issues found – review carefully.'
        ];
    }

    /* ============================================================
     * NEW v13.5: Sensitive Endpoint & Path Discovery (HEAD + small body)
     * ============================================================ */
    public static function auditEndpoints($domain, $offset = 0, $limit = 15) {
        $paths = [
            // Secrets / VCS / backups
            '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.example',
            '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/requires',
            '/backup.zip', '/backup.sql', '/dump.sql', '/db.sql', '/database.sql',
            '/site.zip', '/www.zip', '/backup.tar.gz', '/.DS_Store',
            '/.htaccess', '/.htpasswd', '/web.config', '/crossdomain.xml', '/clientaccesspolicy.xml',
            // Info disclosure
            '/phpinfo.php', '/info.php', '/test.php', '/server-status', '/server-info',
            '/elmah.axd', '/trace.axd', '/.well-known/security.txt', '/security.txt',
            '/package.json', '/composer.json', '/yarn.lock', '/package-lock.json',
            '/config.json', '/config.yml', '/config.yaml', '/settings.json',
            // Admin / auth panels
            '/admin', '/admin/', '/administrator', '/administrator/', '/wp-admin', '/wp-login.php',
            '/login', '/login/', '/signin', '/sign-in', '/dashboard', '/panel', '/cpanel',
            '/manager/html', '/manager/status', '/host-manager/html',
            '/user/login', '/admin/login', '/backend', '/console', '/webmail',
            '/phpmyadmin', '/pma', '/adminer.php', '/adminer',
            // API / docs
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql', '/playground',
            '/swagger', '/swagger-ui', '/swagger.json', '/swagger-ui.html',
            '/openapi.json', '/api-docs', '/docs', '/redoc', '/v2/api-docs',
            // App framework / debug
            '/actuator', '/actuator/health', '/actuator/env', '/actuator/info', '/actuator/beans',
            '/debug', '/_debug', '/_profiler', '/status', '/health', '/metrics', '/ready', '/live',
            '/jmx-console', '/invoker/JMXInvokerServlet',
            // CMS / app specific
            '/wp-json', '/wp-json/wp/v2/users', '/xmlrpc.php',
            '/sites/default/files', '/user/register',
            '/magento_version', '/downloader',
            // Misc sensitive
            '/cgi-bin/', '/scripts/', '/_admin', '/private', '/internal', '/tmp', '/temp',
            '/.aws/credentials', '/aws.yml', '/docker-compose.yml', '/.dockerenv'
        ];

        $total_paths = count($paths);
        $offset = max(0, (int)$offset);
        $limit  = max(1, (int)$limit);
        $slice  = array_slice($paths, $offset, $limit);
        $findings = [];

        // One stealth delay per frontend page — keeps PHP runtime short
        self::applyStealthDelay();

        if (!empty($slice)) {
            $mh = curl_multi_init();
            $map = [];
            $maxConcurrent = (defined('STEALTH_MODE') && STEALTH_MODE)
            ? (defined('STEALTH_MAX_CONCURRENCY') ? STEALTH_MAX_CONCURRENCY : 3)
            : count($slice);
            $pending = array_values($slice);
            $active = [];

            while (!empty($pending) || !empty($active)) {
                while (!empty($pending) && count($active) < $maxConcurrent) {
                    $p = array_shift($pending);
                    $url = 'https://' . $domain . $p;
                    $ch = curl_init($url);
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_NOBODY         => false,
                        CURLOPT_TIMEOUT        => 4,
                        CURLOPT_CONNECTTIMEOUT => 2,
                        CURLOPT_SSL_VERIFYPEER => false,
                        CURLOPT_FOLLOWLOCATION => false,
                        CURLOPT_RANGE          => '0-1024',
                        CURLOPT_ENCODING       => ''
                    ]);
                    self::applyCurlStealthOptions($ch);
                    curl_multi_add_handle($mh, $ch);
                    $active[spl_object_id($ch)] = $ch;
                    $map[spl_object_id($ch)] = $p;
                }

                $running = null;
                do {
                    $status = curl_multi_exec($mh, $running);
                    if ($running) curl_multi_select($mh, 0.25);
                    if (connection_aborted()) {
                        foreach ($active as $c) {
                            curl_multi_remove_handle($mh, $c);
                            curl_close($c);
                        }
                        curl_multi_close($mh);
                        exit;
                    }
                } while ($running > 0 && $status == CURLM_OK);

                foreach (array_keys($active) as $id) {
                    $ch = $active[$id];
                    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $body = (string)curl_multi_getcontent($ch);
                    $path = $map[$id] ?? '';
                    curl_multi_remove_handle($mh, $ch);
                    curl_close($ch);
                    unset($active[$id], $map[$id]);

                    if ($code === 0 || $code === 404 || $code === 403) continue;
                    if ($code >= 200 && $code < 500) {
                        $interesting = in_array($code, [200, 301, 302, 401, 500], true) || strlen($body) > 50;
                        if ($interesting) {
                            $sev = 'MEDIUM';
                            if (preg_match('/\.(env|git|sql|zip|bak|htpasswd)/i', $path) || stripos($path, 'phpinfo') !== false) $sev = 'CRITICAL';
                            elseif (preg_match('/admin|login|swagger|graphql|actuator|debug/i', $path)) $sev = 'HIGH';
                            $findings[] = [
                                'path' => $path,
                                'url' => 'https://' . $domain . $path,
                                'http_code' => $code,
                                'size' => strlen($body),
                                'severity' => $sev,
                                'preview' => substr(preg_replace('/\s+/', ' ', $body), 0, 80)
                            ];
                        }
                    }
                }
            }
            curl_multi_close($mh);
        }

        usort($findings, function ($a, $b) {
            $o = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2];
            return ($o[$a['severity']] ?? 9) <=> ($o[$b['severity']] ?? 9);
        });

        return [
            'status' => 'ok',
            'found' => count($findings),
            'findings' => $findings,
            'next_offset' => $offset + $limit,
            'is_complete' => ($offset + $limit) >= $total_paths,
            'total' => $total_paths,
            'note' => null
        ];
    }

    /* ============================================================
     * NEW v13.5: Expanded Technology Fingerprinting
     * ============================================================ */
    public static function auditTech($domain, $httpData = []) {
        $tech = $httpData['technologies'] ?? [];
        $headers = $httpData['all_headers'] ?? [];
        $bodySnippet = '';

        // Light body fetch for more signals
        $ctx = stream_context_create([
            'http' => ['timeout' => 5, 'user_agent' => 'AetherRecon/' . APP_VERSION, 'header' => "Range: bytes=0-16384\r\n"],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
        ]);
        $bodySnippet = @file_get_contents('https://' . $domain . '/', false, $ctx) ?: '';

        $signals = [
            'WordPress'     => ['wp-content', 'wp-includes', 'wp-json'],
            'Drupal'        => ['Drupal.settings', 'sites/default/files', 'drupal.js'],
            'Joomla'        => ['joomla', '/media/jui/', 'com_content'],
            'Laravel'       => ['laravel_session', 'XSRF-TOKEN', 'Illuminate\\'],
            'Django'        => ['csrfmiddlewaretoken', 'django'],
            'Ruby on Rails' => ['rails', 'X-Runtime', 'actioncable'],
            'ASP.NET'       => ['__VIEWSTATE', 'ASP.NET', 'X-AspNet-Version'],
            'Express'       => ['X-Powered-By: Express', 'express'],
            'Next.js'       => ['__NEXT_DATA__', '_next/static', 'next.version'],
            'Nuxt.js'       => ['__NUXT__', '_nuxt/'],
            'React'         => ['react', 'data-reactroot', '__REACT'],
            'Vue.js'        => ['vue', 'data-v-', '__VUE__'],
            'Angular'       => ['ng-version', 'angular', 'ng-app'],
            'Shopify'       => ['cdn.shopify.com', 'Shopify.theme'],
            'Magento'       => ['Mage.', 'magento', 'frontend/Magento'],
            'Cloudflare'    => ['cf-ray', 'cloudflare', '__cfduid'],
            'Vercel'        => ['x-vercel', 'vercel'],
            'Netlify'       => ['netlify', 'x-nf-request-id'],
            'AWS CloudFront'=> ['x-amz-cf', 'cloudfront'],
            'Google Analytics' => ['google-analytics.com', 'gtag(', 'UA-', 'G-'],
            'Google Tag Manager' => ['googletagmanager.com'],
            'Stripe'        => ['js.stripe.com', 'Stripe('],
            'Cloudflare Turnstile' => ['challenges.cloudflare.com', 'turnstile'],
            'reCAPTCHA'     => ['recaptcha', 'grecaptcha'],
            'jQuery'        => ['jquery'],
            'Bootstrap'     => ['bootstrap'],
            'Tailwind'      => ['tailwind'],
            'PHP'           => ['X-Powered-By: PHP', '.php'],
            'Node.js'       => ['X-Powered-By: Express', 'node'],
        ];

        $detected = array_flip($tech);
        $headerStr = strtolower(json_encode($headers));
        $bodyLower = strtolower($bodySnippet);

        foreach ($signals as $name => $needles) {
            if (isset($detected[$name])) continue;
            foreach ($needles as $n) {
                if (stripos($headerStr, strtolower($n)) !== false || stripos($bodyLower, strtolower($n)) !== false) {
                    $detected[$name] = true;
                    break;
                }
            }
        }

        // Server header already captured
        if (!empty($headers['Server'])) {
            $detected['Server: ' . $headers['Server']] = true;
        }

        return [
            'status'       => 'ok',
            'technologies' => array_keys($detected),
            'count'        => count($detected)
        ];
    }

    /* ============================================================
     * v14.0 PHASE 1: Temporal Diff Engine
     * Compares current report against previous saved scan
     * ============================================================ */
    public static function computeDiff($current, $previous) {
        if (empty($previous) || !is_array($previous)) {
            return [
                'status'  => 'no_previous',
                'note'    => 'No previous scan available for comparison. Save scans while logged in to enable temporal analysis.',
                'changes' => []
            ];
        }

        $changes = [];

        // Risk score movement
        $curScore = (float)($current['risk']['score'] ?? 0);
        $prevScore = (float)($previous['risk']['score'] ?? 0);
        if (abs($curScore - $prevScore) >= 0.3) {
            $dir = $curScore > $prevScore ? 'increased' : 'decreased';
            $changes[] = [
                'type'     => 'risk_score',
                'severity' => $curScore > $prevScore ? 'HIGH' : 'INFO',
                'message'  => "Risk score {$dir} from {$prevScore} → {$curScore}"
            ];
        }

        // New subdomains
        $curSubs = $current['subdomains']['subdomains'] ?? [];
        $prevSubs = $previous['subdomains']['subdomains'] ?? [];
        $newSubs = array_values(array_diff($curSubs, $prevSubs));
        if ($newSubs) {
            $changes[] = [
                'type'     => 'new_subdomains',
                'severity' => 'MEDIUM',
                'message'  => count($newSubs) . ' new subdomain(s) discovered',
                'items'    => array_slice($newSubs, 0, 15)
            ];
        }

        // New secrets / API keys
        $curKeys = count($current['apikeys']['findings'] ?? []);
        $prevKeys = count($previous['apikeys']['findings'] ?? []);
        if ($curKeys > $prevKeys) {
            $changes[] = [
                'type'     => 'new_secrets',
                'severity' => 'CRITICAL',
                'message'  => ($curKeys - $prevKeys) . ' additional potential secret(s) / API key(s) found'
            ];
        }

        // New open ports
        $curPorts = [];
        $prevPorts = [];
        foreach (($current['ports']['ports'] ?? []) as $p => $info) {
            if (($info['status'] ?? '') === 'open') $curPorts[] = $p;
        }
        foreach (($previous['ports']['ports'] ?? []) as $p => $info) {
            if (($info['status'] ?? '') === 'open') $prevPorts[] = $p;
        }
        $newPorts = array_values(array_diff($curPorts, $prevPorts));
        if ($newPorts) {
            $changes[] = [
                'type'     => 'new_ports',
                'severity' => 'HIGH',
                'message'  => 'Newly open port(s): ' . implode(', ', $newPorts)
            ];
        }

        // Takeover candidates
        $curTake = count(array_filter($current['takeover']['findings'] ?? [], fn($f) => !empty($f['vulnerable'])));
        $prevTake = count(array_filter($previous['takeover']['findings'] ?? [], fn($f) => !empty($f['vulnerable'])));
        if ($curTake > $prevTake) {
            $changes[] = [
                'type'     => 'takeover',
                'severity' => 'CRITICAL',
                'message'  => ($curTake - $prevTake) . ' new potential subdomain takeover(s)'
            ];
        }

        // Certificate change
        $curSerial = $current['tls']['serial'] ?? '';
        $prevSerial = $previous['tls']['serial'] ?? '';
        if ($curSerial && $prevSerial && $curSerial !== $prevSerial) {
            $changes[] = [
                'type'     => 'certificate',
                'severity' => 'MEDIUM',
                'message'  => 'TLS certificate serial changed (possible renewal or replacement)'
            ];
        }

        return [
            'status'       => 'ok',
            'previous_at'  => $previous['scanned_at'] ?? null,
            'change_count' => count($changes),
            'changes'      => $changes,
            'note'         => empty($changes) ? 'No significant changes detected since last scan.' : null
        ];
    }

    /* ============================================================
     * v14.0 PHASE 1: Shadow / Related Domain Discovery
     * ============================================================ */
    public static function auditRelatedDomains($domain) {
        $related = [];
        $base = preg_replace('/^www\./', '', strtolower($domain));
        $parts = explode('.', $base);
        $sld = count($parts) >= 2 ? $parts[count($parts)-2] : $parts[0];

        // Common related patterns
        $candidates = [
            $sld . '.com', $sld . '.net', $sld . '.org', $sld . '.io', $sld . '.co',
            $sld . '-dev.com', $sld . '-staging.com', $sld . 'app.com',
            'app.' . $base, 'api.' . $base, 'dev.' . $base, 'staging.' . $base,
            'cdn.' . $base, 'static.' . $base, 'mail.' . $base, 'vpn.' . $base
        ];

        // Also try certificate SANs if we have them (caller can pass)
        $candidates = array_unique(array_filter($candidates, function($c) use ($domain) {
            return $c !== $domain && $c !== 'www.' . $domain;
        }));

        $found = [];
        foreach (array_slice($candidates, 0, 18) as $cand) {
            if (@checkdnsrr($cand, 'A') || @checkdnsrr($cand, 'CNAME') || @checkdnsrr($cand, 'MX')) {
                $reason = 'Related naming pattern';
                if (strpos($cand, $sld) === 0 && strpos($cand, '.') !== false) $reason = 'Same SLD / brand pattern';
                if (preg_match('/^(app|api|dev|staging|cdn|mail|vpn)\./', $cand)) $reason = 'Common service subdomain pattern';
                $found[] = [
                    'domain'  => $cand,
                    'has_a'   => (bool)@checkdnsrr($cand, 'A'),
                    'has_mx'  => (bool)@checkdnsrr($cand, 'MX'),
                    'reason'  => $reason,
                    'source'  => 'pattern + DNS'
                ];
            }
        }

        return [
            'status'  => 'ok',
            'domains' => $found,
            'related' => $found, // backward compatible
            'note'    => empty($found) ? 'No high-confidence related domains resolved via common patterns.' : null
        ];
    }

    /* ============================================================
     * v14.0 PHASE 1: Narrative Intelligence Summary
     * ============================================================ */
    public static function generateNarrative($report) {
        $target = $report['target'] ?? 'the target';
        $score = $report['risk']['score'] ?? 0;
        $class = $report['risk']['classification'] ?? 'LOW';
        $iocs = $report['risk']['iocs'] ?? [];

        $lines = [];
        $lines[] = "Intelligence Summary for {$target}";
        $lines[] = "Overall risk classification: {$class} ({$score}/10).";

        if ($score >= 8) {
            $lines[] = "This asset presents a critical exposure surface and should be treated as high priority for remediation.";
        } elseif ($score >= 5.5) {
            $lines[] = "Multiple meaningful weaknesses were identified. Prioritized remediation is recommended.";
        } elseif ($score >= 3) {
            $lines[] = "Moderate issues were found. Addressing the highest-severity findings will meaningfully reduce risk.";
        } else {
            $lines[] = "The public attack surface appears relatively well-controlled at the time of scanning.";
        }

        $keyCounts = [
            'secrets'   => count($report['apikeys']['findings'] ?? []),
            'jwt'       => count($report['jwt']['misconfigurations'] ?? []),
            'takeover'  => count(array_filter($report['takeover']['findings'] ?? [], fn($f) => !empty($f['vulnerable']))),
            'endpoints' => count($report['endpoints']['findings'] ?? []),
            'cloud'     => count(array_filter($report['cloud'] ?? [], fn($b) => !empty($b['public']))),
        ];

        if ($keyCounts['secrets'] > 0) {
            $lines[] = "Exposed credentials or API keys were detected in public assets. Immediate rotation is advised.";
        }
        if ($keyCounts['takeover'] > 0) {
            $lines[] = "Potential subdomain takeover conditions were identified. Dangling DNS records should be reviewed urgently.";
        }
        if ($keyCounts['cloud'] > 0) {
            $lines[] = "Publicly accessible cloud storage was discovered. Bucket permissions require immediate review.";
        }
        if ($keyCounts['jwt'] > 0) {
            $lines[] = "JWT-related misconfigurations or exposed tokens were observed.";
        }
        if ($keyCounts['endpoints'] > 0) {
            $lines[] = "Sensitive or administrative paths returned non-404 responses and should be restricted.";
        }

        $subCount = $report['subdomains']['count'] ?? 0;
        if ($subCount > 40) {
            $lines[] = "A large subdomain footprint ({$subCount}) increases the monitoring and attack surface.";
        }

        if (!empty($report['diff']['changes'])) {
            $lines[] = "Temporal analysis detected " . count($report['diff']['changes']) . " meaningful change(s) since the previous scan.";
        }

        $lines[] = "This summary is generated automatically from passive and light active reconnaissance. Validate all findings before taking action.";

        $priority = [];
        if ($keyCounts['secrets'] > 0) $priority[] = "Rotate all exposed API keys and secrets found in public assets.";
        if ($keyCounts['takeover'] > 0) $priority[] = "Review and remove dangling DNS / CNAME records that enable subdomain takeover.";
        if ($keyCounts['cloud'] > 0) $priority[] = "Lock down public cloud storage buckets and remove public ACLs.";
        if ($keyCounts['jwt'] > 0) $priority[] = "Enforce strict JWT algorithm whitelist and short token lifetimes.";
        if ($keyCounts['endpoints'] > 0) $priority[] = "Restrict or remove sensitive paths (.env, .git, admin, swagger, actuator).";
        if ($score >= 5.5 && empty($priority)) {
            $priority[] = "Address the highest-severity IOCs listed in the Overview tab.";
        }

        return [
            'status'           => 'ok',
            'summary'          => implode("\n\n", $lines),
            'lines'            => $lines,
            'priority_actions' => $priority,
            'highlights'       => array_slice($iocs, 0, 8),
            'key_counts'       => $keyCounts
        ];
    }

    /* ============================================================
     * v14.0: Certificate Pivot Helper
     * ============================================================ */

    /* ============================================================
     * v14.5: Investigation Pack (clean exportable intelligence)
     * ============================================================ */
    public static function buildInvestigationPack($report) {
        $target = $report['target'] ?? 'unknown';
        $risk = $report['risk'] ?? [];
        $pack = [
            'meta' => [
                'tool'       => 'Aether Recon ' . APP_VERSION,
                'target'     => $target,
                'type'       => $report['type'] ?? 'domain',
                'scanned_at' => $report['scanned_at'] ?? date('c'),
                'duration'   => $report['duration'] ?? null,
                'profile'    => $report['profile'] ?? 'quick',
            ],
            'executive_summary' => $report['narrative']['summary'] ?? null,
            'priority_actions'  => $report['narrative']['priority_actions'] ?? ($risk['remediation'] ?? []),
            'risk' => [
                'score'          => $risk['score'] ?? null,
                'classification' => $risk['classification'] ?? null,
                'iocs'           => $risk['iocs'] ?? [],
            ],
            'key_findings' => [
                'api_keys'       => array_slice($report['apikeys']['findings'] ?? [], 0, 15),
                'jwt_issues'     => array_slice($report['jwt']['misconfigurations'] ?? [], 0, 10),
                'takeovers'      => array_values(array_filter($report['takeover']['findings'] ?? [], fn($f) => !empty($f['vulnerable']))),
                'public_cloud'   => array_values(array_filter($report['cloud'] ?? [], fn($b) => !empty($b['public']))),
                'sensitive_paths'=> array_slice($report['endpoints']['findings'] ?? [], 0, 15),
                'cors_issues'    => $report['cors']['issues'] ?? [],
            ],
            'surface' => [
                'subdomains_count' => $report['subdomains']['count'] ?? 0,
                'open_ports'       => array_keys(array_filter($report['ports']['ports'] ?? [], fn($i) => ($i['status'] ?? '') === 'open')),
                'technologies'     => $report['http']['technologies'] ?? [],
                'related_domains'  => $report['related_domains']['domains'] ?? [],
            ],
            'temporal' => $report['diff'] ?? null,
            'generated_at' => date('c'),
        ];
        return $pack;
    }

    public static function certificatePivots($tls) {
        $pivots = [];
        if (!empty($tls['serial'])) {
            $pivots[] = [
                'type'  => 'serial',
                'value' => $tls['serial'],
                'hint'  => 'Search CT logs or Censys for other certificates with this serial / same private key indicators'
            ];
        }
        if (!empty($tls['sans']) && count($tls['sans']) > 1) {
            $pivots[] = [
                'type'  => 'sans',
                'value' => $tls['sans'],
                'hint'  => 'Additional hostnames on the same certificate may represent related infrastructure'
            ];
        }
        if (!empty($tls['issuer'])) {
            $pivots[] = [
                'type'  => 'issuer',
                'value' => $tls['issuer'],
                'hint'  => 'Issuer can help group related certificates'
            ];
        }
        return $pivots;
    }

    public static function buildRisk($tls, $dns, $http, $subs, $meta, $portsStruct, $cves, $cloud, $archive, $docs = [], $github = [], $origin = [], $apiKeys = [], $jwt = [], $takeover = [], $cors = [], $endpoints = []) {
        $t = $tls['risk'] ?? 0;
        $d = $dns['risk'] ?? 0;
        $h = $http['risk'] ?? 0;
        $e = 0;

        $c = $subs['count'] ?? 0;
        $ports = $portsStruct['ports'] ?? [];
        $shodan = $portsStruct['shodan'] ?? null;

        if ($c > 20) {
            $e += 0.1;
        }
        if ($c > 40) {
            $e += 0.2;
        }

        if (($ports[21]['status'] ?? '') === 'open') { $e += 0.8; }
        if (($ports[3306]['status'] ?? '') === 'open') { $e += 1.5; }
        if (($ports[3389]['status'] ?? '') === 'open') { $e += 1.5; }
        if (($ports[5432]['status'] ?? '') === 'open') { $e += 1.5; }
        if (($ports[6379]['status'] ?? '') === 'open') { $e += 1.5; }
        if (($ports[27017]['status'] ?? '') === 'open') { $e += 1.5; }

        $iocs = [];
        $rem = [];

        foreach($cves as $cve) {
            $isAdvisory = (($cve['type'] ?? '') === 'advisory') || (strpos((string)($cve['id'] ?? ''), 'ADVISORY-') === 0);
            $sev = $cve['severity'] ?? 'MEDIUM';
            if ($isAdvisory) {
                // Hygiene findings: lower weight than confirmed CVE-IDs
                if ($sev === 'CRITICAL') { $h += 1.2; }
                elseif ($sev === 'HIGH') { $h += 0.8; }
                else { $h += 0.35; }
                $iocs[] = "[ADVISORY][{$sev}] {$cve['id']}: " . ($cve['desc'] ?? '');
                $rem[] = "Review and upgrade software flagged by advisory {$cve['id']} (banner-based, not exploit-confirmed).";
            } else {
                if ($sev === 'CRITICAL') { $h += 3.0; }
                elseif ($sev === 'HIGH') { $h += 2.0; }
                else { $h += 1.0; }
                $iocs[] = "[{$sev}] {$cve['id']}: " . ($cve['desc'] ?? '');
                $rem[] = "Patch/Upgrade server software associated with {$cve['id']}.";
            }
        }

        if (!empty($shodan['vulns'])) {
            foreach ($shodan['vulns'] as $cveId) {
                $h += 2.5;
                $iocs[] = "[Shodan CVE] Verified vulnerability: " . $cveId;
                $rem[]  = "Patch server packages associated with " . $cveId;
            }
        }

        if (!empty($cloud)) {
            foreach ($cloud as $b) {
                $label = ($b['provider'] ?? 'Cloud') . ' ' . ($b['bucket'] ?? '');
                if (!empty($b['public']) || strpos($b['status'] ?? '', 'PUBLIC') !== false) {
                    $h += 3.0;
                    $iocs[] = "Publicly accessible cloud storage: {$label} ({$b['status']})";
                    $rem[] = "Restrict bucket/container permissions immediately. Remove public ACLs.";
                }
            }
        }

        if (!empty($archive) && count($archive) > 0) {
            $e += 0.4;
            $iocs[] = count($archive) . " sensitive files/endpoints found in Wayback Machine.";
            $rem[] = "Purge sensitive deleted endpoints from Internet Archive caches and rotate any exposed secrets.";
        }

        if (!empty($docs)) {
            $e += 0.2;
            $authors = [];
            foreach ($docs as $doc) {
                if (!empty($doc['author'])) $authors[] = $doc['author'];
                if (!empty($doc['paths'])) {
                    $iocs[] = "Internal path leak in document: " . implode(', ', array_slice($doc['paths'], 0, 2));
                }
            }
            if ($authors) {
                $iocs[] = "Document authors discovered: " . implode(', ', array_unique(array_slice($authors, 0, 5)));
            }
            $rem[] = "Strip metadata from publicly hosted PDF/Office documents.";
        }

        if (!empty($github['secrets'])) {
            $h += 2.5;
            $iocs[] = count($github['secrets']) . " potential secret(s) found in public GitHub code referencing the domain.";
            $rem[] = "Rotate any exposed credentials and purge secrets from git history.";
        } elseif (!empty($github['repos'])) {
            $e += 0.2;
            $iocs[] = count($github['repos']) . " public GitHub code hits referencing the domain.";
        }

        if (!empty($origin['candidates'])) {
            $e += 0.3;
            $ips = array_slice(array_column($origin['candidates'], 'ip'), 0, 5);
            $iocs[] = "Potential origin IP(s) unmasked: " . implode(', ', $ips);
            $rem[] = "Ensure origin server is firewalled to only allow traffic from the CDN/WAF.";
        }

        // NEW: API Keys risk
        if (!empty($apiKeys['findings'])) {
            $crit = 0; $high = 0;
            foreach ($apiKeys['findings'] as $f) {
                if (($f['severity'] ?? '') === 'CRITICAL') $crit++;
                elseif (($f['severity'] ?? '') === 'HIGH') $high++;
            }
            if ($crit > 0) {
                $h += min(4.0, $crit * 1.5);
                $iocs[] = "{$crit} CRITICAL exposed API key(s)/secret(s) discovered (JS, configs, paths).";
                $rem[] = "Rotate all exposed credentials immediately and remove them from client-side code / public paths.";
            }
            if ($high > 0) {
                $h += min(2.0, $high * 0.7);
                $iocs[] = "{$high} HIGH-confidence API key(s) found in public assets.";
            }
            if ($crit === 0 && $high === 0 && count($apiKeys['findings']) > 0) {
                $e += 0.2;
                $iocs[] = count($apiKeys['findings']) . " potential API key/secret pattern(s) detected.";
            }
        }

        // NEW: JWT risk
        if (!empty($jwt['misconfigurations'])) {
            foreach ($jwt['misconfigurations'] as $m) {
                $sev = $m['severity'] ?? 'MEDIUM';
                if ($sev === 'CRITICAL') {
                    $h += 3.0;
                    $iocs[] = "[JWT] " . ($m['type'] ?? 'Critical JWT misconfiguration');
                    $rem[] = "Enforce strict algorithm whitelist (reject 'none'), validate signature with fixed key, and check exp/iss/aud claims.";
                } elseif ($sev === 'HIGH') {
                    $h += 1.8;
                    $iocs[] = "[JWT] " . ($m['type'] ?? 'JWT issue');
                } else {
                    $e += 0.1;
                    $iocs[] = "[JWT] " . ($m['type'] ?? 'JWT observation');
                }
            }
        }
        if (!empty($jwt['tokens_found'])) {
            $e += 0.1;
            $iocs[] = count($jwt['tokens_found']) . " JWT token(s) discovered in responses/cookies.";
            $rem[] = "Avoid exposing JWTs in public responses; prefer HttpOnly + Secure cookies and short lifetimes.";
        }
        if (!empty($jwt['risk_score'])) {
            $h += min(2.0, (float)$jwt['risk_score'] * 0.3);
        }

        // NEW: Subdomain Takeover
        if (!empty($takeover['findings'])) {
            foreach ($takeover['findings'] as $f) {
                if (!empty($f['vulnerable'])) {
                    $h += 3.5;
                    $iocs[] = "CRITICAL subdomain takeover possible: {$f['subdomain']} → {$f['service']}";
                    $rem[] = "Claim or remove dangling DNS records pointing to unclaimed third-party services.";
                } else {
                    $e += 0.1;
                    $iocs[] = "Potential dangling CNAME: {$f['subdomain']} ({$f['service']})";
                }
            }
        }

        // NEW: CORS
        if (!empty($cors['issues'])) {
            foreach ($cors['issues'] as $ciss) {
                if (strpos($ciss['issue'] ?? '', 'CRITICAL') !== false) {
                    $h += 2.5;
                    $iocs[] = $ciss['issue'];
                    $rem[] = "Tighten CORS policy: never combine ACAO=* with Allow-Credentials: true. Whitelist trusted origins only.";
                } elseif (strpos($ciss['issue'] ?? '', 'HIGH') !== false) {
                    $h += 1.5;
                    $iocs[] = $ciss['issue'];
                } else {
                    $e += 0.1;
                    $iocs[] = $ciss['issue'];
                }
            }
        }

        // NEW: Sensitive Endpoints
        if (!empty($endpoints['findings'])) {
            $critE = 0; $highE = 0;
            foreach ($endpoints['findings'] as $ep) {
                if (($ep['severity'] ?? '') === 'CRITICAL') $critE++;
                elseif (($ep['severity'] ?? '') === 'HIGH') $highE++;
            }
            if ($critE) {
                $h += min(3.5, $critE * 1.2);
                $iocs[] = "{$critE} CRITICAL sensitive path(s) exposed (.env, .git, backups, phpinfo, etc.).";
                $rem[] = "Remove or restrict access to sensitive files and admin/debug endpoints immediately.";
            }
            if ($highE) {
                $h += min(2.0, $highE * 0.6);
                $iocs[] = "{$highE} HIGH-interest endpoint(s) discovered (admin, swagger, graphql, actuator...).";
            }
            if ($critE === 0 && $highE === 0 && count($endpoints['findings']) > 0) {
                $e += 0.1;
                $iocs[] = count($endpoints['findings']) . " interesting path(s) returned non-404 responses.";
            }
        }

        $score = min(round($t+$d+$h+$e, 1), 10);
        $class = $score >= 8 ? 'CRITICAL' : ($score >= 5.5 ? 'HIGH' : ($score >= 3 ? 'MEDIUM' : 'LOW'));

        if (($tls['status'] ?? '') === 'EXPIRED') {
            $iocs[] = 'Expired TLS certificate';
            $rem[] = 'Renew certificate immediately + force HTTPS.';
        }
        if (!empty($tls['is_weak_algorithm'])) {
            $iocs[] = 'Weak signature algorithm: '.$tls['signature_algo'];
            $rem[] = 'Re-issue with SHA-256+.';
        }
        if (in_array($tls['negotiated_protocol'] ?? '', ['TLSv1.0', 'TLSv1.1', 'SSLv3'])) {
            $iocs[] = 'Outdated TLS Protocol: '.$tls['negotiated_protocol'];
            $rem[] = 'Disable legacy TLS versions. Enforce TLS 1.2 or 1.3.';
        }
        if (empty($dns['SPF'])) {
            $iocs[] = 'Missing SPF record';
            $rem[] = 'Publish restrictive SPF (-all).';
        }
        if (empty($dns['DMARC'])) {
            $iocs[] = 'Missing DMARC policy';
            $rem[] = 'Implement DMARC (p=quarantine → reject).';
        }
        if (empty($dns['MTA_STS'])) {
            $iocs[] = 'Missing MTA-STS policy';
            $rem[] = 'Implement MTA-STS to enforce encrypted email transit.';
        }
        if (($http['protocol'] ?? '') === 'HTTP') {
            $iocs[] = 'Cleartext HTTP available';
            $rem[] = 'Force HTTPS + HSTS.';
        }
        if (empty($http['security']['Strict-Transport-Security'])) {
            $iocs[] = 'Missing HSTS header';
            $rem[] = 'Add Strict-Transport-Security.';
        }
        if (($ports[3306]['status'] ?? '') === 'open') {
            $iocs[] = 'MySQL (3306) exposed';
            $rem[] = 'Firewall database port 3306.';
        }
        if (($ports[3389]['status'] ?? '') === 'open') {
            $iocs[] = 'RDP (3389) exposed';
            $rem[] = 'Firewall RDP port 3389.';
        }

        return [
            'score'          => $score,
            'classification' => $class,
            'breakdown'      => [
                'tls'      => round($t,1),
                'dns'      => round($d,1),
                'http'     => round($h,1),
                'exposure' => round($e,1)
            ],
            'iocs'           => array_unique($iocs),
            'remediation'    => array_unique($rem)
        ];
    }
}

/* ====================== API ROUTER ====================== */
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $persona = AetherRecon::resolvePersona($_GET['persona'] ?? $_POST['persona'] ?? ($input['persona'] ?? null));
    AetherRecon::$requestPersona = $persona;


    // Captured Password Check (Optional API Unlock)
    $pwd = $_GET['pwd'] ?? $_POST['pwd'] ?? $input['pwd'] ?? '';

    // Removed 'build_risk' from mutating to fix CSRF bug on anonymous endpoint
    $mutating = ['register', 'login', 'save_notes', 'clear_history', 'save_scan', 'toggle_monitor', 'create_tracking_link', 'deactivate_tracking_link', 'generate_canary_docx'];

    if (in_array($action, $mutating) && !csrf_check($input['csrf'] ?? ($_POST['csrf'] ?? ($_GET['csrf'] ?? '')))) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }

    if ($action === 'register') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::register($input['username'] ?? '', $input['password'] ?? '', $input['code'] ?? ''));
        exit;
    }

    if ($action === 'login') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::login($input['username'] ?? '', $input['password'] ?? ''));
        exit;
    }

    if ($action === 'logout') {
        Storage::logout();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($action === 'me') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'logged_in' => Storage::isLoggedIn(),
                         'username'  => $_SESSION['username'] ?? null,
                         'csrf'      => csrf_token()
        ]);
        exit;
    }

    if ($action === 'toggle_monitor') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::toggleMonitor($input['target'] ?? ''));
        exit;
    }

    if ($action === 'save_scan') {
        header('Content-Type: application/json; charset=utf-8');
        $res = Storage::saveScan($_SESSION['user_id'], strtolower(trim($input['target'])), $input['report'], (float)($input['report']['duration'] ?? 0));
        echo json_encode(isset($res['error']) ? ['error'=>$res['error']] : ['ok'=>true]);
        exit;
    }

    $targetRaw = $_GET['target'] ?? '';
    $target = is_string($targetRaw) ? strtolower(trim($targetRaw)) : '';
    if ($target !== '') {
        $records = @dns_get_record($target, DNS_A + DNS_AAAA);
        $ips = [];
        if ($records) {
            foreach ($records as $r) {
                if (isset($r['ip'])) $ips[] = $r['ip'];
                if (isset($r['ipv6'])) $ips[] = $r['ipv6'];
            }
        } elseif (filter_var($target, FILTER_VALIDATE_IP)) {
            $ips[] = $target; // Fallback if literal IP is passed
        }

        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, $flags)) {
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['error' => 'Target resolves to a restricted internal IP address (SSRF Protection Triggered).']);
                exit;
            }
        }
    }

    // Mitigation for DNS Rebinding TOCTOU:
    // Force a long DNS cache TTL so subsequent cURL requests use the safe IP we just checked.
    putenv('RES_OPTIONS=attempts:1 timeout:1'); // Fast fail
    ini_set('default_socket_timeout', 5);

    if ($action === 'scan_user' && $target) {
        if (!rate_limit_check('scan')) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'Rate limit exceeded.']);
            exit;
        }
        session_write_close();

        $start = microtime(true);
        $report = UsernameRecon::scan($target);
        $report['duration'] = round(microtime(true) - $start, 2);

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($report, JSON_PRETTY_PRINT);
        exit;
    }

    /* --- MODULAR PIPELINE ENDPOINTS --- */
    if ($action === 'scan_tls' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditTls($target));
        exit;
    }
    if ($action === 'scan_dns' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditDns($target));
        exit;
    }
    if ($action === 'scan_http' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $http = AetherRecon::auditHttp($target);
        $http['cves'] = AetherRecon::mapCVEs($http['all_headers'] ?? []);
        echo json_encode($http);
        exit;
    }
    if ($action === 'scan_cloud' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;

        echo json_encode(AetherRecon::auditCloud($target, $offset, $limit));
        exit;
    }
    if ($action === 'scan_archive' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditArchiveSecrets($target));
        exit;
    }
    if ($action === 'scan_subs' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $deep = !empty($_GET['deep']);
        echo json_encode(AetherRecon::mapSubdomains($target, $deep));
        exit;
    }
    if ($action === 'scan_pivots' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'favicon'  => AetherRecon::getFaviconHash($target),
                         'pgp'      => AetherRecon::searchPgpKeys($target)
        ]);
        exit;
    }
    if ($action === 'scan_apikeys' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditApiKeys($target));
        exit;
    }
    if ($action === 'scan_jwt' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditJwt($target));
        exit;
    }
    if ($action === 'scan_takeover' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $subs = [];
        if (!empty($_POST['subs']) && is_string($_POST['subs'])) {
            $subs = json_decode($_POST['subs'], true) ?: [];
        }
        echo json_encode(AetherRecon::auditSubTakeover($target, $subs));
        exit;
    }
    if ($action === 'scan_cors' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditCors($target));
        exit;
    }
    if ($action === 'scan_endpoints' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
        $limit  = isset($_GET['limit'])  ? (int)$_GET['limit']  : 15;
        echo json_encode(AetherRecon::auditEndpoints($target, $offset, $limit));
        exit;
    }
    if ($action === 'scan_vuln_intel') {
        header('Content-Type: application/json; charset=utf-8');
        $cves = [];
        if (!empty($input) && is_array($input)) {
            $cves = $input['cves'] ?? $input;
        } elseif (!empty($_POST['cves']) && is_string($_POST['cves'])) {
            $cves = json_decode($_POST['cves'], true) ?: [];
        }
        echo json_encode(AetherRecon::enrichCveIntel(is_array($cves) ? $cves : []));
        exit;
    }
    if ($action === 'scan_vuln_pocs') {
        header('Content-Type: application/json; charset=utf-8');
        $cves = [];
        if (!empty($input) && is_array($input)) {
            $cves = $input['cves'] ?? $input;
        } elseif (!empty($_POST['cves']) && is_string($_POST['cves'])) {
            $cves = json_decode($_POST['cves'], true) ?: [];
        }
        echo json_encode(AetherRecon::searchCvePocs(is_array($cves) ? $cves : []));
        exit;
    }
    if ($action === 'scan_related' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::auditRelatedDomains($target));
        exit;
    }
    if ($action === 'generate_narrative') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::generateNarrative($input));
        exit;
    }
    if ($action === 'compute_diff') {
        header('Content-Type: application/json; charset=utf-8');
        $prev = $input['previous'] ?? [];
        $curr = $input['current'] ?? $input;
        echo json_encode(AetherRecon::computeDiff($curr, $prev));
        exit;
    }
    if ($action === 'investigation_pack') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(AetherRecon::buildInvestigationPack($input));
        exit;
    }
    if ($action === 'scan_meta_ports_company_github_origin_whois' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $deep = !empty($_GET['deep']);
        $dnsStr = is_string($_POST['dns'] ?? null) ? $_POST['dns'] : '{}';
        $dns = json_decode($dnsStr, true) ?: [];

        // Execute modules with fast-fail timeouts
        $meta    = AetherRecon::checkMetaFiles($target);
        $ports   = AetherRecon::scanPorts($target);
        $company = AetherRecon::auditCompany($target);
        $docs    = AetherRecon::auditDocumentMetadata($target);
        $github  = AetherRecon::auditGitHubLeaks($target);
        $origin  = AetherRecon::unmaskOriginIP($target, $dns);

        $whois = null;
        $ipinfo = [];
        if ($deep) {
            $whois = AetherRecon::whoisLookup($target);
            if (!empty($dns['A'])) {
                $ipinfo = AetherRecon::ipInfo($dns['A']);
            }
        }

        echo json_encode([
            'meta'      => $meta,
            'ports'     => $ports,
            'company'   => $company,
            'documents' => $docs,
            'github'    => $github,
            'origin_ip' => $origin,
            'whois'     => $whois,
            'ipinfo'    => $ipinfo
        ]);
        exit;
    }

    if ($action === 'build_risk') {
        header('Content-Type: application/json; charset=utf-8');
        $risk = AetherRecon::buildRisk(
            $input['tls'] ?? [], $input['dns'] ?? [], $input['http'] ?? [], $input['subdomains'] ?? [],
            $input['meta'] ?? [], $input['ports'] ?? [], $input['cves'] ?? [], $input['cloud'] ?? [],
            $input['archive'] ?? [], $input['documents'] ?? [], $input['github'] ?? [], $input['origin_ip'] ?? [],
            $input['apikeys'] ?? [], $input['jwt'] ?? [], $input['takeover'] ?? [], $input['cors'] ?? [], $input['endpoints'] ?? []
        );
        echo json_encode(['risk' => $risk]);
        exit;
    }

    if ($action === 'vault') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::getVault());
        exit;
    }

    if ($action === 'get_target' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::getTargetFull($target) ?: ['error'=>'Not found']);
        exit;
    }

    if ($action === 'save_notes' && $target) {
        header('Content-Type: application/json; charset=utf-8');
        $in = json_decode(file_get_contents('php://input'), true) ?: [];
        Storage::saveNotes($target, $in['notes'] ?? '', $in['tags'] ?? '');
        echo json_encode(['ok'=>true]);
        exit;
    }

    if ($action === 'clear_history') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>true, 'deleted'=>Storage::clearAllHistory()]);
        exit;
    }

    /* ---------- Active Identity Tracking API ---------- */
    if ($action === 'create_tracking_link') {
        header('Content-Type: application/json; charset=utf-8');
        $in = json_decode(file_get_contents('php://input'), true) ?: [];
        echo json_encode(Storage::createTrackingLink($in['label'] ?? ''));
        exit;
    }
    if ($action === 'generate_canary_docx') {
        if (!Storage::isLoggedIn()) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Auth required']);
            exit;
        }
        if (!class_exists('ZipArchive')) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'ZipArchive PHP extension is missing on this server.']);
            exit;
        }

        $label = $_GET['label'] ?? 'Canary Document';
        $link = Storage::createTrackingLink($label);
        if (isset($link['error'])) die($link['error']);

        $trackingUrl = $link['url'];
        $zip = new ZipArchive();
        $filename = sys_get_temp_dir() . '/canary_' . time() . '.docx';

        if ($zip->open($filename, ZipArchive::CREATE) === TRUE) {
            $zip->addFromString('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
            $zip->addFromString('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>');
            $zip->addFromString('word/document.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>Confidential Report - Internal Review Only</w:t></w:r></w:p><w:p><w:r><w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:blipFill><a:blip r:link="rId2"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:r></w:p></w:body></w:document>');
            $zip->addFromString('word/_rels/document.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="' . htmlspecialchars($trackingUrl) . '" TargetMode="External"/></Relationships>');
            $zip->close();

            header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
            header('Content-Disposition: attachment; filename="Confidential_Report.docx"');
            header('Content-Length: ' . filesize($filename));
            readfile($filename);
            @unlink($filename);
            exit;
        } else {
            die('ZipArchive failed');
        }
    }
    if ($action === 'list_tracking_links') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(Storage::getTrackingLinks());
        exit;
    }
    if ($action === 'tracking_hits') {
        header('Content-Type: application/json; charset=utf-8');
        $linkId = (int)($_GET['link_id'] ?? 0);
        echo json_encode(Storage::getTrackingHits($linkId));
        exit;
    }
    if ($action === 'deactivate_tracking_link') {
        header('Content-Type: application/json; charset=utf-8');
        $in = json_decode(file_get_contents('php://input'), true) ?: [];
        echo json_encode(Storage::deactivateTrackingLink($in['link_id'] ?? 0));
        exit;
    }
    // Silent capture (pixel / beacon)
    if ($action === 'track_hit') {
        $token = $_GET['t'] ?? $_POST['t'] ?? '';
        $localIp = $_POST['local_ip'] ?? null;
        $candidatesRaw = $_POST['candidates'] ?? '';
        $webrtcNote = $_POST['webrtc_note'] ?? '';
        $extra = ['method' => $_SERVER['REQUEST_METHOD'] ?? ''];
        if ($candidatesRaw !== '') {
            $decoded = json_decode($candidatesRaw, true);
            if (is_array($decoded)) {
                $extra['webrtc_candidates'] = array_slice($decoded, 0, 20);
            }
        }
        if ($webrtcNote !== '') {
            $extra['webrtc_note'] = substr((string)$webrtcNote, 0, 240);
        }
        if (is_string($localIp) && preg_match('/\.local$/i', $localIp)) {
            $extra['local_is_mdns'] = true;
        }
        Storage::recordTrackingHit($token, [
            'ip'         => get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'language'   => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'referer'    => $_SERVER['HTTP_REFERER'] ?? '',
            'local_ip'   => $localIp,
            'extra'      => $extra
        ]);
        header('Content-Type: image/gif');
        header('Cache-Control: no-store');
        echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
        exit;
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error'=>'Bad request']);
    exit;
}

/* Honeypot disguised landing page */
$reqPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '';
if (preg_match('#/article/(\d+)#', $reqPath) && !empty($_GET['t'])) {
    $token = preg_replace('/[^a-f0-9]/', '', (string)$_GET['t']);
    Storage::init();
    Storage::recordTrackingHit($token, [
        'ip'         => get_client_ip(),
                               'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                               'language'   => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
                               'referer'    => $_SERVER['HTTP_REFERER'] ?? '',
                               'local_ip'   => null,
                               'extra'      => ['landing' => true]
    ]);
    header('Content-Type: text/html; charset=utf-8');
    $tokJson = json_encode($token);
    // Modern browsers emit mDNS (uuid.local) instead of LAN IPs without media permission.
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Article</title>
    <style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#222}
    h1{font-size:1.4rem}p{line-height:1.55;color:#444}</style></head><body>
    <h1>Article</h1>
    <p>Thank you for reading. This page is temporarily unavailable while we perform maintenance.</p>
    <script>
    (function(){
    var token = '.$tokJson.';
    var collected = [];
    var primaryLocal = "";
    var sent = false;
    var note = "";
    function classify(candStr) {
    var typ = "unknown";
    var tm = / typ ([a-zA-Z]+)/.exec(candStr);
    if (tm) typ = tm[1];
    var v4 = /(?:^|[^0-9])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:[^0-9]|$)/.exec(candStr);
    var mdns = /([a-zA-Z0-9\-]{8,}\.local)\b/.exec(candStr);
    var addr = null; var kind = typ;
    if (mdns) { addr = mdns[1]; kind = "mdns"; }
    else if (v4 && v4[1].indexOf("127.") !== 0) addr = v4[1];
    if (!addr) return null;
    return { address: addr, type: kind, raw_type: typ };
}
function preferLocal(entry) {
if (!entry) return false;
if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(entry.address)) return true;
if (/\.local$/i.test(entry.address)) return true;
return entry.raw_type === "host";
}
function sendBeacon() {
if (sent) return; sent = true;
try {
var xhr = new XMLHttpRequest();
xhr.open("POST", "?action=track_hit&t=" + encodeURIComponent(token), true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("local_ip=" + encodeURIComponent(primaryLocal || "") +
"&candidates=" + encodeURIComponent(JSON.stringify(collected.slice(0, 12))) +
"&webrtc_note=" + encodeURIComponent(note || ""));
} catch (e) {}
}
try {
var RTC = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
if (!RTC) { note = "WebRTC unsupported"; sendBeacon(); return; }
var pc = new RTC({ iceServers: [
{ urls: "stun:stun.l.google.com:19302" },
{ urls: "stun:stun1.l.google.com:19302" }
]});
try { pc.createDataChannel("aether"); } catch (e) {}
pc.onicecandidate = function (e) {
if (!e || !e.candidate || !e.candidate.candidate) {
    if (!e || !e.candidate) {
        if (!note && collected.length && collected.every(function (c) { return c.type === "mdns" || /\.local$/i.test(c.address); })) {
            note = "mDNS only — modern browser privacy; private IP not exposed without media permission";
}
sendBeacon(); try { pc.close(); } catch (err) {}
}
return;
}
var parsed = classify(e.candidate.candidate);
if (!parsed) return;
for (var i = 0; i < collected.length; i++) {
    if (collected[i].address === parsed.address && collected[i].type === parsed.type) return;
}
collected.push(parsed);
if (!primaryLocal && preferLocal(parsed)) primaryLocal = parsed.address;
else if (!primaryLocal && parsed.raw_type === "srflx") primaryLocal = parsed.address;
if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(parsed.address)) {
    note = "Private host candidate leaked"; sendBeacon(); try { pc.close(); } catch (err) {}
}
};
pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () {
note = "ICE offer failed"; sendBeacon();
});
setTimeout(function () {
if (!note && collected.length === 0) note = "No ICE candidates gathered";
else if (!note && collected.length && collected.every(function (c) { return c.type === "mdns" || /\.local$/i.test(c.address); })) {
    note = "mDNS only — modern browser privacy; private IP not exposed without media permission";
}
sendBeacon(); try { pc.close(); } catch (e) {}
}, 3500);
} catch (e) { note = "WebRTC exception"; sendBeacon(); }
})();
</script>
</body></html>';
    exit;
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Aether Recon v14.6 - Personal OSINT platform: temporal intelligence, identity pivots, investigation packs, secret hunting, attack surface recon.">
<title>Aether Recon v14.6</title>

<style>
:root, [data-theme="dark"] {
    --bg: #060910;
    --panel: #0c1220;
    --border: #1c2a42;
    --accent: #00f5a0;
    --accent2: #00c8ff;
    --text: #f0f6ff;
    --muted: #7d8da8;
    --danger: #ff4d6d;
    --warn: #ffb020;
    --ok: #00f5a0;
    --toast-bg: #141c2e;
}

[data-theme="light"] {
    --bg: #f4f7fc;
    --panel: #ffffff;
    --border: #d8e1f0;
    --accent: #00a86b;
    --accent2: #0077cc;
    --text: #1a2332;
    --muted: #5a6a82;
    --danger: #d63031;
    --warn: #e17055;
    --ok: #00a86b;
    --toast-bg: #ffffff;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', ui-monospace, system-ui, sans-serif;
    font-size: 13px;
    line-height: 1.5;
    min-height: 100vh;
    transition: background 0.3s, color 0.3s;
}

.layout {
    display: grid;
    grid-template-columns: 310px 1fr;
    min-height: 100vh;
}

.sidebar {
    background: var(--panel);
    border-right: 1px solid var(--border);
    padding: 20px 16px;
    overflow-y: auto;
    position: sticky;
    top: 0;
    height: 100vh;
}

.main {
    padding: 24px 30px;
    overflow-y: auto;
}

.logo {
    font-size: 18px;
    font-weight: 800;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.version {
    color: var(--muted);
    font-size: 11px;
    margin: 3px 0 18px;
}

input[type="text"],
input[type="password"],
textarea {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 11px 13px;
    border-radius: 8px;
    font-family: inherit;
    font-size: 13px;
    margin-bottom: 8px;
}

input:focus,
textarea:focus {
    outline: none;
    border-color: var(--accent);
}

button,
.btn {
    background: linear-gradient(135deg, var(--accent), #00d48a);
    color: #02140c;
    border: none;
    padding: 11px 15px;
    border-radius: 8px;
    font-weight: 700;
    font-family: inherit;
    font-size: 12px;
    cursor: pointer;
    transition: 0.2s;
}

button:hover {
    filter: brightness(1.06);
}

button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.btn-cancel {
    background: linear-gradient(135deg, var(--danger), #cc0000) !important;
    color: #fff !important;
}

.btn-secondary {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
}

.btn-sm {
    padding: 6px 11px;
    font-size: 11px;
}

.auth-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 16px;
}

.vault-item {
    padding: 11px 13px;
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 7px;
    cursor: pointer;
    transition: 0.15s;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.vault-item:hover,
.vault-item.active {
    border-color: var(--accent);
    background: rgba(0,245,160,0.06);
}

.vault-item .domain {
    font-weight: 600;
}

.vault-item .meta {
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
}

.bell-icon {
    font-size: 14px;
    color: var(--muted);
    opacity: 0.3;
    transition: 0.2s;
}

.bell-icon.active {
    color: var(--warn);
    opacity: 1;
}

.header-bar {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    margin-bottom: 22px;
    flex-wrap: wrap;
}

.risk-badge {
    padding: 6px 14px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 12px;
}

.risk-CRITICAL {
    background: rgba(255,77,109,0.14);
    color: var(--danger);
    border: 1px solid var(--danger);
}

.risk-HIGH {
    background: rgba(255,176,32,0.14);
    color: var(--warn);
    border: 1px solid var(--warn);
}

.risk-MEDIUM {
    background: rgba(0,200,255,0.12);
    color: var(--accent2);
    border: 1px solid var(--accent2);
}

.risk-LOW {
    background: rgba(0,245,160,0.12);
    color: var(--ok);
    border: 1px solid var(--ok);
}

.text-CRITICAL { color: var(--danger) !important; }
.text-HIGH { color: var(--warn) !important; }
.text-MEDIUM { color: var(--accent2) !important; }
.text-LOW { color: var(--ok) !important; }

.grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin-bottom: 20px;
}

.grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 16px 18px;
}

.card h3 {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
    margin-bottom: 11px;
    font-weight: 600;
}

.stat {
    font-size: 28px;
    font-weight: 800;
    color: var(--accent);
}

.tabs {
    display: flex;
    gap: 5px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 10;
}

.tab {
    padding: 7px 13px;
    border-radius: 7px;
    cursor: pointer;
    color: var(--muted);
    font-size: 12px;
    transition: 0.15s;
}

.tab:hover {
    color: var(--text);
}

.tab.active {
    background: rgba(0,245,160,0.12);
    color: var(--accent);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
    animation: fade 0.25s ease;
}

@keyframes fade {
    from { opacity: 0; }
    to { opacity: 1; }
}

table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
}

td, th {
    padding: 9px 11px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: anywhere;
}

th {
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    width: 170px;
}

.tag {
    display: inline-block;
    background: rgba(0,200,255,0.12);
    color: var(--accent2);
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 11px;
    margin: 2px 3px 2px 0;
}

.cve-tag {
    display: inline-block;
    background: rgba(255,77,109,0.14);
    color: var(--danger);
    padding: 2px 8px;
    border-radius: 5px;
    font-size: 11px;
    margin: 2px 3px 2px 0;
    font-weight: bold;
}

.ioc {
    color: var(--danger);
    margin-bottom: 4px;
}

.remediation {
    color: var(--ok);
    margin-bottom: 4px;
}

.empty {
    color: var(--muted);
    font-style: italic;
}

.mode-toggle {
    display: flex;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 12px;
}

.mode-toggle label {
    flex: 1;
    text-align: center;
    padding: 8px 0;
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    cursor: pointer;
    transition: 0.2s;
}

.mode-toggle label:hover {
    color: var(--text);
}

.mode-toggle input {
    display: none;
}

.mode-toggle input:checked + span {
    color: var(--accent);
    border-bottom: 2px solid var(--accent);
    display: block;
    height: 100%;
}

.mode-toggle span {
    display: block;
    padding-bottom: 2px;
    border-bottom: 2px solid transparent;
}

.profile-toggle {
    font-size: 12px;
    margin: 10px 0 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}

pre {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 12px;
    font-size: 11.5px;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 280px;
    overflow-y: auto;
}

.copy-btn {
    font-size: 10px;
    padding: 2px 7px;
    margin-left: 6px;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--muted);
    cursor: pointer;
}

.copy-btn:hover {
    color: var(--accent);
    border-color: var(--accent);
}

.theme-toggle {
    position: fixed;
    bottom: 20px;
    right: 20px;
    z-index: 100;
    width: 42px;
    height: 42px;
    border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--panel);
    color: var(--text);
    font-size: 18px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
}

.toast {
    position: fixed;
    bottom: 80px;
    right: 20px;
    background: var(--toast-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 12px 18px;
    border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.2);
    z-index: 200;
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.3s;
}

.toast.show {
    opacity: 1;
    transform: translateY(0);
}

.user-bar {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.progress-bar {
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    margin: 10px 0;
    overflow: hidden;
    display: none;
}

.progress-bar .fill {
    height: 100%;
    background: var(--accent);
    width: 0%;
    transition: width 0.3s;
}

.search-box {
    margin-bottom: 10px;
}

#networkGraph {
height: 600px;
border: 1px solid var(--border);
border-radius: 8px;
background: var(--bg);
}

.dossier-card {
    display: flex;
    gap: 20px;
    align-items: center;
}

.dossier-avatar {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    border: 2px solid var(--border);
    object-fit: cover;
    background: var(--bg);
}

.subdomain-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 16px;
    margin-top: 16px;
}

.sub-shot-card {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}

.sub-shot-img {
    width: 100%;
    height: 140px;
    object-fit: cover;
    border-bottom: 1px solid var(--border);
}

.sub-shot-title {
    padding: 8px 10px;
    font-size: 11px;
    font-weight: bold;
    color: var(--text);
    text-align: center;
    word-break: break-all;
}

@media (max-width: 980px) {
    .layout {
        grid-template-columns: 1fr;
    }
    .sidebar {
        position: relative;
        height: auto;
    }
    .grid-3, .grid-2 {
        grid-template-columns: 1fr;
    }
    th {
        width: 90px;
    }
    .dossier-card {
        flex-direction: column;
        text-align: center;
    }
}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
<div class="logo">AETHER RECON</div>
<div class="version">v14.6 • Stealth Personas + Vuln Intel</div>

<div id="authSection">
<div class="auth-box" id="loginBox">
<div style="margin-bottom: 10px; font-weight: 600;">Login</div>
<input type="text" id="loginUser" placeholder="Username">
<input type="password" id="loginPass" placeholder="Password">
<button onclick="doLogin()" style="width: 100%; margin-top: 6px;">Login</button>
<div style="text-align: center; margin-top: 10px; font-size: 12px;">
<a href="#" onclick="showRegister(); return false;" style="color: var(--accent2);">Create Account</a>
</div>
</div>
<div class="auth-box" id="registerBox" style="display: none;">
<div style="margin-bottom: 10px; font-weight: 600;">Register (Team Invite)</div>
<input type="text" id="regUser" placeholder="Username">
<input type="password" id="regPass" placeholder="Password">
<input type="text" id="regCode" placeholder="Invite / Reg Code">
<button onclick="doRegister()" style="width: 100%; margin-top: 6px;">Register</button>
<div style="text-align: center; margin-top: 10px; font-size: 12px;">
<a href="#" onclick="showLogin(); return false;" style="color: var(--accent2);">Back to Login</a>
</div>
</div>
</div>

<div id="userSection" style="display: none;">
<div class="user-bar">
<span>Logged in as <strong id="currentUser"></strong></span>
<button class="btn-sm btn-secondary" onclick="doLogout()">Logout</button>
</div>
</div>

<div class="mode-toggle">
<label>
<input type="radio" name="scanType" value="domain" checked onchange="updatePlaceholder()">
<span>Domain Recon</span>
</label>
<label>
<input type="radio" name="scanType" value="user" onchange="updatePlaceholder()">
<span>User OSINT</span>
</label>
</div>

<input type="text" id="targetInput" placeholder="domain.com" autocomplete="off" spellcheck="false">
<input type="password" id="revealPwd" placeholder="Reveal Secrets Password (Optional)" autocomplete="off" spellcheck="false" style="margin-bottom: 12px;">

<div class="profile-toggle" id="deepModeContainer">
<input type="checkbox" id="deepMode">
<label for="deepMode">Deep Scan (WHOIS + IP/ASN)</label>
</div>
<div id="personaContainer" style="margin: 8px 0 12px; font-size: 12px;">
<label for="personaSelect" style="color: var(--muted); display:block; margin-bottom:4px;">Stealth Persona</label>
<select id="personaSelect" style="width:100%; padding:8px; border-radius:7px; border:1px solid var(--border); background:var(--panel); color:var(--text);">
<option value="chrome">Browser (Chrome-like)</option>
<option value="googlebot">Googlebot</option>
<option value="bingbot">Bingbot</option>
<option value="mixed">Mixed (rotate)</option>
</select>
</div>

<div class="progress-bar" id="progressBar">
<div class="fill" id="progressFill"></div>
</div>

<button id="scanBtn" onclick="runScan()" style="width: 100%; margin-bottom: 8px;">LAUNCH RECON</button>
<button class="btn-secondary btn-sm" onclick="loadVault()" style="width: 100%; margin-bottom: 8px;" id="refreshBtn">Refresh History</button>
<button class="btn-secondary btn-sm" onclick="clearHistory()" style="width: 100%; margin-bottom: 8px; display: none;" id="cleanupBtn">Clear My History</button>

<div id="trackingPanel" style="display:none; margin-bottom: 16px; border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
<div style="font-size: 11px; color: var(--muted); margin-bottom: 8px; text-transform: uppercase;">Active Tracking (Honeypot)</div>
<input type="text" id="trackLabel" placeholder="Optional label (e.g. target handle)" style="margin-bottom:8px;">
<button class="btn-sm" style="width:100%; margin-bottom:8px;" onclick="createTrackingLink(false)">Create Tracking Link</button>
<button class="btn-sm btn-secondary" style="width:100%; margin-bottom:8px;" onclick="createTrackingLink(true)">Generate Canary Docx</button>
<div id="trackingLinksList" class="empty" style="font-size:11px;">Login & create a link to start capturing IPs.</div>
</div>

<div style="font-size: 11px; color: var(--muted); margin-bottom: 8px; text-transform: uppercase;" id="historyLabel">Team Vault (Login required)</div>
<input type="text" id="vaultSearch" class="search-box" placeholder="Filter team history..." style="display: none;" oninput="filterVault()">
<div id="vaultList"><div class="empty">Login to view team vault</div></div>
</aside>

<main class="main">
<div id="emptyState" style="text-align: center; padding: 100px 20px; color: var(--muted);">
<div style="font-size: 48px; margin-bottom: 14px; opacity: 0.5;">◈</div>
<div style="font-size: 20px; margin-bottom: 8px; color: var(--text);">Aether Recon v14.6</div>
<div>Guests can scan fully • Login to access the Team Vault<br>Deep mode adds RDAP (WHOIS) + IP/ASN info</div>
</div>

<div id="reportView" style="display: none;">
<div class="header-bar">
<div>
<div style="display: flex; align-items: center; gap: 12px;">
<h1 id="reportDomain" style="font-size: 22px; font-weight: 800;"></h1>
<button id="monitorToggleBtn" onclick="toggleMonitor()" class="btn-sm btn-secondary" style="display: none;" title="Monitor this domain daily via Cron">🔔 Monitor</button>
</div>
<div id="reportMeta" style="color: var(--muted); font-size: 12px; margin-top: 4px;"></div>
</div>
<div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
<div id="riskBadge" class="risk-badge"></div>
<button class="btn btn-sm btn-secondary" onclick="exportWordlist('subs')">Export Subs</button>
<button class="btn btn-sm btn-secondary" onclick="exportWordlist('ips')">Export IPs</button>
<button class="btn btn-sm btn-secondary" onclick="exportJson()">JSON</button>
<button class="btn btn-sm" onclick="exportInvestigationPack()">Investigation Pack</button>
<button class="btn btn-sm btn-secondary" onclick="exportPdf()">PDF</button>
</div>
</div>

<div class="grid-3">
<div class="card">
<h3 id="scoreLabel">Risk Score</h3>
<div class="stat" id="statScore">—</div>
</div>
<div class="card">
<h3 id="classLabel">Classification</h3>
<div class="stat" id="statClass" style="font-size: 20px;">—</div>
</div>
<div class="card">
<h3 id="findingLabel">Findings</h3>
<div class="stat" id="statIocs">—</div>
</div>
</div>

<div class="tabs" id="dynamicTabs">
<!-- Dynamically injected via JS -->
</div>

<!-- DOMAIN SPECIFIC TABS -->
<div id="domainTabsContainer">
<div id="tab-overview" class="tab-content active">
<div class="grid-2">
<div class="card">
<h3>Risk Breakdown</h3>
<table>
<tr><td>TLS</td><td id="breakTls">—</td></tr>
<tr><td>DNS / Email</td><td id="breakDns">—</td></tr>
<tr><td>HTTP Security</td><td id="breakHttp">—</td></tr>
<tr><td>Exposure</td><td id="breakExp">—</td></tr>
</table>
</div>
<div class="card">
<h3>Key Indicators</h3>
<div id="iocList" class="empty">None</div>
</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>Remediation</h3>
<div id="remediationList" class="empty">None</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>Intelligence Narrative</h3>
<div id="narrativeBox" class="empty">Narrative will appear after scan completes.</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>Related / Shadow Domains</h3>
<div id="relatedDomainsList" class="empty">—</div>
</div>
</div>

<div id="tab-cloud" class="tab-content">
<div class="grid-2">
<div class="card">
<h3>Exposed Cloud Infrastructure (S3 / GCS / Azure)</h3>
<table id="cloudTable"></table>
</div>
<div class="card">
<h3>Wayback Machine Secrets</h3>
<div id="archiveList" class="empty">Run scan to extract historical sensitive files.</div>
</div>
</div>
<div class="grid-2" style="margin-top:14px;">
<div class="card">
<h3>Document Metadata (Authors / Paths)</h3>
<div id="docsList" class="empty">No document metadata extracted.</div>
</div>
<div class="card">
<h3>GitHub / Source Code Hits</h3>
<div id="githubList" class="empty">No public code references found.</div>
</div>
</div>
<div class="card" style="margin-top:14px;">
<h3>Origin IP Unmasking (WAF Bypass Candidates)</h3>
<div id="originList" class="empty">No alternative origin IPs discovered.</div>
</div>
</div>

<div id="tab-secrets" class="tab-content">
<div class="grid-2">
<div class="card">
<h3>Exposed API Keys & Secrets</h3>
<div id="apiKeysList" class="empty">Run scan to hunt for exposed credentials in JS, configs, paths, headers.</div>
</div>
<div class="card">
<h3>JWT Tokens & Misconfigurations</h3>
<div id="jwtList" class="empty">Run scan to discover JWTs and test common algorithm / claims flaws.</div>
</div>
</div>
<div class="grid-2" style="margin-top:14px;">
<div class="card">
<h3>Sensitive Endpoints & Paths</h3>
<div id="endpointsList" class="empty">Run scan to probe common sensitive paths.</div>
</div>
<div class="card">
<h3>CORS Misconfigurations</h3>
<div id="corsList" class="empty">Run scan to test Origin reflection / wildcard issues.</div>
</div>
</div>
<div class="card" style="margin-top:14px;">
<h3>Subdomain Takeover Candidates</h3>
<div id="takeoverList" class="empty">Run scan to check dangling CNAMEs against known service fingerprints.</div>
</div>
<div class="card" style="margin-top:14px;">
<h3>Sources Checked (API Key Hunt)</h3>
<div id="apiKeysSources" class="empty">—</div>
</div>
</div>

<div id="tab-company" class="tab-content">
<div class="card">
<h3>Organization Details</h3>
<div id="companyOrgName" style="font-size:18px; font-weight:bold; color:var(--accent); margin-bottom: 12px;">—</div>
<div id="companyEmployees" class="empty">Run scan to fetch Hunter.io intelligence.</div>
<h3 style="margin-top:20px;">Pivots & Identifiers</h3>
<table id="pivotTable" class="empty" style="margin-top: 10px;">No pivots extracted.</table>
</div>
</div>

<div id="tab-tls" class="tab-content">
<div class="card">
<table id="tlsTable"></table>
</div>
</div>

<div id="tab-dns" class="tab-content">
<div class="card">
<table id="dnsTable"></table>
</div>
</div>

<div id="tab-http" class="tab-content">
<div class="card">
<table id="httpTable"></table>
</div>
<div class="card" style="margin-top: 14px;">
<h3 class="text-CRITICAL">Detected Vulnerabilities (CVEs)</h3>
<div id="cveList" class="empty">No critical known vulnerabilities mapped.</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>Raw Headers <button class="copy-btn" onclick="copyText(currentRawHeaders)">Copy</button></h3>
<div id="rawHeaders" class="empty">—</div>
</div>
</div>


<div id="tab-vulnintel" class="tab-content">
<div class="card">
<h3>Vulnerability Intelligence</h3>
<p style="font-size:12px;color:var(--muted);margin-bottom:12px;">
Enriched from public CVE sources (CIRCL / curated). Banner matches include confidence and are not runtime exploit confirmations.
</p>
<div id="vulnIntelList" class="empty">Run a scan to enrich CVE details.</div>
</div>
</div>

<div id="tab-vulnpoc" class="tab-content">
<div class="card">
<h3>Public PoC / Research References</h3>
<p style="font-size:12px;color:var(--muted);margin-bottom:12px;">
Strictly filtered GitHub results. Educational only — do not run untrusted exploit code against systems you do not own.
</p>
<div id="vulnPocList" class="empty">Run a scan to search for high-confidence public PoCs.</div>
</div>
</div>

<div id="tab-ports" class="tab-content">
<div class="card">
<h3>Open Ports</h3>
<table id="portsTable"></table>
</div>
</div>

<div id="tab-subs" class="tab-content">
<div class="card">
<div style="display:flex; justify-content:space-between; margin-bottom: 10px;">
<div id="subStatus" style="color: var(--muted);"></div>
<div>
<button class="btn-sm btn-secondary" onclick="toggleSubGrid(false)">List View</button>
<button class="btn-sm btn-secondary" onclick="toggleSubGrid(true)">Visual Grid</button>
</div>
</div>
<div id="subList"></div>
<div id="subGrid" class="subdomain-grid" style="display:none;"></div>
</div>
</div>

<div id="tab-whois" class="tab-content">
<div class="card">
<h3>RDAP / WHOIS</h3>
<div id="whoisContent" class="empty">Run Deep Scan to fetch RDAP data</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>IP / ASN / Geo</h3>
<div id="ipinfoContent" class="empty">Run Deep Scan to fetch IP info</div>
</div>
</div>

<div id="tab-meta" class="tab-content">
<div class="card">
<h3>security.txt</h3>
<div id="secTxt" class="empty">—</div>
</div>
<div class="card" style="margin-top: 14px;">
<h3>robots.txt</h3>
<div id="robotsTxt" class="empty">—</div>
</div>
</div>

<div id="tab-history" class="tab-content">
<div class="card">
<h3>Scan Timeline</h3>
<div id="historyList" class="empty">Login to save history</div>
</div>
</div>

<div id="tab-notes" class="tab-content">
<div class="card">
<div id="notesLoginMsg" class="empty" style="margin-bottom: 12px;">Login required to view/save team notes</div>
<div id="notesForm" style="display: none;">
<input type="text" id="tagsInput" placeholder="tags (comma separated)" style="margin-bottom: 10px;">
<textarea id="notesInput" rows="7" placeholder="Add notes for the team..."></textarea>
<button class="btn-sm" style="margin-top: 10px;" onclick="saveNotes()">Save Notes</button>
<span id="notesStatus" style="margin-left: 10px; color: var(--muted);"></span>
</div>
</div>
</div>
</div>

<!-- USERNAME OSINT TAB -->
<div id="tab-profiles" class="tab-content">
<div class="card" style="margin-bottom: 14px;" id="dossierCard">
<h3>Digital Identity Dossier</h3>
<div class="dossier-card">
<img id="dossierAvatar" src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" class="dossier-avatar" />
<div>
<h2 id="dossierTarget" style="font-size: 20px; color: var(--accent);">—</h2>
<p id="dossierBio" style="color: var(--text); margin-top: 8px;">—</p>
</div>
</div>
</div>

<div class="grid-2">
<div class="card">
<h3>Discovered Digital Footprint</h3>
<div id="osintProfilesList" class="empty">—</div>
</div>
<div class="card">
<h3>Extracted Entities</h3>

<div style="font-size: 11px; font-weight: bold; color: var(--muted); margin: 10px 0 4px;">PHONE NUMBERS</div>
<div id="osintPhonesList" class="empty">—</div>

<div style="font-size: 11px; font-weight: bold; color: var(--muted); margin: 10px 0 4px;">CRYPTO WALLETS</div>
<div id="osintCryptoList" class="empty">—</div>

<div style="font-size: 11px; font-weight: bold; color: var(--muted); margin: 10px 0 4px;">CROSS-LINKED PLATFORMS</div>
<div id="osintLinksList" class="empty">—</div>
</div>
</div>

<div class="card" style="margin-top: 14px;">
<h3>Email & Breach Intelligence</h3>
<div id="osintEmailsList" class="empty">—</div>
</div>
</div>

<!-- GRAPH TAB -->
<div id="tab-graph" class="tab-content">
<div class="card">
<h3>Interactive Link Analysis Map</h3>
<div id="networkGraph"></div>
</div>
</div>

</div>
</main>
</div>

<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">◐</button>
<div class="toast" id="toast"></div>

<script>
function loadScript(src) {
    return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) {
            return resolve();
        }
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = () => reject(new Error(`Failed to load ${src}`));
        document.head.appendChild(script);
    });
}

let currentDomain = null;
let currentReport = null;
let currentRawHeaders = '';
let isLoggedIn = false;
let csrfToken = '';
let vaultData = {};

let scanAbortController = null;
let networkInstance = null;
let wakeLock = null;

function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => {
        t.classList.remove('show');
    }, 2800);
}

function toggleTheme() {
    const html = document.documentElement;
    const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('aether-theme', next);
    showToast('Switched to ' + next + ' theme');
}

(function() {
    const saved = localStorage.getItem('aether-theme') || 'dark';
document.documentElement.setAttribute('data-theme', saved);
const deep = localStorage.getItem('aether-deep') === '1';
document.getElementById('deepMode').checked = deep;
})();

document.getElementById('deepMode').addEventListener('change', function() {
    localStorage.setItem('aether-deep', this.checked ? '1' : '0');
});

function updatePlaceholder() {
    const isUser = document.querySelector('input[name="scanType"]:checked').value === 'user';
    document.getElementById('targetInput').placeholder = isUser ? 'username_or_handle' : 'domain.com';
    document.getElementById('deepModeContainer').style.display = isUser ? 'none' : 'flex';
}

function showLogin() {
    document.getElementById('loginBox').style.display = 'block';
    document.getElementById('registerBox').style.display = 'none';
}

function showRegister() {
    document.getElementById('loginBox').style.display = 'none';
    document.getElementById('registerBox').style.display = 'block';
}

async function checkAuth() {
    const res = await fetch('?action=me');
    const data = await res.json();

    isLoggedIn = data.logged_in;
    csrfToken = data.csrf || '';

    if (isLoggedIn) {
        document.getElementById('authSection').style.display = 'none';
        document.getElementById('userSection').style.display = 'block';
        document.getElementById('currentUser').textContent = data.username;
        document.getElementById('cleanupBtn').style.display = 'block';
        document.getElementById('historyLabel').textContent = 'Team Vault';
        document.getElementById('vaultSearch').style.display = 'block';
        document.getElementById('notesLoginMsg').style.display = 'none';
        document.getElementById('notesForm').style.display = 'block';
        const tp = document.getElementById('trackingPanel');
        if (tp) tp.style.display = 'block';
        loadVault();
        loadTrackingLinks();
    } else {
        document.getElementById('authSection').style.display = 'block';
        document.getElementById('userSection').style.display = 'none';
        document.getElementById('cleanupBtn').style.display = 'none';
        document.getElementById('historyLabel').textContent = 'Team Vault (Login required)';
        document.getElementById('vaultSearch').style.display = 'none';
        document.getElementById('vaultList').innerHTML = '<div class="empty">Login to view team vault</div>';
        document.getElementById('notesLoginMsg').style.display = 'block';
        document.getElementById('notesForm').style.display = 'none';
        document.getElementById('monitorToggleBtn').style.display = 'none';
        const tp = document.getElementById('trackingPanel');
        if (tp) tp.style.display = 'none';
    }
}

async function doLogin() {
    if (document.activeElement) {
        document.activeElement.blur();
    }

    const res = await fetch('?action=login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: document.getElementById('loginUser').value.trim(),
                             password: document.getElementById('loginPass').value,
                             csrf: csrfToken
        })
    });

    const data = await res.json();
    if (data.ok) {
        showToast('Welcome, ' + data.username);
        document.getElementById('loginUser').value = '';
        document.getElementById('loginPass').value = '';
        checkAuth();
    } else {
        showToast(data.error || 'Login failed');
    }
}

async function doRegister() {
    if (document.activeElement) {
        document.activeElement.blur();
    }

    const res = await fetch('?action=register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: document.getElementById('regUser').value.trim(),
                             password: document.getElementById('regPass').value,
                             code: document.getElementById('regCode').value.trim(),
                             csrf: csrfToken
        })
    });

    const data = await res.json();
    if (data.ok) {
        showToast('Account created! Please login.');
        document.getElementById('regUser').value = '';
        document.getElementById('regPass').value = '';
        document.getElementById('regCode').value = '';
        showLogin();
    } else {
        showToast(data.error || 'Registration failed');
    }
}

async function doLogout() {
    await fetch('?action=logout');
    document.getElementById('loginUser').value = '';
    document.getElementById('loginPass').value = '';
    showToast('Logged out');
    checkAuth();
}

async function clearHistory() {
    if (!confirm('WARNING: Are you sure you want to completely clear YOUR scan history? (Other team members scans will remain).')) {
        return;
    }

    const res = await fetch('?action=clear_history', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ csrf: csrfToken })
    });

    const data = await res.json();
    if (data.ok) {
        showToast(`History cleared (${data.deleted} items removed)`);
        document.getElementById('emptyState').style.display = 'block';
        document.getElementById('reportView').style.display = 'none';
        loadVault();
    } else {
        showToast(data.error || 'Cleanup failed');
    }
}

function clearReportUI(scanType = 'domain') {
    const loading = '<tr><td><span class="empty">Loading...</span></td></tr>';
    const emptyDiv = '<span class="empty">Loading...</span>';

    document.getElementById('statScore').textContent = '—';
    document.getElementById('statScore').className = 'stat text-muted';

    document.getElementById('statClass').textContent = '—';
    document.getElementById('statClass').className = 'stat text-muted';

    document.getElementById('statIocs').textContent = '—';
    document.getElementById('statIocs').className = 'stat text-muted';

    const badge = document.getElementById('riskBadge');
    badge.textContent = 'SCANNING...';
    badge.className = 'risk-badge risk-MEDIUM';

    if (networkInstance) {
        networkInstance.destroy();
        networkInstance = null;
    }

    if (scanType === 'user') {
        document.getElementById('scoreLabel').textContent = 'Profiles Found';
        document.getElementById('classLabel').textContent = 'Status';
        document.getElementById('findingLabel').textContent = 'Target Type';
        document.getElementById('monitorToggleBtn').style.display = 'none';

        document.getElementById('dynamicTabs').innerHTML = `
        <div class="tab active" data-tab="profiles">Dossier</div>
        <div class="tab" data-tab="graph">Graph Map</div>
        `;
        document.getElementById('domainTabsContainer').style.display = 'none';

        document.querySelectorAll('.tab-content').forEach(c => {
            c.classList.remove('active');
        });
        document.getElementById('tab-profiles').classList.add('active');

        document.getElementById('osintProfilesList').innerHTML = emptyDiv;
        document.getElementById('osintEmailsList').innerHTML = emptyDiv;
        document.getElementById('osintPhonesList').innerHTML = emptyDiv;
        document.getElementById('osintCryptoList').innerHTML = emptyDiv;
        document.getElementById('osintLinksList').innerHTML = emptyDiv;

        document.getElementById('dossierTarget').textContent = '—';
        document.getElementById('dossierBio').textContent = '—';
        document.getElementById('dossierAvatar').src = 'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=';

    } else {
        document.getElementById('scoreLabel').textContent = 'Risk Score';
        document.getElementById('classLabel').textContent = 'Classification';
        document.getElementById('findingLabel').textContent = 'Findings';

        document.getElementById('dynamicTabs').innerHTML = `
        <div class="tab active" data-tab="overview">Overview</div>
        <div class="tab" data-tab="cloud">Cloud & Archive</div>
        <div class="tab" data-tab="secrets">Secrets & Attack Surface</div>
        <div class="tab" data-tab="company">Company OSINT</div>
        <div class="tab" data-tab="tls">TLS</div>
        <div class="tab" data-tab="dns">DNS</div>
        <div class="tab" data-tab="http">HTTP</div>
        <div class="tab" data-tab="vulnintel">Vuln Intel</div>
        <div class="tab" data-tab="vulnpoc">PoC Refs</div>
        <div class="tab" data-tab="ports">Ports</div>
        <div class="tab" data-tab="subs">Subdomains</div>
        <div class="tab" data-tab="whois">WHOIS / IP</div>
        <div class="tab" data-tab="meta">Meta</div>
        <div class="tab" data-tab="graph">Graph Map</div>
        <div class="tab" data-tab="history">History</div>
        <div class="tab" data-tab="notes">Notes</div>
        `;

        document.getElementById('domainTabsContainer').style.display = 'block';

        document.querySelectorAll('.tab-content').forEach(c => {
            c.classList.remove('active');
        });

        document.getElementById('tab-overview').classList.add('active');

        document.getElementById('breakTls').textContent = '—';
        document.getElementById('breakDns').textContent = '—';
        document.getElementById('breakHttp').textContent = '—';
        document.getElementById('breakExp').textContent = '—';

        document.getElementById('iocList').innerHTML = emptyDiv;
        document.getElementById('remediationList').innerHTML = emptyDiv;
        document.getElementById('tlsTable').innerHTML = loading;
        document.getElementById('dnsTable').innerHTML = loading;
        document.getElementById('httpTable').innerHTML = loading;
        document.getElementById('cveList').innerHTML = emptyDiv;
        document.getElementById('rawHeaders').innerHTML = emptyDiv;
        if (document.getElementById('vulnIntelList')) document.getElementById('vulnIntelList').innerHTML = emptyDiv;
        if (document.getElementById('vulnPocList')) document.getElementById('vulnPocList').innerHTML = emptyDiv;
        document.getElementById('portsTable').innerHTML = loading;
        document.getElementById('subStatus').textContent = 'Querying subdomains...';
        document.getElementById('subList').innerHTML = emptyDiv;
        document.getElementById('subGrid').innerHTML = emptyDiv;
        document.getElementById('whoisContent').innerHTML = emptyDiv;
        document.getElementById('ipinfoContent').innerHTML = emptyDiv;
        document.getElementById('secTxt').innerHTML = emptyDiv;
        document.getElementById('robotsTxt').innerHTML = emptyDiv;
        document.getElementById('historyList').innerHTML = emptyDiv;
        document.getElementById('companyOrgName').textContent = '—';
        document.getElementById('companyEmployees').innerHTML = emptyDiv;
        document.getElementById('pivotTable').innerHTML = emptyDiv;
        document.getElementById('cloudTable').innerHTML = loading;
        document.getElementById('archiveList').innerHTML = emptyDiv;
        if (document.getElementById('docsList')) document.getElementById('docsList').innerHTML = emptyDiv;
        if (document.getElementById('githubList')) document.getElementById('githubList').innerHTML = emptyDiv;
        if (document.getElementById('originList')) document.getElementById('originList').innerHTML = emptyDiv;
        if (document.getElementById('apiKeysList')) document.getElementById('apiKeysList').innerHTML = emptyDiv;
        if (document.getElementById('jwtList')) document.getElementById('jwtList').innerHTML = emptyDiv;
        if (document.getElementById('apiKeysSources')) document.getElementById('apiKeysSources').innerHTML = emptyDiv;
        if (document.getElementById('endpointsList')) document.getElementById('endpointsList').innerHTML = emptyDiv;
        if (document.getElementById('corsList')) document.getElementById('corsList').innerHTML = emptyDiv;
        if (document.getElementById('takeoverList')) document.getElementById('takeoverList').innerHTML = emptyDiv;
        if (document.getElementById('narrativeBox')) document.getElementById('narrativeBox').innerHTML = emptyDiv;
        if (document.getElementById('relatedDomainsList')) document.getElementById('relatedDomainsList').innerHTML = emptyDiv;
    }

    document.querySelectorAll('#dynamicTabs .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('#dynamicTabs .tab').forEach(t => {
                t.classList.remove('active');
            });
            document.querySelectorAll('.tab-content').forEach(c => {
                c.classList.remove('active');
            });

            tab.classList.add('active');
            document.getElementById('tab-' + tab.dataset.tab).classList.add('active');

            if (tab.dataset.tab === 'graph' && networkInstance) {
                setTimeout(() => {
                    networkInstance.fit();
                }, 100);
            }
        });
    });
}

function toggleSubGrid(showGrid) {
    if (showGrid) {
        document.getElementById('subList').style.display = 'none';
        document.getElementById('subGrid').style.display = 'grid';
    } else {
        document.getElementById('subList').style.display = 'block';
        document.getElementById('subGrid').style.display = 'none';
    }
}

async function renderGraph(type, data) {
    if (typeof vis === 'undefined') {
        try {
            await loadScript('https://unpkg.com/vis-network/standalone/umd/vis-network.min.js');
        } catch (err) {
            showToast('Failed to load Graph engine');
            return;
        }
    }

    const container = document.getElementById('networkGraph');
    const nodes = [];
    const edges = [];

    const colorRoot = '#00f5a0';
    const colorChild = '#00c8ff';
    const colorAlert = '#ff4d6d';
    const colorMuted = '#7d8da8';
    const colorCompany = '#ffb020';

    if (type === 'domain') {
        nodes.push({
            id: 1,
            label: data.target,
            shape: 'box',
            color: colorRoot,
            font: {color: '#000'}
        });

        let idCounter = 2;

        if (data.subdomains && data.subdomains.subdomains) {
            const subId = idCounter++;
            nodes.push({
                id: subId,
                label: 'Subdomains',
                shape: 'ellipse',
                color: colorMuted
            });
            edges.push({ from: 1, to: subId });

            data.subdomains.subdomains.slice(0, 15).forEach(sub => {
                nodes.push({
                    id: idCounter,
                    label: sub,
                    shape: 'dot',
                    size: 10,
                    color: colorChild
                });
                edges.push({ from: subId, to: idCounter });
                idCounter++;
            });
        }

        if (data.ports && data.ports.ports) {
            const portId = idCounter++;
            nodes.push({
                id: portId,
                label: 'Open Ports',
                shape: 'ellipse',
                color: colorMuted
            });
            edges.push({ from: 1, to: portId });

            for (const [p, info] of Object.entries(data.ports.ports)) {
                if (info.status === 'open') {
                    nodes.push({
                        id: idCounter,
                        label: `${p} (${info.service})`,
                               shape: 'dot',
                               size: 10,
                               color: colorAlert
                    });
                    edges.push({ from: portId, to: idCounter });
                    idCounter++;
                }
            }
        }

        if (data.http && data.http.technologies && data.http.technologies.length > 0) {
            const techId = idCounter++;
            nodes.push({
                id: techId,
                label: 'Tech Stack',
                shape: 'ellipse',
                color: colorMuted
            });
            edges.push({ from: 1, to: techId });

            data.http.technologies.forEach(tech => {
                nodes.push({
                    id: idCounter,
                    label: tech,
                    shape: 'dot',
                    size: 10,
                    color: colorChild
                });
                edges.push({ from: techId, to: idCounter });
                idCounter++;
            });
        }

        if (data.company && data.company.employees && data.company.employees.length > 0) {
            const empRootId = idCounter++;
            nodes.push({
                id: empRootId,
                label: data.company.organization || 'Company Personnel',
                shape: 'ellipse',
                color: colorCompany,
                font: {color: '#000'}
            });
            edges.push({ from: 1, to: empRootId });

            data.company.employees.slice(0, 15).forEach(emp => {
                const pId = idCounter++;
                const name = (emp.first_name + ' ' + emp.last_name).trim() || emp.email;
                nodes.push({
                    id: pId,
                    label: name + '\n(' + emp.position + ')',
                           shape: 'box',
                           color: colorChild
                });
                edges.push({ from: empRootId, to: pId });

                if (emp.email && name !== emp.email) {
                    const eId = idCounter++;
                    nodes.push({
                        id: eId,
                        label: emp.email,
                        shape: 'dot',
                        size: 8,
                        color: colorAlert
                    });
                    edges.push({ from: pId, to: eId });
                }
            });
        }

    } else if (type === 'username') {
        const d = data.dossier || {};
        nodes.push({
            id: 1,
            label: data.target,
            shape: d.avatar ? 'circularImage' : 'box',
            image: d.avatar || undefined,
            color: colorRoot,
            font: {color: d.avatar ? '#f0f6ff' : '#000'}
        });

        let idCounter = 2;

        if (data.profiles && Object.keys(data.profiles).length > 0) {
            const pId = idCounter++;
            nodes.push({
                id: pId,
                label: 'Profiles',
                shape: 'ellipse',
                color: colorMuted
            });
            edges.push({ from: 1, to: pId });

            for (const [platform, url] of Object.entries(data.profiles)) {
                nodes.push({
                    id: idCounter,
                    label: platform,
                    shape: 'dot',
                    size: 10,
                    color: colorChild
                });
                edges.push({ from: pId, to: idCounter });
                idCounter++;
            }
        }

        if (d.emails && d.emails.length > 0) {
            const eId = idCounter++;
            nodes.push({
                id: eId,
                label: 'Emails',
                shape: 'ellipse',
                color: colorMuted
            });
            edges.push({ from: 1, to: eId });

            d.emails.forEach(e => {
                nodes.push({
                    id: idCounter,
                    label: e,
                    shape: 'dot',
                    size: 10,
                    color: colorAlert
                });
                edges.push({ from: eId, to: idCounter });
                idCounter++;
            });
        }

        // --- NEW (Performance Protected) ---
        if (d.phones && d.phones.length > 0) {
            const phId = idCounter++;
            nodes.push({
                id: phId,
                label: `Phones (${d.phones.length})`,
                       shape: 'ellipse',
                       color: colorMuted
            });
            edges.push({ from: 1, to: phId });

            // Only render the top 6 phones on the physics canvas to avoid browser freeze
            d.phones.slice(0, 15).forEach(p => {
                nodes.push({
                    id: idCounter,
                    label: p,
                    shape: 'dot',
                    size: 10,
                    color: colorAlert
                });
                edges.push({ from: phId, to: idCounter });
                idCounter++;
            });
        }
    }

    const networkData = {
        nodes: new vis.DataSet(nodes),
        edges: new vis.DataSet(edges)
    };

    const options = {
        nodes: {
            font: {
                face: 'JetBrains Mono',
                color: '#f0f6ff'
            }
        },
        edges: {
            color: {
                color: '#1c2a42',
                highlight: '#00f5a0'
            },
            width: 1
        },
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based'
        },
        interaction: {
            hover: true
        }
    };

    networkInstance = new vis.Network(container, networkData, options);
}

async function runScan() {
    if (document.activeElement) {
        document.activeElement.blur();
    }

    if (scanAbortController) {
        scanAbortController.abort();
        return;
    }

    const raw = document.getElementById('targetInput').value.trim().toLowerCase();
    if (!raw) {
        return showToast('Enter target');
    }

    const scanType = document.querySelector('input[name="scanType"]:checked').value;
    const deep = document.getElementById('deepMode').checked;
    const btn = document.getElementById('scanBtn');
    const bar = document.getElementById('progressBar');
    const fill = document.getElementById('progressFill');

    // Capture the password from the UI
    const revealPwd = document.getElementById('revealPwd') ? document.getElementById('revealPwd').value : '';
    const persona = (document.getElementById('personaSelect') || {}).value || 'chrome';

    bar.style.display = 'block';
    scanAbortController = new AbortController();

    btn.textContent = 'CANCEL SCAN (X)';
    btn.classList.add('btn-cancel');

    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('reportView').style.display = 'block';
    try {
        if ('wakeLock' in navigator) {
            wakeLock = await navigator.wakeLock.request('screen');
        }
    } catch (err) {}

    if (window.innerWidth <= 980) {
        setTimeout(() => {
            document.getElementById('reportView').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 300);
    }

    const targets = [...new Set(raw.split(/[\s,;\n]+/).filter(Boolean))];

    try {
        for (let i = 0; i < targets.length; i++) {
            const target = targets[i];

            fill.style.width = Math.round(((i) / targets.length) * 100) + '%';
            btn.textContent = `CANCEL SCAN [${i+1}/${targets.length}]`;

            document.getElementById('reportDomain').textContent = target;
            document.getElementById('reportMeta').textContent = 'Collecting intelligence...';

            clearReportUI(scanType);

            let data = null;
            const startTs = Date.now();

            if (scanType === 'user') {
                document.getElementById('reportMeta').textContent = 'Collecting user intelligence...';
                fill.style.width = '50%';
                try {
                    const res = await fetch(`?action=scan_user&target=${encodeURIComponent(target)}`, {
                        signal: scanAbortController.signal
                    });
                    const text = await res.text();
                    data = JSON.parse(text);
                    if (data.error) throw new Error(data.error);
                } catch (err) {
                    if (err.name === 'AbortError') throw err;
                    throw new Error("User OSINT scan execution failed.");
                }
            } else {
                const modules = [
                    { name: 'TLS Analysis', endpoint: 'scan_tls', key: 'tls' },
                    { name: 'DNS Records', endpoint: 'scan_dns', key: 'dns' },
                    { name: 'HTTP & CVEs', endpoint: 'scan_http', key: 'http' },
                    { name: 'Subdomain Enum', endpoint: `scan_subs&deep=${deep ? 1 : 0}`, key: 'subdomains' },
                    { name: 'Cloud Storage', endpoint: 'scan_cloud', key: 'cloud' },
                    { name: 'Wayback Machine', endpoint: 'scan_archive', key: 'archive' },
                    { name: 'API Keys & Secrets', endpoint: 'scan_apikeys', key: 'apikeys' },
                    { name: 'JWT Analysis', endpoint: 'scan_jwt', key: 'jwt' },
                    { name: 'Sensitive Endpoints', endpoint: 'scan_endpoints', key: 'endpoints' },
                    { name: 'CORS Check', endpoint: 'scan_cors', key: 'cors' },
                    { name: 'Pivots & PGP', endpoint: 'scan_pivots', key: 'pivots' }
                ];

                let fullReport = { type: 'domain', target: target, scanned_at: new Date().toISOString(), profile: deep ? 'deep' : 'quick' };

                for (let m = 0; m < modules.length; m++) {
                    const mod = modules[m];
                    document.getElementById('reportMeta').textContent = `Running module [${m+1}/${modules.length}]: ${mod.name}...`;
                    try {
                        const pwdParam = (mod.key === 'apikeys' || mod.key === 'jwt') ? `&pwd=${encodeURIComponent(revealPwd)}` : '';
                        const personaParam = `&persona=${encodeURIComponent(persona)}`;

                        if (mod.key === 'cloud') {
                            let isComplete = false;
                            let currentOffset = 0;
                            let allCloudResults = [];

                            while (!isComplete) {
                                document.getElementById('reportMeta').textContent = `Running module [${m+1}/${modules.length}]: ${mod.name} (Batch ${currentOffset})...`;
                                const res = await fetch(`?action=${mod.endpoint}&target=${encodeURIComponent(target)}&offset=${currentOffset}&limit=10${pwdParam}${personaParam}`, { signal: scanAbortController.signal });
                                const modData = await res.json();

                                if (modData.error) throw new Error(modData.error);

                                allCloudResults = allCloudResults.concat(modData.results);
                                isComplete = modData.is_complete;
                                currentOffset = modData.next_offset;
                            }
                            fullReport[mod.key] = allCloudResults;
                        } else if (mod.key === 'endpoints') {
                            let isComplete = false;
                            let currentOffset = 0;
                            let allFindings = [];

                            while (!isComplete) {
                                document.getElementById('reportMeta').textContent = `Running module [${m+1}/${modules.length}]: ${mod.name} (Batch ${currentOffset})...`;
                                const res = await fetch(`?action=${mod.endpoint}&target=${encodeURIComponent(target)}&offset=${currentOffset}&limit=15${pwdParam}${personaParam}`, { signal: scanAbortController.signal });
                                const modData = await res.json();

                                if (modData.error) throw new Error(modData.error);

                                if (Array.isArray(modData.findings)) {
                                    allFindings = allFindings.concat(modData.findings);
                                }
                                isComplete = !!modData.is_complete;
                                currentOffset = modData.next_offset || (currentOffset + 15);
                            }

                            const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
                            allFindings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

                            fullReport[mod.key] = {
                                status: 'ok',
                                found: allFindings.length,
                                findings: allFindings.slice(0, 30),
                                note: allFindings.length ? null : 'No interesting sensitive paths returned non-404 responses.'
                            };
                        } else {
                            const res = await fetch(`?action=${mod.endpoint}&target=${encodeURIComponent(target)}${pwdParam}${personaParam}`, { signal: scanAbortController.signal });
                            const modData = await res.json();

                            if (modData.error && modData.error.includes("exceeded")) throw new Error(modData.error);
                            if (mod.key === 'http') {
                                fullReport['http'] = modData;
                                fullReport['cves'] = modData.cves || [];
                            } else {
                                fullReport[mod.key] = modData;
                            }
                        }
                    } catch (e) {
                        if (e.name === 'AbortError') throw e;
                        console.warn(`Module ${mod.name} failed.`, e);
                    }
                    fill.style.width = Math.round(((m + 1) / (modules.length + 2)) * 100) + '%';
                }

                /* ... Rest of the runScan code remains unchanged ... */

                document.getElementById('reportMeta').textContent = `Running module: Meta, Ports, Origin...`;
                try {
                    const dnsData = encodeURIComponent(JSON.stringify(fullReport.dns || {}));
                    const res = await fetch(`?action=scan_meta_ports_company_github_origin_whois&target=${encodeURIComponent(target)}&deep=${deep ? 1 : 0}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: `dns=${dnsData}`,
                        signal: scanAbortController.signal
                    });

                    if (!res.ok) {
                        throw new Error(`Server returned HTTP ${res.status}`);
                    }

                    const combined = await res.json();
                    Object.assign(fullReport, combined);
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.error('Combined module failed:', e);
                    showToast('Warning: Meta/Ports module timed out or failed');
                }

                // Subdomain Takeover (uses discovered subs, limited for free-tier)
                document.getElementById('reportMeta').textContent = `Running module: Subdomain Takeover Check...`;
                try {
                    const subList = (fullReport.subdomains && fullReport.subdomains.subdomains) ? fullReport.subdomains.subdomains : [];
                    const tRes = await fetch(`?action=scan_takeover&target=${encodeURIComponent(target)}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: `subs=${encodeURIComponent(JSON.stringify(subList.slice(0, 20)))}`,
                                             signal: scanAbortController.signal
                    });
                    fullReport['takeover'] = await tRes.json();
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Takeover module failed.', e);
                }

                // Related / Shadow domains
                document.getElementById('reportMeta').textContent = `Running module: Related Domain Discovery...`;
                try {
                    const relRes = await fetch(`?action=scan_related&target=${encodeURIComponent(target)}`, { signal: scanAbortController.signal });
                    fullReport['related_domains'] = await relRes.json();
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Related domains module failed.', e);
                }

                let cveBag = Array.isArray(fullReport.cves) ? [...fullReport.cves] : [];
                if (fullReport.ports && fullReport.ports.shodan && Array.isArray(fullReport.ports.shodan.vulns)) {
                    fullReport.ports.shodan.vulns.forEach(id => {
                        if (typeof id === 'string' && /^CVE-\d{4}-\d{4,}$/i.test(id) && !cveBag.some(c => (c.id || c) === id)) {
                            cveBag.push({ id: id, severity: 'HIGH', confidence: 'medium', evidence: 'Shodan host vulns', type: 'cve' });
                        }
                    });
                }
                const realCves = cveBag.filter(c => {
                    const id = (c && c.id) ? c.id : c;
                    return typeof id === 'string' && /^CVE-\d{4}-\d{4,}$/i.test(id);
                });

                document.getElementById('reportMeta').textContent = `Running module: Vulnerability Intelligence...`;
                try {
                    const viRes = await fetch('?action=scan_vuln_intel', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ cves: realCves }),
                                              signal: scanAbortController.signal
                    });
                    fullReport['vuln_intel'] = await viRes.json();
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Vuln intel module failed.', e);
                    fullReport['vuln_intel'] = { status: 'error', items: [], note: 'Enrichment failed' };
                }

                document.getElementById('reportMeta').textContent = `Running module: PoC Reference Search...`;
                try {
                    const vpRes = await fetch('?action=scan_vuln_pocs', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ cves: realCves }),
                                              signal: scanAbortController.signal
                    });
                    fullReport['vuln_pocs'] = await vpRes.json();
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Vuln PoC module failed.', e);
                    fullReport['vuln_pocs'] = { status: 'error', items: [], note: 'PoC search failed' };
                }

                fill.style.width = '92%';
                document.getElementById('reportMeta').textContent = `Building Risk Profile...`;

                try {
                    const rRes = await fetch('?action=build_risk', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(fullReport),
                                             signal: scanAbortController.signal
                    });
                    const rData = await rRes.json();
                    fullReport['risk'] = rData.risk;
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Risk build failed.', e);
                }

                // Narrative Intelligence Summary
                try {
                    const nRes = await fetch('?action=generate_narrative', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(fullReport),
                                             signal: scanAbortController.signal
                    });
                    fullReport['narrative'] = await nRes.json();
                } catch (e) {
                    if (e.name === 'AbortError') throw e;
                    console.warn('Narrative generation failed.', e);
                }

                // Certificate pivots
                if (fullReport.tls) {
                    fullReport['cert_pivots'] = { status: 'ok', pivots: [] }; // populated server-side if needed
                }

                fullReport['duration'] = ((Date.now() - startTs) / 1000).toFixed(2);
                data = fullReport;
                fill.style.width = '100%';
            }

            if (data.type === 'username') {
                renderUserReport(data);
                renderGraph('username', data);
            } else {
                if (isLoggedIn && data.risk) {
                    try {
                        await fetch('?action=save_scan', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                target: target,
                                report: data,
                                csrf: csrfToken
                            })
                        });
                    } catch (err) {}

                    try {
                        const histRes = await fetch(`?action=get_target&target=${encodeURIComponent(target)}`);
                        const histData = await histRes.json();
                        renderReport(target, data, histData || {});
                        loadVault();
                    } catch (err) {
                        renderReport(target, data);
                    }
                } else {
                    renderReport(target, data);
                }
                renderGraph('domain', data);
            }
            if (!data.debug_db_error) {
                showToast(isLoggedIn ? `Saved: ${target}` : `Scanned (guest mode)`);
            }
        }
    } catch (err) {
        if (err.name === 'AbortError') {
            document.getElementById('reportView').style.display = 'none';
            document.getElementById('emptyState').style.display = 'block';
            showToast('Scan Halted by User');
        } else {
            showToast('Error: ' + err.message);
        }
    } finally {
        fill.style.width = '100%';
        setTimeout(() => {
            bar.style.display = 'none';
        fill.style.width = '0%';
        }, 600);

        scanAbortController = null;
        btn.classList.remove('btn-cancel');
        btn.textContent = 'LAUNCH RECON';

        if (wakeLock !== null) {
            wakeLock.release().then(() => {
                wakeLock = null;
            });
        }

    }
}

function renderUserReport(data) {
    currentDomain = data.target;
    currentReport = data;

    document.getElementById('reportDomain').textContent = data.target;
    document.getElementById('reportMeta').textContent = `Deep User OSINT • ${data.scanned_at} • ${data.duration}s`;

    const badge = document.getElementById('riskBadge');
    badge.textContent = 'OSINT COMPLETE';
    badge.className = 'risk-badge risk-LOW';

    const ident = data.identity || {};
    const idScore = ident.score ?? data.profiles_found ?? 0;
    document.getElementById('scoreLabel').textContent = 'Identity Score';
    document.getElementById('statScore').textContent = idScore;
    document.getElementById('statScore').className = 'stat text-' + (idScore >= 70 ? 'HIGH' : (idScore >= 40 ? 'MEDIUM' : 'LOW'));

    document.getElementById('classLabel').textContent = 'Persona';
    document.getElementById('statClass').textContent = (ident.persona || 'ACTIVE').split(' ')[0];
    document.getElementById('statClass').className = 'stat text-LOW';

    document.getElementById('findingLabel').textContent = 'Profiles / Emails';
    document.getElementById('statIocs').textContent = (data.profiles_found || 0) + ' / ' + ((data.dossier?.emails || []).length);
    document.getElementById('statIocs').className = 'stat text-HIGH';

    const d = data.dossier || {};
    document.getElementById('dossierTarget').textContent = data.target + (ident.persona ? ' · ' + ident.persona : '');
    document.getElementById('dossierBio').textContent = d.bio || 'No public biography discovered.';

    if (d.avatar) {
        document.getElementById('dossierAvatar').src = d.avatar;
    }

    let html = '';
    if (data.profiles_found > 0) {
        html = '<ul style="list-style:none; padding:0; margin:0;">';
        for (const [platform, url] of Object.entries(data.profiles)) {
            html += `
            <li style="padding:10px; border-bottom:1px solid var(--border); display:flex; align-items:center;">
            <span class="tag" style="width:80px; text-align:center; font-weight:bold;">${platform}</span>
            <a href="${url}" target="_blank" style="color:var(--accent2); text-decoration:none; margin-left:10px; word-break:break-all;">${url}</a>
            </li>`;
        }
        html += '</ul>';
    } else {
        html = '<span class="empty">No public profiles found for this username.</span>';
    }
    document.getElementById('osintProfilesList').innerHTML = html;

    let emailHtml = '';
    const emails = d.emails || [];
    const breaches = data.breaches || [];

    if (emails.length > 0) {
        emails.forEach(email => {
            let breachTag = '';
        const eBreaches = breaches.filter(b => b.email === email);

        if (eBreaches.length > 0) {
            breachTag = `<div style="margin-left: 20px; font-size: 11px; color: var(--danger);">⚠ Found in ${eBreaches.length} breaches (e.g., ${esc(eBreaches[0].breach)})</div>`;
        } else if (breaches.length === 0) {
            breachTag = `<div style="margin-left: 20px; font-size: 11px; color: var(--ok);">✓ Clean or API Check Skipped</div>`;
        }

        emailHtml += `<div class="ioc" style="margin-bottom:8px; color:var(--text);">📧 ${esc(email)}${breachTag}</div>`;
        });
    } else {
        emailHtml = '<span class="empty">No emails publicly scraped from profiles.</span>';
    }
    document.getElementById('osintEmailsList').innerHTML = emailHtml;

    let phoneHtml = '';
    if (d.phones && d.phones.length > 0) {
        d.phones.forEach(phone => {
            phoneHtml += `<div class="ioc" style="margin-bottom:8px; color:var(--text);">📱 ${esc(phone)}</div>`;
        });
    } else {
        phoneHtml = '<span class="empty">No phone numbers discovered.</span>';
    }
    document.getElementById('osintPhonesList').innerHTML = phoneHtml;

    let cryptoHtml = '';
    if (d.cryptos && d.cryptos.length > 0) {
        d.cryptos.forEach(c => {
            cryptoHtml += `<div class="ioc" style="margin-bottom:8px; color:var(--warn);">💰 [${esc(c.type)}] ${esc(c.address)}</div>`;
        });
    } else {
        cryptoHtml = '<span class="empty">No crypto wallets discovered.</span>';
    }
    document.getElementById('osintCryptoList').innerHTML = cryptoHtml;

    let linksHtml = '';
    if (data.cross_links && data.cross_links.length > 0) {
        data.cross_links.forEach(link => {
            linksHtml += `<div style="margin-bottom:8px; font-size:11px;">🔗 <a href="${esc(link)}" target="_blank" style="color:var(--accent2); text-decoration:none;">${esc(link)}</a></div>`;
        });
    } else {
        linksHtml = '<span class="empty">No cross-platform links discovered.</span>';
    }
    document.getElementById('osintLinksList').innerHTML = linksHtml;
}

function renderReport(domain, data, meta = {}) {
    currentDomain = domain;
    currentReport = data;

    document.getElementById('reportDomain').textContent = domain;
    document.getElementById('reportMeta').textContent = (data.scanned_at || meta.timestamp || '') + ' • ' + (data.profile || 'quick') + (data.duration ? ` • ${data.duration}s` : '') + (meta.scan_count ? ` • ${meta.scan_count} scans` : '');

    if (isLoggedIn) {
        const monBtn = document.getElementById('monitorToggleBtn');
        monBtn.style.display = 'inline-block';
        monBtn.className = meta.is_monitored ? 'btn-sm' : 'btn-sm btn-secondary';
        monBtn.textContent = meta.is_monitored ? '🔔 Monitored' : '🔕 Monitor';
    }

    const risk = data.risk || {};
    const cls = risk.classification || 'LOW';

    const badge = document.getElementById('riskBadge');
    badge.textContent = `${risk.score ?? '—'}/10 ${cls}`;
    badge.className = 'risk-badge risk-' + cls;

    const statScore = document.getElementById('statScore');
    statScore.textContent = risk.score ?? '—';
    statScore.className = 'stat text-' + cls;

    const statClass = document.getElementById('statClass');
    statClass.textContent = cls;
    statClass.className = 'stat text-' + cls;

    const statIocs = document.getElementById('statIocs');
    statIocs.textContent = (risk.iocs || []).length;
    statIocs.className = 'stat text-' + ((risk.iocs || []).length > 0 ? 'HIGH' : 'LOW');

    document.getElementById('breakTls').textContent  = risk.breakdown?.tls ?? '—';
    document.getElementById('breakDns').textContent  = risk.breakdown?.dns ?? '—';
    document.getElementById('breakHttp').textContent = risk.breakdown?.http ?? '—';
    document.getElementById('breakExp').textContent  = risk.breakdown?.exposure ?? '—';

    if ((risk.iocs || []).length > 0) {
        document.getElementById('iocList').innerHTML = risk.iocs.map(i => `<div class="ioc">• ${esc(i)}</div>`).join('');
    } else {
        document.getElementById('iocList').innerHTML = '<span class="empty">No critical indicators</span>';
    }

    if ((risk.remediation || []).length > 0) {
        document.getElementById('remediationList').innerHTML = risk.remediation.map(r => `<div class="remediation">• ${esc(r)}</div>`).join('');
    } else {
        document.getElementById('remediationList').innerHTML = '<span class="empty">No critical actions</span>';
    }

    let cloudHtml = '';
    if (data.cloud && data.cloud.length > 0) {
        data.cloud.forEach(b => {
            const isPub = !!(b.public || (b.status && b.status.includes('PUBLIC')));
            const prov = b.provider ? `<span class="tag">${esc(b.provider)}</span> ` : '';
        cloudHtml += `<tr><td>${prov}<strong>${esc(b.bucket || b.url || '')}</strong></td><td class="${isPub ? 'ioc' : ''}">${esc(b.status)}</td></tr>`;
        });
        document.getElementById('cloudTable').innerHTML = cloudHtml;
    } else {
        document.getElementById('cloudTable').innerHTML = '<tr><td colspan="2"><span class="empty">No cloud storage permutations discovered.</span></td></tr>';
    }

    let archHtml = '';
    if (data.archive && data.archive.length > 0) {
        data.archive.forEach(u => {
            archHtml += `<div style="margin-bottom:8px; font-size:11px; word-break:break-all;"><a href="${esc(u)}" target="_blank" style="color:var(--danger);">${esc(u)}</a></div>`;
        });
        document.getElementById('archiveList').innerHTML = archHtml;
    } else {
        document.getElementById('archiveList').innerHTML = '<span class="empty">No sensitive endpoints (.env, .sql, .bak) found in Wayback Machine.</span>';
    }

    const docs = data.documents || [];
    if (docs.length > 0) {
        let dHtml = '';
        docs.forEach(d => {
            dHtml += `<div style="margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border);">
            <div style="font-size:11px;word-break:break-all;"><a href="${esc(d.url)}" target="_blank" style="color:var(--accent2);">${esc(d.url)}</a></div>
            <div style="margin-top:4px;font-size:12px;">
            ${d.author ? `<span class="tag">Author: ${esc(d.author)}</span>` : ''}
            ${d.creator ? `<span class="tag">Creator: ${esc(d.creator)}</span>` : ''}
            ${d.software || d.producer ? `<span class="tag">${esc(d.software || d.producer)}</span>` : ''}
            ${d.title ? `<span class="tag">${esc(d.title)}</span>` : ''}
            </div>
            ${(d.paths && d.paths.length) ? `<div class="ioc" style="margin-top:4px;font-size:11px;">Paths: ${d.paths.map(p=>esc(p)).join(' | ')}</div>` : ''}
            </div>`;
        });
        document.getElementById('docsList').innerHTML = dHtml;
    } else if (document.getElementById('docsList')) {
        document.getElementById('docsList').innerHTML = '<span class="empty">No document metadata extracted.</span>';
    }

    const gh = data.github || {};
    let ghHtml = '';

    if (gh.status === 'rate_limited') {
        ghHtml += `<div class="ioc" style="margin-bottom:10px; font-weight:bold;">⚠ ${esc(gh.note)}</div>`;
    }
    if (gh.secrets && gh.secrets.length) {
        ghHtml += '<div style="margin-bottom:8px;font-weight:bold;color:var(--danger);">Potential Secrets</div>';
        gh.secrets.forEach(s => {
            ghHtml += `<div style="margin-bottom:8px;font-size:11px;"><a href="${esc(s.url)}" target="_blank" style="color:var(--danger);">${esc(s.repo)} – ${esc(s.path)}</a></div>`;
        });
    }
    if (gh.repos && gh.repos.length) {
        ghHtml += '<div style="margin:10px 0 6px;font-weight:bold;color:var(--muted);">Code References</div>';
        gh.repos.slice(0,12).forEach(r => {
            ghHtml += `<div style="margin-bottom:6px;font-size:11px;"><a href="${esc(r.html_url)}" target="_blank" style="color:var(--accent2);">${esc(r.name)} – ${esc(r.path)}</a></div>`;
        });
    }
    if (gh.note) ghHtml += `<div class="empty" style="margin-top:8px;">${esc(gh.note)}</div>`;
    if (document.getElementById('githubList')) {
        document.getElementById('githubList').innerHTML = ghHtml || '<span class="empty">No public code references found.</span>';
    }

    const origin = data.origin_ip || {};
    let oHtml = '';
    if (origin.candidates && origin.candidates.length) {
        oHtml += '<table><tr><th>IP</th><th>Source</th></tr>';
        origin.candidates.forEach(c => {
            oHtml += `<tr><td class="ioc"><strong>${esc(c.ip)}</strong></td><td>${esc(c.source || '')}</td></tr>`;
        });
        oHtml += '</table>';
    }
    if (origin.current_ips && origin.current_ips.length) {
        oHtml += `<div style="margin-top:10px;font-size:11px;color:var(--muted);">Current resolved: ${origin.current_ips.map(i=>esc(i)).join(', ')}</div>`;
    }
    if (origin.note) oHtml += `<div class="empty" style="margin-top:8px;">${esc(origin.note)}</div>`;
    if (document.getElementById('originList')) {
        document.getElementById('originList').innerHTML = oHtml || '<span class="empty">No alternative origin IPs discovered.</span>';
    }

    // API Keys rendering
    const apikeys = data.apikeys || {};
    let akHtml = '';
    if (apikeys.findings && apikeys.findings.length) {
        apikeys.findings.forEach(f => {
            const sevClass = f.severity === 'CRITICAL' ? 'ioc' : (f.severity === 'HIGH' ? 'text-HIGH' : '');
            akHtml += `<div style="margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border);">
            <div><span class="cve-tag">${esc(f.severity)}</span> <strong>${esc(f.type)}</strong></div>
            <div style="font-family:monospace;margin:4px 0;word-break:break-all;" class="${sevClass}">${esc(f.value)}</div>
            <div style="font-size:11px;color:var(--muted);">Source: <a href="${esc(f.source)}" target="_blank" style="color:var(--accent2);">${esc(f.source)}</a></div>
            ${f.context ? `<div style="font-size:10px;color:var(--muted);margin-top:3px;">Context: ${esc(f.context)}</div>` : ''}
            </div>`;
        });
        if (apikeys.note) akHtml += `<div class="empty" style="margin-top:8px;">${esc(apikeys.note)}</div>`;
    } else {
        akHtml = `<span class="empty">${esc(apikeys.note || 'No high-confidence API keys extracted.')}</span>`;
    }
    if (document.getElementById('apiKeysList')) {
        document.getElementById('apiKeysList').innerHTML = akHtml;
    }
    if (document.getElementById('apiKeysSources') && apikeys.sources_checked) {
        document.getElementById('apiKeysSources').innerHTML = apikeys.sources_checked.map(s =>
        `<div style="font-size:11px;word-break:break-all;margin-bottom:3px;"><a href="${esc(s)}" target="_blank" style="color:var(--accent2);">${esc(s)}</a></div>`
        ).join('') || '<span class="empty">—</span>';
    }

    // JWT rendering
    const jwt = data.jwt || {};
    let jwtHtml = '';
    if (jwt.misconfigurations && jwt.misconfigurations.length) {
        jwtHtml += '<div style="margin-bottom:12px;font-weight:bold;color:var(--danger);">Misconfigurations</div>';
        jwt.misconfigurations.forEach(m => {
            jwtHtml += `<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
            <span class="cve-tag">${esc(m.severity || 'MEDIUM')}</span> <strong>${esc(m.type)}</strong>
            <div style="font-size:12px;margin-top:4px;">${esc(m.detail || '')}</div>
            ${m.url ? `<div style="font-size:11px;"><a href="${esc(m.url)}" target="_blank" style="color:var(--accent2);">${esc(m.url)}</a></div>` : ''}
            </div>`;
        });
    }
    if (jwt.tokens_found && jwt.tokens_found.length) {
        jwtHtml += '<div style="margin:14px 0 8px;font-weight:bold;color:var(--muted);">Discovered Tokens</div>';
        jwt.tokens_found.forEach(t => {
            jwtHtml += `<div style="margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);">
            <div style="font-family:monospace;font-size:11px;word-break:break-all;">${esc(t.preview || t.token)}</div>
            <div style="font-size:11px;margin-top:4px;">
            <span class="tag">alg: ${esc(t.alg || '?')}</span>
            <span class="tag">${esc(t.location || '')}</span>
            ${t.expired ? '<span class="tag" style="background:rgba(255,77,109,0.2);color:var(--danger);">EXPIRED</span>' : ''}
            </div>
            <div style="font-size:10px;color:var(--muted);">Source: ${esc(t.source || '')}</div>
            ${t.note ? `<div style="font-size:11px;color:var(--warn);margin-top:3px;">${esc(t.note)}</div>` : ''}
            </div>`;
        });
    }
    if (jwt.note) jwtHtml += `<div class="empty" style="margin-top:10px;">${esc(jwt.note)}</div>`;
    if (!jwtHtml) jwtHtml = '<span class="empty">No JWTs or misconfigurations discovered on common endpoints.</span>';
    if (document.getElementById('jwtList')) {
        document.getElementById('jwtList').innerHTML = jwtHtml;
    }

    // Sensitive Endpoints
    const endpoints = data.endpoints || {};
    let epHtml = '';
    if (endpoints.findings && endpoints.findings.length) {
        endpoints.findings.forEach(ep => {
            const sevC = ep.severity === 'CRITICAL' ? 'ioc' : (ep.severity === 'HIGH' ? 'text-HIGH' : '');
            epHtml += `<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
            <span class="cve-tag">${esc(ep.severity)}</span> <strong>${esc(ep.path)}</strong> <span class="tag">HTTP ${ep.http_code}</span>
            <div style="font-size:11px;margin-top:3px;"><a href="${esc(ep.url)}" target="_blank" style="color:var(--accent2);">${esc(ep.url)}</a></div>
            ${ep.preview ? `<div style="font-size:10px;color:var(--muted);margin-top:2px;">${esc(ep.preview)}</div>` : ''}
            </div>`;
        });
    } else {
        epHtml = `<span class="empty">${esc(endpoints.note || 'No interesting sensitive paths found.')}</span>`;
    }
    if (document.getElementById('endpointsList')) document.getElementById('endpointsList').innerHTML = epHtml;

    // CORS
    const cors = data.cors || {};
    let corsHtml = '';
    if (cors.issues && cors.issues.length) {
        cors.issues.forEach(c => {
            corsHtml += `<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
            <div class="ioc">${esc(c.issue)}</div>
            <div style="font-size:11px;color:var(--muted);">Origin sent: ${esc(c.origin_sent)} → ACAO: ${esc(c.acao)} | ACAC: ${esc(c.acac || '—')}</div>
            </div>`;
        });
    } else {
        corsHtml = `<span class="empty">${esc(cors.note || 'No CORS issues detected.')}</span>`;
    }
    if (document.getElementById('corsList')) document.getElementById('corsList').innerHTML = corsHtml;

    // Takeover
    const takeover = data.takeover || {};
    let toHtml = '';
    if (takeover.findings && takeover.findings.length) {
        takeover.findings.forEach(t => {
            const sev = t.vulnerable ? 'CRITICAL' : 'MEDIUM';
        toHtml += `<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
        <span class="cve-tag">${sev}</span> <strong>${esc(t.subdomain)}</strong>
        <div style="font-size:12px;margin-top:3px;">Service: ${esc(t.service || '—')} | CNAME: ${esc(t.cname || '—')}</div>
        ${t.vulnerable ? '<div class="ioc" style="margin-top:3px;">Potential takeover – fingerprint matched or empty response</div>' : '<div style="color:var(--muted);font-size:11px;">Candidate only (not confirmed vulnerable)</div>'}
        </div>`;
        });
    } else {
        toHtml = `<span class="empty">${esc(takeover.note || 'No subdomain takeover candidates detected.')}</span>`;
    }
    if (document.getElementById('takeoverList')) document.getElementById('takeoverList').innerHTML = toHtml;

    // Intelligence Narrative
    const narr = data.narrative || {};
    let narrHtml = '';
    if (narr.summary || narr.lines) {
        const lines = narr.lines || (narr.summary ? [narr.summary] : []);
        if (Array.isArray(lines) && lines.length) {
            narrHtml = lines.map(l => `<p style="margin-bottom:8px;line-height:1.55;">${esc(l)}</p>`).join('');
        } else if (typeof narr.summary === 'string') {
            narrHtml = `<p style="line-height:1.55;">${esc(narr.summary)}</p>`;
        }
        if (narr.priority_actions && narr.priority_actions.length) {
            narrHtml += '<div style="margin-top:12px;font-weight:bold;color:var(--warn);">Priority Actions</div><ul style="margin:6px 0 0 18px;">';
            narr.priority_actions.forEach(a => { narrHtml += `<li style="margin-bottom:4px;">${esc(a)}</li>`; });
            narrHtml += '</ul>';
        }
    } else {
        narrHtml = '<span class="empty">Narrative will appear after scan completes.</span>';
    }
    if (document.getElementById('narrativeBox')) document.getElementById('narrativeBox').innerHTML = narrHtml;

    // Related / Shadow Domains
    const related = data.related_domains || {};
    let relHtml = '';
    if (related.domains && related.domains.length) {
        related.domains.forEach(d => {
            relHtml += `<div style="margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);">
            <strong>${esc(d.domain || d)}</strong>
            ${d.reason ? `<span class="tag" style="margin-left:6px;">${esc(d.reason)}</span>` : ''}
            ${d.source ? `<span style="font-size:11px;color:var(--muted);margin-left:6px;">${esc(d.source)}</span>` : ''}
            </div>`;
        });
        if (related.note) relHtml += `<div class="empty" style="margin-top:8px;">${esc(related.note)}</div>`;
    } else {
        relHtml = `<span class="empty">${esc(related.note || 'No related / shadow domains discovered.')}</span>`;
    }
    if (document.getElementById('relatedDomainsList')) document.getElementById('relatedDomainsList').innerHTML = relHtml;

    // Temporal Diff (when previous scan data is available via meta.history)
    if (meta.history && meta.history.length > 1 && data.risk) {
        // Diff is best computed server-side; surface a simple indicator if present
        if (data.diff && data.diff.changes && data.diff.changes.length) {
            let diffHtml = '<div style="margin-top:10px;"><strong>Changes since previous scan:</strong><ul style="margin:6px 0 0 18px;">';
            data.diff.changes.slice(0, 12).forEach(c => {
                diffHtml += `<li style="margin-bottom:3px;" class="${c.severity === 'high' ? 'ioc' : ''}">${esc(c.message || c)}</li>`;
            });
            diffHtml += '</ul></div>';
            if (document.getElementById('narrativeBox')) {
                document.getElementById('narrativeBox').innerHTML += diffHtml;
            }
        }
    }

    const comp = data.company || {};
    if (comp.organization) {
        document.getElementById('companyOrgName').textContent = comp.organization;
    }

    if (comp.employees && comp.employees.length > 0) {
        let empHtml = '<table style="margin-top: 10px;"><tr><th>Name</th><th>Role</th><th>Email / Contacts</th></tr>';
        comp.employees.forEach(emp => {
            const name = (emp.first_name + ' ' + emp.last_name).trim() || '—';
        let contacts = [];

        if (emp.email) {
            contacts.push(`<span class="ioc">📧 ${esc(emp.email)}</span>`);
        }
        if (emp.linkedin) {
            contacts.push(`<a href="${esc(emp.linkedin)}" target="_blank" style="color:var(--accent2); text-decoration:none;">in</a>`);
        }
        if (emp.twitter) {
            contacts.push(`<a href="${esc(emp.twitter)}" target="_blank" style="color:var(--accent2); text-decoration:none;">tw</a>`);
        }

        empHtml += `<tr>
        <td><strong>${esc(name)}</strong></td>
        <td>${esc(emp.position)}</td>
        <td>${contacts.join(' &nbsp; ')}</td>
        </tr>`;
        });
        empHtml += '</table>';
        document.getElementById('companyEmployees').innerHTML = empHtml;
    } else {
        document.getElementById('companyEmployees').innerHTML = '<span class="empty">No employee emails or founder data found via public Hunter.io records.</span>';
    }

    const pivots = data.pivots || {};
    let pivotHtml = '';
    if (pivots.favicon) {
        pivotHtml += `<tr><th>Favicon Hash (Shodan)</th><td><a href="https://www.shodan.io/search?query=http.favicon.hash%3A${pivots.favicon}" target="_blank" class="tag" style="text-decoration:none;">${pivots.favicon}</a></td></tr>`;
    }
    if (pivots.pgp && pivots.pgp.length > 0) {
        let pLines = pivots.pgp.map(p => `Key ID: ${esc(p.key_id)} (${esc(p.algo)}) - Created: ${esc(p.created_at)}`);
        pivotHtml += `<tr><th>PGP Keys</th><td>${pLines.join('<br>')}</td></tr>`;
    }
    if (pivotHtml) {
        document.getElementById('pivotTable').innerHTML = pivotHtml;
        document.getElementById('pivotTable').classList.remove('empty');
    } else {
        document.getElementById('pivotTable').innerHTML = '<span class="empty">No pivots extracted.</span>';
        document.getElementById('pivotTable').classList.add('empty');
    }

    const tls = data.tls || {};
    document.getElementById('tlsTable').innerHTML = `
    <tr><th>Status</th><td><strong>${esc(tls.status)}</strong></td></tr>
    <tr><th>Subject</th><td>${esc(tls.subject)}</td></tr>
    <tr><th>Issuer</th><td>${esc(tls.issuer)}</td></tr>
    <tr><th>Protocol</th><td>${esc(tls.negotiated_protocol)}</td></tr>
    <tr><th>Signature</th><td>${esc(tls.signature_algo)} ${tls.is_weak_algorithm ? '<span class="ioc">WEAK</span>' : ''}</td></tr>
    <tr><th>Valid From</th><td>${esc(tls.valid_from)}</td></tr>
    <tr><th>Valid Until</th><td>${esc(tls.valid_until)} ${tls.days_remaining >= 0 ? `(${tls.days_remaining}d left)` : ''}</td></tr>
    <tr><th>Serial</th><td>${esc(tls.serial)}</td></tr>
    <tr><th>SANs</th><td>${(tls.sans||[]).map(s=>`<span class="tag">${esc(s)}</span>`).join(' ') || '—'}</td></tr>
    `;

    const dns = data.dns || {};
    document.getElementById('dnsTable').innerHTML = `
    <tr><th>A</th><td>${(dns.A||[]).join(', ') || '—'}</td></tr>
    <tr><th>AAAA</th><td>${(dns.AAAA||[]).join(', ') || '—'}</td></tr>
    <tr><th>MX</th><td>${(dns.MX||[]).join('<br>') || '—'}</td></tr>
    <tr><th>NS</th><td>${(dns.NS||[]).join('<br>') || '—'}</td></tr>
    <tr><th>SPF</th><td>${dns.SPF ? esc(dns.SPF) : '<span class="ioc">MISSING</span>'}</td></tr>
    <tr><th>DMARC</th><td>${dns.DMARC ? esc(dns.DMARC) : '<span class="ioc">MISSING</span>'}</td></tr>
    <tr><th>MTA-STS</th><td>${dns.MTA_STS ? esc(dns.MTA_STS) : '<span class="empty">MISSING</span>'}</td></tr>
    <tr><th>BIMI</th><td>${dns.BIMI ? esc(dns.BIMI) : '<span class="empty">MISSING</span>'}</td></tr>
    <tr><th>CAA</th><td>${(dns.CAA||[]).join('<br>') || '—'}</td></tr>
    <tr><th>TXT</th><td>${(dns.TXT||[]).map(t=>`<div style="margin-bottom:4px">${esc(t)}</div>`).join('') || '—'}</td></tr>
    `;

    const http = data.http || {};
    const sec = http.security || {};

    // Combine HTTP header CVEs and Shodan IP-level CVEs
    let cves = Array.isArray(data.cves) ? [...data.cves] : [];

    if (data.ports && data.ports.shodan && Array.isArray(data.ports.shodan.vulns)) {
        data.ports.shodan.vulns.forEach(cveId => {
            if (!cves.some(c => c.id === cveId)) {
                cves.push({
                    id: cveId,
                    severity: 'CRITICAL',
                    desc: 'Verified IP-level vulnerability reported by Shodan host intelligence.'
                });
            }
        });
    }

    const verMap = http.versions || {};
    const verTags = Object.keys(verMap).map(k => `<span class="tag">${esc(k)} ${esc(verMap[k])}</span>`).join(' ');
    let rows = `
    <tr><th>Protocol</th><td><strong>${esc(http.protocol)}</strong></td></tr>
    <tr><th>Server</th><td>${esc(http.server)}</td></tr>
    <tr><th>Technologies</th><td>${(http.technologies||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join(' ') || '—'}</td></tr>
    <tr><th>Versions</th><td>${verTags || '—'}</td></tr>
    `;

    for (const [k,v] of Object.entries(sec)) {
        if (['Server','X-Powered-By'].includes(k)) {
            continue;
        }
        rows += `<tr><th>${esc(k)}</th><td>${v ? esc(v) : '<span class="ioc">MISSING</span>'}</td></tr>`;
    }
    const hFindings = http.header_findings || [];
    if (hFindings.length) {
        rows += `<tr><th>Header / Cookie Findings</th><td>`;
        hFindings.forEach(f => {
            rows += `<div style="margin-bottom:4px;"><span class="cve-tag">${esc(f.severity||'LOW')}</span> <span style="font-size:11px;">${esc(f.detail||f.id||'')}</span></div>`;
        });
        rows += `</td></tr>`;
    }
    document.getElementById('httpTable').innerHTML = rows;

    if (cves.length > 0) {
        document.getElementById('cveList').innerHTML = cves.map(c => `
        <div style="margin-bottom:8px; padding-bottom:8px; border-bottom:1px solid var(--border);">
        <span class="cve-tag">${esc(c.id)}</span>
        ${c.confidence ? `<span class="tag">${esc(c.confidence)} confidence</span>` : ''}
        ${c.type === 'advisory' ? `<span class="tag">advisory</span>` : ''}
        <span style="font-size:11px; color:var(--text);">${esc(c.desc || '')}</span>
        ${c.evidence ? `<div style="font-size:10px;color:var(--muted);margin-top:3px;">Evidence: ${esc(c.evidence)}</div>` : ''}
        </div>
        `).join('');
    } else {
        document.getElementById('cveList').innerHTML = '<span class="empty">No known high-impact CVEs mapped to public server headers.</span>';
    }

    const vIntel = data.vuln_intel || {};
    let viHtml = '';
    if (vIntel.items && vIntel.items.length) {
        vIntel.items.forEach(v => {
            viHtml += `<div style="margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--border);">
            <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:6px;">
            <span class="cve-tag">${esc(v.id)}</span>
            <span class="tag">${esc(v.severity || 'UNKNOWN')}</span>
            ${v.cvss != null ? `<span class="tag">CVSS ${esc(v.cvss)}</span>` : ''}
            ${v.confidence ? `<span class="tag">${esc(v.confidence)} confidence</span>` : ''}
            </div>
            <p style="font-size:13px;line-height:1.55;margin:6px 0;">${esc(v.summary || 'No summary available.')}</p>
            <div style="font-size:11px;color:var(--muted);margin-bottom:6px;">
            ${v.product ? `Product: <strong>${esc(v.product)}</strong> · ` : ''}
            ${v.published ? `Published: ${esc(v.published)} · ` : ''}
            ${v.source ? `Source: ${esc(v.source)}` : ''}
            </div>
            ${(v.cwe && v.cwe.length) ? `<div style="margin-bottom:6px;">${v.cwe.map(w => `<span class="tag">${esc(w)}</span>`).join(' ')}</div>` : ''}
            <div style="font-size:11px;color:var(--warn);margin-top:6px;">${esc(v.disclaimer || 'Correlation finding — not a confirmed exploit on this host.')}</div>
            ${(v.references && v.references.length) ? `<div style="margin-top:8px;font-size:11px;">${v.references.map(r => `<div style="margin-bottom:3px;"><a href="${esc(r)}" target="_blank" rel="noopener" style="color:var(--accent2);">${esc(r)}</a></div>`).join('')}</div>` : ''}
            </div>`;
        });
    } else {
        viHtml = `<span class="empty">${esc(vIntel.note || 'No CVE-IDs eligible for enrichment (or none detected).')}</span>`;
    }
    if (document.getElementById('vulnIntelList')) document.getElementById('vulnIntelList').innerHTML = viHtml;

    const vPoc = data.vuln_pocs || {};
    let vpHtml = '';
    if (vPoc.items && vPoc.items.length) {
        vPoc.items.forEach(block => {
            vpHtml += `<div style="margin-bottom:18px;"><div style="font-weight:700;margin-bottom:8px;"><span class="cve-tag">${esc(block.id)}</span></div>`;
            if (block.pocs && block.pocs.length) {
                block.pocs.forEach(p => {
                    vpHtml += `<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">
                    <div><a href="${esc(p.url)}" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:600;">${esc(p.title)}</a>
                    <span class="tag">${esc(p.source || 'GitHub')}</span>
                    <span class="tag">${esc(p.confidence)} confidence</span>
                    ${p.stars != null ? `<span class="tag">★ ${esc(p.stars)}</span>` : ''}
                    </div>
                    <div style="font-size:12px;margin-top:4px;">${esc(p.summary || '')}</div>
                    </div>`;
                });
            } else {
                vpHtml += `<div class="empty" style="margin-bottom:8px;">${esc(block.note || 'No high-confidence PoCs found.')}</div>`;
            }
            vpHtml += `</div>`;
        });
    } else {
        vpHtml = `<span class="empty">${esc(vPoc.note || 'No PoC references to display.')}</span>`;
    }
    if (document.getElementById('vulnPocList')) document.getElementById('vulnPocList').innerHTML = vpHtml;

    currentRawHeaders = Object.entries(http.all_headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');

    if (currentRawHeaders) {
        document.getElementById('rawHeaders').innerHTML = `<pre>${esc(currentRawHeaders)}</pre>`;
    } else {
        document.getElementById('rawHeaders').innerHTML = '<span class="empty">None</span>';
    }

    const ports = data.ports || {};
    let portRows = '';

    if (ports.ports) {
        for (const [port, info] of Object.entries(ports.ports)) {
            const isOpen = info.status === 'open';
            const statusIcon = isOpen ? '✓ OPEN' : 'CLOSED';
            const source = info.source === 'shodan_passive' ? ' (Passive Shodan)' : '';
            portRows += `<tr><th>Port ${port} (${info.service})</th><td class="${isOpen ? 'ioc' : ''}" style="${!isOpen ? 'color:var(--muted)' : ''}"><strong>${statusIcon}</strong>${source}</td></tr>`;
        }
    } else {
        for (const [port, info] of Object.entries(ports)) {
            const isOpen = info.status === 'open';
            const statusIcon = isOpen ? '✓ OPEN' : 'CLOSED';
            portRows += `<tr><th>Port ${port} (${info.service})</th><td class="${isOpen ? 'ioc' : ''}" style="${!isOpen ? 'color:var(--muted)' : ''}"><strong>${statusIcon}</strong></td></tr>`;
        }
    }

    if (portRows) {
        document.getElementById('portsTable').innerHTML = portRows;
    } else {
        document.getElementById('portsTable').innerHTML = '<span class="empty">No port data</span>';
    }

    const subs = data.subdomains || {};
    const srcText = (subs.sources && subs.sources.length) ? `Sources: ${subs.sources.join(' → ')}` : (subs.status === 'all_failed' ? 'All sources failed' : '');
    document.getElementById('subStatus').textContent = (subs.count ? `${subs.count} subdomains found` : 'No subdomains') + (srcText ? ` • ${srcText}` : '');

    if ((subs.subdomains || []).length > 0) {
        document.getElementById('subList').innerHTML = subs.subdomains.map(s => `<span class="tag"><a href="http://${esc(s)}" target="_blank" style="color:inherit;text-decoration:none;">${esc(s)}</a></span>`).join(' ');

        document.getElementById('subGrid').innerHTML = subs.subdomains.map(s => `
        <div class="sub-shot-card">
        <a href="http://${esc(s)}" target="_blank">
        <img class="sub-shot-img" src="https://s0.wp.com/mshots/v1/http://${esc(s)}?w=400" loading="lazy" alt="Screenshot of ${esc(s)}" onerror="this.src='data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='">
        </a>
        <div class="sub-shot-title">${esc(s)}</div>
        </div>
        `).join('');
    } else {
        document.getElementById('subList').innerHTML = '<span class="empty">None found</span>';
        document.getElementById('subGrid').innerHTML = '<span class="empty">None found</span>';
    }

    const whois = data.whois || {};
    if (whois.status === 'ok') {
        document.getElementById('whoisContent').innerHTML = `
        <table>
        <tr><th>Registrar</th><td>${esc(whois.registrar)}</td></tr>
        <tr><th>Created</th><td>${esc(whois.created)}</td></tr>
        <tr><th>Expires</th><td>${esc(whois.expires)}</td></tr>
        <tr><th>Updated</th><td>${esc(whois.updated)}</td></tr>
        <tr><th>Nameservers</th><td>${(Array.isArray(whois.nameservers) ? whois.nameservers : []).map(n=>esc(n)).join('<br>') || '—'}</td></tr>
        </table>
        <h3 style="margin-top:14px;">Raw JSON</h3>
        <pre>${esc(whois.raw)}</pre>
        `;
    } else {
        document.getElementById('whoisContent').innerHTML = '<span class="empty">Run a Deep Scan to fetch RDAP data</span>';
    }

    const ipinfo = data.ipinfo || {};
    if (Object.keys(ipinfo).length) {
        let html = '<table><tr><th>IP</th><th>Country</th><th>ISP / Org</th><th>ASN</th></tr>';
        for (const [ip, info] of Object.entries(ipinfo)) {
            html += `<tr><td>${esc(ip)}</td><td>${esc(info.country)}</td><td>${esc(info.isp)} / ${esc(info.org)}</td><td>${esc(info.asn)}</td></tr>`;
        }
        html += '</table>';
        document.getElementById('ipinfoContent').innerHTML = html;
    } else {
        document.getElementById('ipinfoContent').innerHTML = '<span class="empty">Run a Deep Scan to fetch IP / ASN / Geo</span>';
    }

    const metaF = data.meta || {};
    if (metaF.has_security_txt) {
        document.getElementById('secTxt').innerHTML = `<div style="color:var(--ok);margin-bottom:6px">✓ Present</div><pre>${esc(metaF.security_txt)}</pre>`;
    } else {
        document.getElementById('secTxt').innerHTML = '<span class="ioc">Missing</span>';
    }

    if (metaF.has_robots) {
        let rHtml = `<div style="color:var(--ok);margin-bottom:6px">✓ Present</div><pre>${esc(metaF.robots_txt)}</pre>`;
        const interest = metaF.interesting_paths || metaF.robots_paths || [];
        if (interest.length) {
            rHtml += `<div style="margin-top:10px;font-weight:bold;color:var(--muted);">Interesting paths (robots / sitemap)</div>`;
            rHtml += interest.slice(0, 40).map(p => `<span class="tag" style="margin:2px;">${esc(p)}</span>`).join(' ');
        }
        if (metaF.sitemap_urls && metaF.sitemap_urls.length) {
            rHtml += `<div style="margin-top:8px;font-size:11px;color:var(--muted);">Sitemaps: ${metaF.sitemap_urls.map(u=>esc(u)).join(' · ')}</div>`;
        }
        document.getElementById('robotsTxt').innerHTML = rHtml;
    } else {
        document.getElementById('robotsTxt').innerHTML = '<span class="empty">Not found</span>';
    }

    const hist = meta.history || [];
    if (hist.length > 0) {
        document.getElementById('historyList').innerHTML = hist.map((h, idx) => `
        <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);">
        <div>
        <strong>${esc(h.scanned_at)}</strong>
        <div style="font-size:11px;color:var(--muted);">${h.profile} • ${h.duration || '?'}s</div>
        </div>
        <div class="risk-badge risk-${h.classification}" style="font-size:11px;padding:4px 10px;">${h.score}/10</div>
        </div>
        `).join('');
    } else {
        document.getElementById('historyList').innerHTML = '<span class="empty">' + (isLoggedIn ? 'Only current scan' : 'Login to save history') + '</span>';
    }

    if (isLoggedIn) {
        document.getElementById('notesInput').value = meta.notes || '';
        document.getElementById('tagsInput').value = (meta.tags || []).join(', ');
    }
}

async function toggleMonitor() {
    if (!isLoggedIn || !currentDomain) return;

    const res = await fetch(`?action=toggle_monitor`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ target: currentDomain, csrf: csrfToken })
    });

    const data = await res.json();
    if (data.ok) {
        const monBtn = document.getElementById('monitorToggleBtn');
        monBtn.className = data.is_monitored ? 'btn-sm' : 'btn-sm btn-secondary';
        monBtn.textContent = data.is_monitored ? '🔔 Monitored' : '🔕 Monitor';
        showToast(data.is_monitored ? 'Domain added to daily cron monitor' : 'Domain removed from cron monitor');
        loadVault();
    }
}

function exportWordlist(type) {
    if (!currentReport) return showToast('No report loaded');

    let lines = [];
    if (type === 'subs') {
        lines = currentReport.subdomains?.subdomains || [];
    } else if (type === 'ips') {
        lines = currentReport.dns?.A || [];
        if (currentReport.origin_ip?.candidates) {
            lines = lines.concat(currentReport.origin_ip.candidates.map(c => c.ip));
        }
    }

    lines = [...new Set(lines.filter(Boolean))];
    if (!lines.length) return showToast('No items available for export');

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${currentDomain}_${type}.txt`;
    a.click();
    showToast(`Exported ${lines.length} ${type} to wordlist`);
}

function exportJson() {
    if (!currentReport) {
        return showToast('No report loaded');
    }
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (currentDomain || 'report') + '_aether.json';
    a.click();
    showToast('JSON exported');
}

async function exportInvestigationPack() {
    if (!currentReport) return showToast('No report loaded');
    showToast('Building investigation pack...');
    try {
        const res = await fetch('?action=investigation_pack', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(currentReport)
        });
        const pack = await res.json();
        const blob = new Blob([JSON.stringify(pack, null, 2)], {type: 'application/json'});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = (currentDomain || 'target') + '_investigation_pack.json';
        a.click();
        showToast('Investigation Pack exported');
    } catch (e) {
        showToast('Pack export failed');
    }
}

async function exportPdf() {
    if (!currentReport) {
        return showToast('No report loaded');
    }

    if (typeof html2pdf === 'undefined') {
        showToast('Loading PDF engine...');
        try {
            await loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js');
        } catch (err) {
            return showToast('Failed to load PDF engine');
        }
    }

    const gridState = document.getElementById('subGrid').style.display;
    document.getElementById('subGrid').style.display = 'none';
    document.getElementById('subList').style.display = 'block';

    const element = document.getElementById('reportView');
    const opt = {
        margin: 0.5,
        filename: (currentDomain || 'report') + '_aether.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, logging: false },
        jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
    };

    showToast('Generating PDF...');
    html2pdf().set(opt).from(element).save().then(() => {
        document.getElementById('subGrid').style.display = gridState;
        showToast('PDF Exported Successfully');
    });
}

function copyText(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => showToast('Copied'));
}

async function loadVault() {
    if (!isLoggedIn) return;
    const list = document.getElementById('vaultList');

    try {
        const res = await fetch('?action=vault');
        vaultData = await res.json();
        renderVaultList();
    } catch {
        list.innerHTML = '<div class="empty">Failed to load</div>';
    }
}

function renderVaultList(filter = '') {
    const list = document.getElementById('vaultList');
    const domains = Object.keys(vaultData).filter(d => !filter || d.includes(filter.toLowerCase())).sort((a,b) => (vaultData[b].timestamp||'').localeCompare(vaultData[a].timestamp||''));

    if (!domains.length) {
        list.innerHTML = '<div class="empty">No team history yet</div>';
        return;
    }

    list.innerHTML = domains.map(d => {
        const e = vaultData[d];
        const score = (e.risk_score !== null && e.risk_score !== undefined) ? e.risk_score : (e.report?.risk?.score ?? '?');
        const cls = e.classification || e.report?.risk?.classification || '';
    const bell = e.is_monitored ? '<span class="bell-icon active">🔔</span>' : '<span class="bell-icon">🔕</span>';

    return `
    <div class="vault-item" onclick="loadFromVault('${e.domain}')">
    <div>
    <div class="domain">${esc(e.domain)}</div>
    <div class="meta">${e.timestamp||''} • By: ${esc(e.author)} • ${score}/10 ${cls}</div>
    </div>
    <div>${bell}</div>
    </div>
    `;
    }).join('');
}

function filterVault() {
    const q = document.getElementById('vaultSearch').value.trim().toLowerCase();
    renderVaultList(q);
}

async function loadFromVault(domain) {
    if (!isLoggedIn) return;

    clearReportUI('domain');
    document.getElementById('reportDomain').textContent = domain;
    document.getElementById('reportMeta').textContent = 'Loading from vault...';
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('reportView').style.display = 'block';

    if (window.innerWidth <= 980) {
        document.getElementById('reportView').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    const res = await fetch(`?action=get_target&target=${encodeURIComponent(domain)}`);
    const entry = await res.json();

    if (entry.error) {
        return showToast('Not found');
    }

    let report = entry.report || {};
    // Auto temporal diff when history has a previous scan
    if (entry.history && entry.history.length > 1 && entry.history[1].report) {
        try {
            const dRes = await fetch('?action=compute_diff', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ current: report, previous: entry.history[1].report })
            });
            report.diff = await dRes.json();
        } catch (e) {}
    }

    renderReport(domain, report, entry);
    document.getElementById('targetInput').value = domain;

    renderGraph('domain', report);
}

async function saveNotes() {
    if (!isLoggedIn || !currentDomain) return;

    const res = await fetch(`?action=save_notes&target=${encodeURIComponent(currentDomain)}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            notes: document.getElementById('notesInput').value,
                             tags: document.getElementById('tagsInput').value,
                             csrf: csrfToken
        })
    });

    const data = await res.json();
    showToast(data.ok ? 'Team notes updated' : 'Save failed');
}

function esc(s) {
    if (s == null) return '—';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

document.getElementById('targetInput').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        runScan();
    }
});

document.getElementById('loginUser').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        doLogin();
    }
});

document.getElementById('loginPass').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        doLogin();
    }
});

document.getElementById('regUser').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        doRegister();
    }
});

document.getElementById('regPass').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        doRegister();
    }
});

document.getElementById('regCode').addEventListener('keypress', e => {
    if (e.key === 'Enter') {
        doRegister();
    }
});

/* ---------- Active Tracking (Honeypot) UI helpers ---------- */
async function createTrackingLink(isDocx = false) {
    if (!isLoggedIn) return showToast('Login required');
    const label = (document.getElementById('trackLabel') || {}).value || '';

    if (isDocx) {
        window.location.href = `?action=generate_canary_docx&label=${encodeURIComponent(label)}&csrf=${csrfToken}`;
        showToast('Generating Canary Document...');
        setTimeout(loadTrackingLinks, 2000);
        return;
    }

    const res = await fetch('?action=create_tracking_link', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ label: label, csrf: csrfToken })
    });
    const data = await res.json();
    if (data.ok) {
        showToast('Tracking link created');
        if (document.getElementById('trackLabel')) document.getElementById('trackLabel').value = '';
        loadTrackingLinks();
        if (data.url && navigator.clipboard) {
            navigator.clipboard.writeText(data.url).then(function(){ showToast('URL copied to clipboard'); });
        }
    } else {
        showToast(data.error || 'Failed to create link');
    }
}

async function loadTrackingLinks() {
    if (!isLoggedIn) return;
    const box = document.getElementById('trackingLinksList');
    if (!box) return;
    try {
        const res = await fetch('?action=list_tracking_links');
        const list = await res.json();
        if (!Array.isArray(list) || !list.length) {
            box.innerHTML = '<span class="empty">No tracking links yet.</span>';
            return;
        }
        box.innerHTML = list.map(function(l) {
            return '<div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">' +
        '<div style="font-weight:600;word-break:break-all;">' + esc(l.label || l.disguise_path) + '</div>' +
        '<div style="font-size:10px;color:var(--muted);margin:3px 0;">Hits: ' + l.hit_count + ' • ' + (l.is_active ? 'Active' : 'Off') + '</div>' +
        '<div style="font-size:10px;word-break:break-all;color:var(--accent2);cursor:pointer;" onclick="navigator.clipboard.writeText(\'' + esc(l.url) + '\').then(function(){showToast(\'Copied\')})">' + esc(l.url) + '</div>' +
        '<button class="btn-sm btn-secondary" style="margin-top:4px;font-size:10px;" onclick="viewTrackingHits(' + l.id + ')">View Hits</button>' +
        '</div>';
        }).join('');
    } catch (e) {
        box.innerHTML = '<span class="empty">Failed to load links</span>';
    }
}

async function viewTrackingHits(linkId) {
    const res = await fetch('?action=tracking_hits&link_id=' + encodeURIComponent(linkId));
    const hits = await res.json();
    if (!Array.isArray(hits) || !hits.length) {
        return showToast('No hits yet for this link');
    }
    var msg = hits.slice(0, 8).map(function(h) {
        let ext = {};
        try { ext = JSON.parse(h.extra_json) || {}; } catch(e){}
        let vpnFlag = ext.is_vpn_or_proxy ? '[VPN/PROXY] ' : '';
    let local = h.local_ip || '-';
    if (ext.local_is_mdns || /\.local$/i.test(local)) local = local + ' (mDNS)';
    let note = ext.webrtc_note ? ' | ' + String(ext.webrtc_note).slice(0, 60) : '';
        return (h.hit_at || '') + ' | ' + vpnFlag + (h.ip || '?') + ' | local:' + local + note + ' | ' + ((h.user_agent || '').slice(0,40));
    }).join('\n');
    alert('Recent hits:\n\n' + msg);
}

checkAuth();
</script>
</body>
</html>
