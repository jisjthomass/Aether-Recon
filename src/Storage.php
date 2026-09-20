<?php
/**
 * Aether Recon v14.6 — Storage & Authentication Layer
 * Security hardened: SQL strict mode (Fix #6), password complexity + account lockout (Fix #5).
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/helpers.php';

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
            // Fix #6: Enable SQL strict mode instead of disabling it
            self::$pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
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
                             failed_logins INT DEFAULT 0,
                             locked_until DATETIME DEFAULT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");

            // Fix #5: Add lockout columns if they don't exist (for existing databases)
            try {
                self::$pdo->exec("ALTER TABLE users ADD COLUMN failed_logins INT DEFAULT 0");
            } catch (\Throwable $e) {} // Column may already exist
            try {
                self::$pdo->exec("ALTER TABLE users ADD COLUMN locked_until DATETIME DEFAULT NULL");
            } catch (\Throwable $e) {} // Column may already exist

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

    /**
     * Fix #5: Validate password complexity.
     * Requires: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit.
     */
    private static function validatePasswordStrength(string $password): ?string {
        if (strlen($password) < 8) {
            return 'Password must be at least 8 characters';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return 'Password must contain at least one uppercase letter';
        }
        if (!preg_match('/[a-z]/', $password)) {
            return 'Password must contain at least one lowercase letter';
        }
        if (!preg_match('/[0-9]/', $password)) {
            return 'Password must contain at least one number';
        }
        return null; // Valid
    }

    public static function register($username, $password, $code) {
        if (!self::ping()) {
            return ['error' => 'Database offline'];
        }
        if ($code !== REGISTRATION_CODE) {
            return ['error' => 'Invalid team code'];
        }
        if (strlen($username) < 3) {
            return ['error' => 'Username must be at least 3 characters'];
        }

        // Fix #5: Enforce password complexity
        $pwError = self::validatePasswordStrength($password);
        if ($pwError) {
            return ['error' => $pwError];
        }

        try {
            $hash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
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
            $stmt = self::$pdo->prepare("SELECT id, username, password_hash, failed_logins, locked_until FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user) {
                return ['error' => 'Invalid credentials'];
            }

            // Fix #5: Check account lockout
            if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                $remaining = ceil((strtotime($user['locked_until']) - time()) / 60);
                return ['error' => "Account locked. Try again in {$remaining} minutes."];
            }

            if (password_verify($password, $user['password_hash'])) {
                // Reset failed login counter on success
                $stmt = self::$pdo->prepare("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?");
                $stmt->execute([$user['id']]);

                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                return ['ok' => true, 'username' => $user['username']];
            }

            // Fix #5: Track failed logins and lockout after 5 attempts
            $failures = ((int)$user['failed_logins']) + 1;
            if ($failures >= 5) {
                // Lock for 15 minutes
                $stmt = self::$pdo->prepare("UPDATE users SET failed_logins = ?, locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id = ?");
                $stmt->execute([$failures, $user['id']]);
                return ['error' => 'Too many failed attempts. Account locked for 15 minutes.'];
            } else {
                $stmt = self::$pdo->prepare("UPDATE users SET failed_logins = ? WHERE id = ?");
                $stmt->execute([$failures, $user['id']]);
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
