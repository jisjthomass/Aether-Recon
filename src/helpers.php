<?php
/**
 * Aether Recon v14.6 — Helper Functions
 * Security hardened: atomic file locking for rate limiter, generic rate limit for all endpoints.
 */

require_once __DIR__ . '/../config/config.php';

/**
 * Log a message to the application log file.
 */
function log_msg(string $msg): void {
    file_put_contents(LOG_FILE, date('c') . ' ' . $msg . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * Get the client's real IP address (Cloudflare-aware).
 */
function get_client_ip(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Rate limiter with atomic file locking (Fix #7 — Race Conditions).
 *
 * Uses flock() to prevent TOCTOU race conditions where concurrent
 * requests could read the same counter and bypass the limit.
 *
 * @param string $action The action being rate-limited (e.g. 'scan')
 * @return bool True if the request is allowed, false if rate-limited
 */
function rate_limit_check(string $action = 'scan'): bool {
    // Logged-in users bypass rate limiting
    if (class_exists('Storage') && Storage::isLoggedIn()) {
        return true;
    }

    $ip = preg_replace('/[^0-9a-fA-F:.]/', '', get_client_ip());
    $file = CACHE_DIR . '/rl_' . md5($ip . $action) . '.json';
    $now = time();

    // Fix #7: Use flock() for atomic read-modify-write
    $fp = fopen($file, 'c+');
    if (!$fp) {
        return true; // Fail open if file can't be created
    }

    flock($fp, LOCK_EX);

    $raw = stream_get_contents($fp);
    $data = $raw ? (json_decode($raw, true) ?: ['count' => 0, 'start' => $now]) : ['count' => 0, 'start' => $now];

    // Reset window after 1 hour
    if ($now - $data['start'] > 3600) {
        $data = ['count' => 0, 'start' => $now];
    }

    if ($data['count'] >= RATE_LIMIT_SCANS) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }

    $data['count']++;

    // Atomic write
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);

    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}

/**
 * Generate or retrieve the CSRF token for the current session.
 */
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

/**
 * Validate a CSRF token against the session token.
 */
function csrf_check(string $token): bool {
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$token);
}
