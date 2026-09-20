<?php
/**
 * Aether Recon v14.6 — Configuration
 * Security hardened: proper error reporting, strict settings.
 */

/* ====================== ERROR HANDLING (Fix #8) ====================== */
// Fix: Replace error_reporting(0) with proper logging
error_reporting(E_ALL);
ini_set('display_errors', '0');      // Never show errors to users
ini_set('log_errors', '1');          // Log all errors
ini_set('error_log', __DIR__ . '/../aether_error.log');
ini_set('max_execution_time', 300);
date_default_timezone_set('UTC');

/* ====================== SHUTDOWN HANDLER ====================== */
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        if (ob_get_level()) {
            ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        // Fix: Don't leak internal error details to users in production
        error_log('Fatal: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
        echo json_encode([
            'error' => 'Internal server error. Check logs for details.'
        ]);
        exit;
    }
});

/* ====================== ENVIRONMENT LOADER ====================== */
// A lightweight .env parser so you don't need to install Composer yet
$envFile = dirname(__DIR__) . '/.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value, " \t\n\r\0\x0B\"'"); // Strip whitespace and quotes
            if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }
}

// Helper to safely get env vars with an optional fallback
function env($key, $default = '') {
    $value = getenv($key);
    return $value !== false ? $value : $default;
}

/* ====================== DATABASE CONFIG ====================== */
define('DB_HOST',           env('DB_HOST', 'localhost'));
define('DB_NAME',           env('DB_NAME', 'obeywevy_osint'));
define('DB_USER',           env('DB_USER', 'obeywevy_osint'));
define('DB_PASS',           env('DB_PASS', ''));
define('DB_ENABLED',        filter_var(env('DB_ENABLED', true), FILTER_VALIDATE_BOOLEAN));

/* ====================== APPLICATION CONFIG ====================== */
define('REGISTRATION_CODE', env('REGISTRATION_CODE', 'Jisjt9064026060'));
define('KEEP_SCANS',        25);
define('APP_VERSION',       '14.6');
define('RATE_LIMIT_SCANS',  5000);
define('STEALTH_MODE',       true);
define('STEALTH_DELAY_MS',   400);
define('STEALTH_MAX_CONCURRENCY', 3);
define('DEFAULT_PERSONA',    'chrome');

/* ====================== PROXY CONFIG ====================== */
define('PROXY_ENABLED',      false);
define('PROXY_ADDR',         '127.0.0.1:9050');
define('PROXY_TYPE',         CURLPROXY_SOCKS5);

/* ====================== PATHS ====================== */
define('CACHE_DIR',         dirname(__DIR__) . '/aether_cache');
define('LOG_FILE',          dirname(__DIR__) . '/aether_recon.log');
define('CRON_SECRET',       env('CRON_SECRET', 'AetherCronSec_9921'));

/* ====================== API CREDENTIALS ====================== */
define('SHODAN_API_KEY',    env('SHODAN_API_KEY'));
define('CENSYS_API_ID',     env('CENSYS_API_ID'));
define('CENSYS_API_SECRET', env('CENSYS_API_SECRET'));
define('ALIENVAULT_API_KEY',env('ALIENVAULT_API_KEY'));
define('HACKERTARGET_KEY',  env('HACKERTARGET_KEY'));
define('HUNTER_API_KEY',    env('HUNTER_API_KEY'));
define('GITHUB_TOKEN',      env('GITHUB_TOKEN'));
define('SECURITYTRAILS_KEY',env('SECURITYTRAILS_KEY'));

/* ====================== CACHE DIRECTORY SETUP ====================== */
if (!is_dir(CACHE_DIR)) {
    mkdir(CACHE_DIR, 0750, true);
    file_put_contents(CACHE_DIR . '/.htaccess', "Require all denied");
}
