<?php
/**
 * Aether Recon v14.6 — Public Entry Point
 * Security hardened: rate limiting, SSRF pinning, domain validation, XSS prevention
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../src/helpers.php';
require_once __DIR__ . '/../src/Storage.php';
require_once __DIR__ . '/../src/UsernameRecon.php';
require_once __DIR__ . '/../src/AetherRecon.php';

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

/* ====================== API ROUTER ====================== */
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $persona = AetherRecon::resolvePersona($_GET['persona'] ?? $_POST['persona'] ?? ($input['persona'] ?? null));
    AetherRecon::$requestPersona = $persona;


    // Captured Password Check (Optional API Unlock)
    $pwd = $_POST['pwd'] ?? $_GET['pwd'] ?? $input['pwd'] ?? '';

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
    if ($target !== '' && !filter_var($target, FILTER_VALIDATE_IP) && !AetherRecon::validateDomain($target)) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Invalid domain format.']);
        exit;
    }
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


    if (!empty($ips)) {
        AetherRecon::setResolvedTarget($target, $ips);
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

    // Fix: Apply rate limiting to ALL scan endpoints, not just scan_user
    $rateActions = ['scan_tls','scan_dns','scan_http','scan_cloud','scan_archive','scan_subs',
                    'scan_pivots','scan_apikeys','scan_jwt','scan_takeover','scan_cors',
                    'scan_endpoints','scan_vuln_intel','scan_vuln_pocs','scan_related',
                    'scan_meta_ports_company_github_origin_whois','scan_user'];
    if (in_array($action, $rateActions) && !rate_limit_check('scan')) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Rate limit exceeded.']);
        exit;
    }

    if ($action === 'scan_user' && $target) {
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

        $label = $_POST['label'] ?? $_GET['label'] ?? 'Canary Document';
        $link = Storage::createTrackingLink($label);
        if (isset($link['error'])) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => $link['error']]);
            exit;
        }

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
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'ZipArchive creation failed']);
            exit;
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
    $tokJson = json_encode($token, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
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

<link rel="stylesheet" href="assets/style.css">
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

<script src="assets/app.js"></script>
</body>
</html>
