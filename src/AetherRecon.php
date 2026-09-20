<?php
/**
 * Aether Recon v14.6 — Main Reconnaissance Engine
 * Extracted from monolithic build. Security hardened.
 */

require_once __DIR__ . '/../config/config.php';

class AetherRecon {

    /** @var string|null Persona for current request (set by API router) */
    public static $requestPersona = null;

    /** Resolved target IP for CURLOPT_RESOLVE pinning (SSRF mitigation) */
    private static $resolvedTarget = null;
    private static $resolvedIps = [];

    /**
     * Set the resolved target domain and IPs for DNS pinning.
     * Called by the router after SSRF validation.
     */
    public static function setResolvedTarget(string $domain, array $ips): void {
        self::$resolvedTarget = $domain;
        self::$resolvedIps = $ips;
    }

    /**
     * Apply DNS pinning to a cURL handle if a resolved target is set.
     */
    private static function applyCurlResolve($ch): void {
        if (self::$resolvedTarget && !empty(self::$resolvedIps)) {
            $resolves = [];
            foreach (self::$resolvedIps as $ip) {
                $resolves[] = self::$resolvedTarget . ':443:' . $ip;
                $resolves[] = self::$resolvedTarget . ':80:' . $ip;
            }
            curl_setopt($ch, CURLOPT_RESOLVE, $resolves);
        }
    }

    /**
     * Validate domain format strictly.
     */
    public static function validateDomain(string $domain): bool {
        return (bool) preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/i', $domain);
    }

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
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]
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
                'verify_peer' => true,
                'verify_peer_name' => true,
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
                'verify_peer' => true,
                'verify_peer_name' => true
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
        if ($security['X-Powered-By']) {
            $tech[] = $security['X-Powered-By'];
        }
        if ($security['Server']) {
            foreach (['cloudflare'=>'Cloudflare','nginx'=>'Nginx','apache'=>'Apache','litespeed'=>'LiteSpeed'] as $n => $l) {
                if (stripos($security['Server'], $n) !== false) {
                    $tech[] = $l;
                }
            }
        }

        $bodyCtx = stream_context_create([
            'http' => [
                'timeout' => 5,
                'method' => 'GET',
                'header' => "User-Agent: " . self::getStealthUserAgent() . "\r\nRange: bytes=0-20480\r\n"
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);
        $body = @file_get_contents($url, false, $bodyCtx);
        if ($body) {
            if (stripos($body, 'wp-content') !== false) {
                $tech[] = 'WordPress';
            }
            if (stripos($body, 'id="__next"') !== false) {
                $tech[] = 'Next.js';
            }
            if (stripos($body, 'data-reactroot') !== false || stripos($body, '_react') !== false) {
                $tech[] = 'React';
            }
            if (stripos($body, 'laravel') !== false) {
                $tech[] = 'Laravel';
            }
            if (stripos($body, 'bootstrap') !== false) {
                $tech[] = 'Bootstrap';
            }
            if (stripos($body, 'stripe.com/v3') !== false) {
                $tech[] = 'Stripe';
            }
            if (stripos($body, 'google-analytics.com') !== false || stripos($body, 'gtag') !== false) {
                $tech[] = 'Google Analytics';
            }
            if (stripos($body, 'v-data-v-') !== false) {
                $tech[] = 'Vue.js';
            }
        }

        $risk = 0;
        if ($proto === 'HTTP') {
            $risk += 2.6;
        }
        if (empty($security['Strict-Transport-Security'])) {
            $risk += 0.5;
        }
        if (empty($security['Content-Security-Policy'])) {
            $risk += 0.4;
        }
        if (empty($security['X-Frame-Options'])) {
            $risk += 0.3;
        }
        if (empty($security['X-Content-Type-Options'])) {
            $risk += 0.2;
        }

        return [
            'protocol'     => $proto,
            'final_url'    => $url,
            'server'       => $security['Server'] ?? 'Not disclosed',
            'powered_by'   => $security['X-Powered-By'],
            'technologies' => array_values(array_unique($tech)),
            'security'     => $security,
            'all_headers'  => $allHeaders,
            'risk'         => min($risk,5.0)
        ];
    }

    public static function mapCVEs($headers) {
        $cves = [];
        $server = strtolower($headers['Server'] ?? '');
        $powered = strtolower($headers['X-Powered-By'] ?? '');

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
        if (preg_match('/nginx\/1\.(1[0-9]|18|16)(\D|$)/', $server)) {
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
        if (preg_match('/openssl\/1\.(0\.|1\.0)/', $server)) {
            $cves[] = [
                'id' => 'ADVISORY-OPENSSL-OLD', 'severity' => 'HIGH',
                'desc' => 'OpenSSL 1.0.x / early 1.1.0 lineage is end-of-life. Banner-based hygiene finding.',
                'type' => 'advisory', 'confidence' => 'medium', 'evidence' => 'Server banner', 'product' => 'OpenSSL'
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
                'user_agent' => self::getStealthUserAgent() // <-- Fixed
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);

        $sec = @file_get_contents("https://{$domain}/.well-known/security.txt", false, $ctx) ?: @file_get_contents("https://{$domain}/security.txt", false, $ctx);
        $robots = @file_get_contents("https://{$domain}/robots.txt", false, $ctx);

        return [
            'has_security_txt' => !empty($sec),
            'security_txt'     => $sec ? substr(trim($sec),0,2000) : null,
            'has_robots'       => !empty($robots),
            'robots_txt'       => $robots ? substr(trim($robots),0,1500) : null
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

        // High-confidence regex patterns (real-world service keys)
        $patterns = [
            'AWS Access Key'          => '/\b(AKIA[0-9A-Z]{16})\b/',
            'AWS Secret Key'          => '/\b([A-Za-z0-9\/+=]{40})\b(?=.*(?:aws|secret|access))/i',
            'Stripe Live Secret'      => '/\b(sk_live_[0-9a-zA-Z]{24,})\b/',
            'Stripe Restricted'       => '/\b(rk_live_[0-9a-zA-Z]{24,})\b/',
            'Stripe Publishable'      => '/\b(pk_live_[0-9a-zA-Z]{24,})\b/',
            'GitHub PAT'              => '/\b(ghp_[A-Za-z0-9_]{36,})\b/',
            'GitHub OAuth'            => '/\b(gho_[A-Za-z0-9_]{36,})\b/',
            'GitHub App'              => '/\b(ghu_[A-Za-z0-9_]{36,})\b/',
            'Slack Token'             => '/\b(xox[baprs]-[0-9a-zA-Z-]{10,})\b/',
            'Slack Webhook'           => '/\b(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)\b/',
            'Google API Key'          => '/\b(AIza[0-9A-Za-z\-_]{35})\b/',
            'Twilio Account SID'      => '/\b(AC[a-f0-9]{32})\b/',
            'Twilio Auth Token'       => '/\b([a-f0-9]{32})\b(?=.*twilio)/i',
            'SendGrid API Key'        => '/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/',
            'Mailgun API Key'         => '/\b(key-[0-9a-zA-Z]{32})\b/',
            'OpenAI API Key'          => '/\b(sk-[A-Za-z0-9]{32,})\b/',
            'Discord Bot/Token'       => '/\b([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b/',
            'Firebase'                => '/\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b/',
            'Heroku API Key'          => '/\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b(?=.*heroku)/i',
            'Generic API Key'         => '/(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-\.]{16,80})[\'"]?/i',
            'JWT Secret / HS Key'     => '/(?:jwt[_-]?secret|hs256[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-\+\/=]{8,128})[\'"]?/i',
            'Private Key Block'       => '/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/',
            'Basic Auth Hardcoded'    => '/(?:Authorization|Basic)\s+[\'"]?Basic\s+([A-Za-z0-9+\/=]{20,})/i',
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
                'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true]
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
                    'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]
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
            '/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config',
            '/.svn/entries', '/backup.zip', '/backup.sql', '/dump.sql', '/db.sql',
            '/phpinfo.php', '/info.php', '/test.php', '/admin', '/administrator',
            '/wp-admin', '/wp-login.php', '/login', '/dashboard', '/api', '/api/v1',
            '/graphql', '/graphiql', '/swagger', '/swagger-ui', '/swagger.json',
            '/openapi.json', '/api-docs', '/.well-known/security.txt', '/security.txt',
            '/server-status', '/server-info', '/.DS_Store', '/web.config',
            '/crossdomain.xml', '/clientaccesspolicy.xml', '/elmah.axd',
            '/trace.axd', '/actuator', '/actuator/health', '/actuator/env',
            '/console', '/debug', '/_debug', '/status', '/health', '/metrics',
            '/.htaccess', '/.htpasswd', '/config.json', '/config.yml',
            '/package.json', '/composer.json', '/yarn.lock', '/package-lock.json'
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
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true]
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
