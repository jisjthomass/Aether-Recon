<?php
/**
 * Aether Recon v14.6 — Username OSINT Engine
 * Security hardened: SSL verification enforced for outgoing requests (Fix #2).
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/AetherRecon.php'; // Needed for AetherRecon::applyCurlStealthOptions

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
            // Fix #2: Removed CURLOPT_SSL_VERIFYPEER => false to enable default SSL validation
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => false,
                CURLOPT_NOBODY         => false,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_ENCODING       => '',
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
                    ],
                    // Fix #2: Enable SSL verification by removing verify_peer => false
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
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
