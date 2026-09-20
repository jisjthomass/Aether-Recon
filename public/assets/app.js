// Aether Recon v14.6 — Frontend Application
// Security hardened: CSRF via POST, SRI for CDN scripts, pwd via POST body
function loadScript(src, integrity) {
    return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) {
            return resolve();
        }
        const script = document.createElement('script');
        script.src = src;
        if (integrity) {
            script.integrity = integrity;
            script.crossOrigin = 'anonymous';
        }
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
                        const pwdParam = ''; // Password now sent via POST body, not GET URL
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
                            const fetchOpts = { signal: scanAbortController.signal };
                            let fetchUrl = `?action=${mod.endpoint}&target=${encodeURIComponent(target)}${personaParam}`;
                            if ((mod.key === 'apikeys' || mod.key === 'jwt') && revealPwd) {
                                fetchOpts.method = 'POST';
                                fetchOpts.headers = {'Content-Type': 'application/x-www-form-urlencoded'};
                                fetchOpts.body = 'pwd=' + encodeURIComponent(revealPwd);
                            }
                            const res = await fetch(fetchUrl, fetchOpts);
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

    let rows = `
    <tr><th>Protocol</th><td><strong>${esc(http.protocol)}</strong></td></tr>
    <tr><th>Server</th><td>${esc(http.server)}</td></tr>
    <tr><th>Technologies</th><td>${(http.technologies||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join(' ') || '—'}</td></tr>
    `;

    for (const [k,v] of Object.entries(sec)) {
        if (['Server','X-Powered-By'].includes(k)) {
            continue;
        }
        rows += `<tr><th>${esc(k)}</th><td>${v ? esc(v) : '<span class="ioc">MISSING</span>'}</td></tr>`;
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
        document.getElementById('robotsTxt').innerHTML = `<div style="color:var(--ok);margin-bottom:6px">✓ Present</div><pre>${esc(metaF.robots_txt)}</pre>`;
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
        // Fix: Use POST form instead of GET to avoid CSRF token in URL/logs
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '?action=generate_canary_docx';
        form.style.display = 'none';
        const addField = (name, value) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = value;
            form.appendChild(input);
        };
        addField('label', label);
        addField('csrf', csrfToken);
        document.body.appendChild(form);
        form.submit();
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
