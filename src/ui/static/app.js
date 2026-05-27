function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function shortHash(value) {
    if (!value || value === 'N/A') return value || 'N/A';
    return value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function formatTime(value) {
    if (!value) return '--:--:--';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
}

function safeNumber(value) {
    const n = Number(value || 0);
    return Number.isFinite(n) ? n.toFixed(n % 1 === 0 ? 0 : 2) : '0';
}

function renderAttackFeed(alerts) {
    const el = document.getElementById('attack-feed');
    const rows = (alerts || []).slice().reverse().slice(0, 12);
    if (!rows.length) {
        el.innerHTML = '<div class="muted">No alerts yet</div>';
        return;
    }

    el.innerHTML = rows.map(alert => `
        <div class="event-row">
            <span>${formatTime(alert.timestamp)}</span>
            <span class="badge ${alert.severity}">${alert.severity}</span>
            <span>${alert.protocol} ${alert.msg_type} flood from <strong>${alert.src_ip}</strong> @ ${safeNumber(alert.pps)} PPS</span>
            <span class="hash" title="${alert.evidence_hash || ''}">${shortHash(alert.evidence_hash)}</span>
        </div>
    `).join('');
}

function renderTimeline(events) {
    const el = document.getElementById('timeline');
    const rows = (events || []).slice().reverse().slice(0, 16);
    if (!rows.length) {
        el.innerHTML = '<div class="muted">Awaiting events</div>';
        return;
    }

    el.innerHTML = rows.map(event => `
        <div class="event-row">
            <span>${formatTime(event.timestamp)}</span>
            <span class="badge ${event.severity}">${event.stage}</span>
            <span>${event.message}</span>
            <span class="badge ${event.severity}">${event.severity}</span>
        </div>
    `).join('');
}

function renderTopTalkers(talkers) {
    const el = document.getElementById('top-talkers');
    const rows = Object.entries(talkers || {}).sort((a, b) => Number(b[1]) - Number(a[1])).slice(0, 10);
    if (!rows.length) {
        el.innerHTML = '<div class="muted">No traffic yet</div>';
        return;
    }

    el.innerHTML = rows.map(([ip, pps]) => `
        <div class="table-row"><span>${ip}</span><span class="badge INFO">${safeNumber(pps)} PPS</span></div>
    `).join('');
}

function renderBans(bans) {
    const el = document.getElementById('active-bans');
    const rows = Object.values(bans || {}).slice(0, 10);
    if (!rows.length) {
        el.innerHTML = '<div class="muted">No bans active</div>';
        return;
    }

    el.innerHTML = rows.map(ban => `
        <div class="table-row">
            <span><strong>${ban.src_ip}</strong> <span class="muted">${ban.protocol}</span></span>
            <span class="badge CRITICAL">${ban.action || 'BAN'} · ${safeNumber(ban.remaining_seconds)}s</span>
        </div>
    `).join('');
}

function renderBlockchain(events) {
    const el = document.getElementById('blockchain-events');
    const rows = (events || []).slice().reverse().slice(0, 10);
    if (!rows.length) {
        el.innerHTML = '<div class="muted">No chain events yet</div>';
        return;
    }

    el.innerHTML = rows.map(event => `
        <div class="chain-row">
            <span>${formatTime(event.timestamp)}</span>
            <span class="tx" title="${event.tx_hash || ''}">TX ${shortHash(event.tx_hash)}</span>
            <span class="hash" title="${event.evidence_hash || ''}">HASH ${shortHash(event.evidence_hash)}</span>
            <span class="badge ${event.anchored ? 'Valid' : 'WARN'}">${event.status}</span>
        </div>
    `).join('');
}

async function refresh() {
    try {
        const res = await fetch('/stats', { cache: 'no-store' });
        const data = await res.json();

        setText('packets', data.packets_seen || 0);
        setText('alerts', data.alerts_seen || 0);
        setText('bans', data.bans_seen || 0);
        setText('peak-pps', safeNumber(data.peak_pps || 0));
        setText('mqtt-count', data.protocol_counts?.mqtt || 0);
        setText('coap-count', data.protocol_counts?.coap || 0);
        setText('chain-status', data.blockchain_events_seen > 0 ? 'CHAIN ACTIVE' : 'LIVE');

        renderAttackFeed(data.recent_alerts);
        renderTimeline(data.timeline);
        renderTopTalkers(data.top_talkers);
        renderBans(data.active_bans);
        renderBlockchain(data.blockchain_events);
    } catch (error) {
        setText('chain-status', 'RECONNECTING');
        console.error('Dashboard refresh failed:', error);
    }
}

async function verifyFile() {
    const input = document.getElementById('verify-file');
    const status = document.getElementById('verify-status');
    const results = document.getElementById('verify-results');

    if (!input.files.length) {
        status.textContent = 'Choose an alerts.jsonl file first.';
        return;
    }

    const text = await input.files[0].text();
    status.textContent = 'Verifying...';

    try {
        const res = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: text
        });

        if (!res.ok) {
            status.textContent = 'Verification failed before parsing.';
            return;
        }

        const data = await res.json();
        const summary = data.summary;
        status.textContent = `${summary.overall_status}: ${summary.valid} valid, ${summary.tampered} tampered, ${summary.missing_hash} missing hash, ${summary.parse_errors} parse errors`;

        results.innerHTML = (data.results || []).slice(0, 40).map(row => `
            <div class="verify-row">
                <span>#${row.line_number}</span>
                <span class="badge ${row.status}">${row.status}</span>
                <span>${row.src_ip || 'N/A'} ${row.protocol || ''} ${row.msg_type || ''}</span>
            </div>
        `).join('');

        refresh();
    } catch (error) {
        status.textContent = 'Verification request failed.';
        console.error(error);
    }
}

document.getElementById('verify-button').addEventListener('click', verifyFile);
setInterval(refresh, 1000);
refresh();
