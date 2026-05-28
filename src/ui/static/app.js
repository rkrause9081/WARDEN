/*
 * app.js
 *
 * Purpose:
 *     Provides client-side dashboard behavior for WARDEN.
 *
 * Responsibilities:
 *     - Poll live dashboard telemetry
 *     - Render packet, alert, ban, blockchain, and timeline data
 *     - Upload alerts.jsonl files for verification
 *     - Display verification summaries and per-line results
 *
 * Non-Responsibilities:
 *     - Running IDS detection
 *     - Applying mitigation
 *     - Anchoring blockchain evidence
 *     - Recomputing verification hashes directly in the browser
 *
 * Architecture:
 *
 *      Axum /stats API
 *              ↓
 *         fetchDashboard()
 *              ↓
 *          renderState()
 *              ↓
 *        Browser Dashboard
 */

/* -------------------------------------------------------------------------- */
/*                                  Constants                                 */
/* -------------------------------------------------------------------------- */

const REFRESH_INTERVAL_MS = 1000;

/* -------------------------------------------------------------------------- */
/*                              DOM Shortcuts                                 */
/* -------------------------------------------------------------------------- */

const $ = (id) => document.getElementById(id);

/* -------------------------------------------------------------------------- */
/*                             Render Helpers                                 */
/* -------------------------------------------------------------------------- */

function text(value, fallback = "—") {
    if (value === null || value === undefined || value === "") {
        return fallback;
    }

    return String(value);
}

function number(value) {
    return Number(value || 0).toLocaleString();
}

function fixed(value, digits = 2) {
    return Number(value || 0).toFixed(digits);
}

function shortHash(value) {
    if (!value || value === "N/A") {
        return "N/A";
    }

    if (value.length <= 22) {
        return value;
    }

    return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function escapeHtml(value) {
    return text(value, "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function emptyMessage(message) {
    return `<div class="muted">${escapeHtml(message)}</div>`;
}

/* -------------------------------------------------------------------------- */
/*                             Dashboard Fetching                             */
/* -------------------------------------------------------------------------- */

async function fetchDashboard() {
    const response = await fetch("/stats", {
        cache: "no-store",
    });

    if (!response.ok) {
        throw new Error(`stats request failed: ${response.status}`);
    }

    return response.json();
}

async function refreshDashboard() {
    try {
        const state = await fetchDashboard();

        renderState(state);
        renderConnectionStatus(true, state);
    } catch (error) {
        console.error(error);
        renderConnectionStatus(false);
    }
}

/* -------------------------------------------------------------------------- */
/*                              State Rendering                               */
/* -------------------------------------------------------------------------- */

function renderState(state) {
    $("packets").textContent = number(state.packets_seen);
    $("alerts").textContent = number(state.alerts_seen);
    $("bans").textContent = number(state.bans_seen);
    $("peak-pps").textContent = fixed(state.peak_pps);

    $("mqtt-count").textContent = number(state.protocol_counts?.mqtt || state.mqtt_packets);
    $("coap-count").textContent = number(state.protocol_counts?.coap || state.coap_packets);

    renderTopTalkers(state.top_talkers || {});
    renderAttackFeed(state.recent_alerts || []);
    renderTimeline(state.timeline || []);
    renderActiveBans(state.active_bans || {});
    renderBlockchainEvents(state.blockchain_events || []);
}

function renderConnectionStatus(online, state = null) {
    const pill = $("chain-status");

    if (!pill) {
        return;
    }

    if (!online) {
        pill.textContent = "OFFLINE";
        pill.className = "status-pill WARN";
        return;
    }

    if (state?.dry_run === true) {
        pill.textContent = "DRY RUN";
        pill.className = "status-pill WARN";
        return;
    }

    if (state?.dry_run === false) {
        pill.textContent = "LIVE";
        pill.className = "status-pill CRITICAL";
        return;
    }

    pill.textContent = "LIVE";
    pill.className = "status-pill INFO";
}

function renderTopTalkers(topTalkers) {
    const rows = Object.entries(topTalkers)
        .sort(([, left], [, right]) => Number(right) - Number(left))
        .slice(0, 8)
        .map(([ip, pps]) => {
            return `
                <div class="table-row">
                    <span>${escapeHtml(ip)}</span>
                    <strong>${fixed(pps)} PPS</strong>
                </div>
            `;
        });

    $("top-talkers").innerHTML = rows.length
        ? rows.join("")
        : emptyMessage("No traffic yet");
}

function renderAttackFeed(alerts) {
    const rows = alerts
        .slice()
        .reverse()
        .map((alert) => {
            return `
                <div class="event-row">
                    <span>${escapeHtml(alert.timestamp)}</span>
                    <span class="badge ${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span>
                    <span>
                        ${escapeHtml(alert.protocol)}
                        ${escapeHtml(alert.msg_type)}
                        from ${escapeHtml(alert.src_ip)}
                        at ${fixed(alert.pps)} PPS
                    </span>
                    <span class="hash" title="${escapeHtml(alert.evidence_hash)}">
                        ${escapeHtml(shortHash(alert.evidence_hash))}
                    </span>
                </div>
            `;
        });

    $("attack-feed").innerHTML = rows.length
        ? rows.join("")
        : emptyMessage("No alerts yet");
}

function renderTimeline(timeline) {
    const rows = timeline
        .slice()
        .reverse()
        .map((event) => {
            return `
                <div class="event-row">
                    <span>${escapeHtml(event.timestamp)}</span>
                    <span class="badge ${escapeHtml(event.severity)}">${escapeHtml(event.stage)}</span>
                    <span>${escapeHtml(event.message)}</span>
                    <span class="badge ${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span>
                </div>
            `;
        });

    $("timeline").innerHTML = rows.length
        ? rows.join("")
        : emptyMessage("Awaiting events");
}

function renderActiveBans(activeBans) {
    const rows = Object.values(activeBans)
        .sort((left, right) => left.src_ip.localeCompare(right.src_ip))
        .map((ban) => {
            return `
                <div class="table-row">
                    <span>
                        ${escapeHtml(ban.src_ip)}
                        · ${escapeHtml(ban.protocol)}
                        · ${fixed(ban.pps)} PPS
                    </span>
                    <span class="badge ${ban.dry_run ? "WARN" : "CRITICAL"}">
                        ${escapeHtml(ban.action)}
                    </span>
                </div>
            `;
        });

    $("active-bans").innerHTML = rows.length
        ? rows.join("")
        : emptyMessage("No bans active");
}

function renderBlockchainEvents(events) {
    const rows = events
        .slice()
        .reverse()
        .map((event) => {
            const statusClass = event.anchored ? "Valid" : "WARN";

            return `
                <div class="chain-row">
                    <span>${escapeHtml(event.timestamp)}</span>
                    <span class="tx" title="${escapeHtml(event.tx_hash)}">
                        ${escapeHtml(shortHash(event.tx_hash))}
                    </span>
                    <span class="hash" title="${escapeHtml(event.evidence_hash)}">
                        ${escapeHtml(shortHash(event.evidence_hash))}
                    </span>
                    <span class="badge ${statusClass}">
                        ${escapeHtml(event.status)}
                    </span>
                </div>
            `;
        });

    $("blockchain-events").innerHTML = rows.length
        ? rows.join("")
        : emptyMessage("No chain events yet");
}

/* -------------------------------------------------------------------------- */
/*                            Verification Upload                             */
/* -------------------------------------------------------------------------- */

async function verifySelectedFile() {
    const fileInput = $("verify-file");
    const status = $("verify-status");
    const results = $("verify-results");
    const button = $("verify-button");

    const file = fileInput?.files?.[0];

    if (!file) {
        status.textContent = "Select an alerts.jsonl file first.";
        return;
    }

    button.disabled = true;
    status.textContent = `Verifying ${file.name}...`;
    results.innerHTML = "";

    try {
        const body = await file.text();

        const response = await fetch("/api/verify", {
            method: "POST",
            headers: {
                "Content-Type": "text/plain; charset=utf-8",
            },
            body,
        });

        if (!response.ok) {
            throw new Error(`verification request failed: ${response.status}`);
        }

        const verification = await response.json();

        renderVerification(verification);

        status.textContent = `Verification complete: ${verification.summary.overall_status}`;
    } catch (error) {
        console.error(error);

        status.textContent = "Verification failed. Check console output.";
        results.innerHTML = emptyMessage(error.message);
    } finally {
        button.disabled = false;
    }
}

function renderVerification(verification) {
    const summary = verification.summary;
    const results = verification.results || [];

    const summaryRow = `
        <div class="verify-row">
            <span class="badge ${escapeHtml(summary.overall_status)}">
                ${escapeHtml(summary.overall_status)}
            </span>
            <span>${number(summary.total)} lines</span>
            <span>
                ${number(summary.valid)} valid ·
                ${number(summary.tampered)} tampered ·
                ${number(summary.missing_hash)} missing hash ·
                ${number(summary.parse_errors)} parse errors
            </span>
        </div>
    `;

    const resultRows = results.map((result) => {
        return `
            <div class="verify-row">
                <span>#${number(result.line_number)}</span>
                <span class="badge ${escapeHtml(result.status)}">
                    ${escapeHtml(result.status)}
                </span>
                <span>
                    ${escapeHtml(result.protocol)}
                    ${escapeHtml(result.msg_type)}
                    ${escapeHtml(result.src_ip)}
                    <span class="hash" title="${escapeHtml(result.stored_hash)}">
                        stored=${escapeHtml(shortHash(result.stored_hash))}
                    </span>
                    <span class="hash" title="${escapeHtml(result.recomputed_hash)}">
                        recomputed=${escapeHtml(shortHash(result.recomputed_hash))}
                    </span>
                    ${result.error ? `· ${escapeHtml(result.error)}` : ""}
                </span>
            </div>
        `;
    });

    $("verify-results").innerHTML = summaryRow + resultRows.join("");
}

/* -------------------------------------------------------------------------- */
/*                                   Startup                                  */
/* -------------------------------------------------------------------------- */

function startDashboard() {
    const verifyButton = $("verify-button");

    if (verifyButton) {
        verifyButton.addEventListener("click", verifySelectedFile);
    }

    refreshDashboard();

    setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
}

document.addEventListener("DOMContentLoaded", startDashboard);