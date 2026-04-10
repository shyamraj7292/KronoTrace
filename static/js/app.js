/**
 * KronoTrace — Frontend Application
 * Handles file upload, WebSocket pipeline, timeline, table, and alerts.
 */

const state = {
    files: [],
    pipelineId: null,
    ws: null,
    events: [],
    alerts: [],
    summary: {},
    timeline: null,
    currentPage: 1,
    pageSize: 50,
    searchTerm: '',
    severityFilter: 'all',
    categoryFilter: 'all',
    sortColumn: 'timestamp',
    sortDirection: 'asc',
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

document.addEventListener('DOMContentLoaded', () => {
    setupUploadZone();
    setupTableControls();
});

// ─── Upload Zone ─────────────────────────────────────────────────────────────

function setupUploadZone() {
    const zone = $('#upload-zone');
    const input = $('#file-input');
    zone.addEventListener('click', (e) => {
        if (e.target.closest('.file-item-remove') || e.target.closest('.btn-primary')) return;
        input.click();
    });
    input.addEventListener('change', (e) => { addFiles(Array.from(e.target.files)); input.value = ''; });
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => { zone.classList.remove('drag-over'); });
    zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('drag-over'); addFiles(Array.from(e.dataTransfer.files)); });
}

function addFiles(newFiles) {
    const supported = ['.csv', '.evtx', '.pcap', '.pcapng', '.log', '.txt', '.syslog'];
    for (const file of newFiles) {
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        if (!supported.includes(ext)) continue;
        if (!state.files.find(f => f.name === file.name && f.size === file.size)) {
            state.files.push(file);
        }
    }
    renderFileList();
}

function removeFile(index) { state.files.splice(index, 1); renderFileList(); }

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function getFileIcon(name) {
    const ext = name.split('.').pop().toLowerCase();
    return { csv: '\u{1F4CA}', evtx: '\u{1FA9F}', pcap: '\u{1F310}', pcapng: '\u{1F310}', log: '\u{1F4DD}', txt: '\u{1F4DD}', syslog: '\u{1F4DD}' }[ext] || '\u{1F4C4}';
}

function renderFileList() {
    const container = $('#file-list');
    const btnContainer = $('#upload-btn-container');
    if (state.files.length === 0) { container.innerHTML = ''; btnContainer.style.display = 'none'; return; }
    btnContainer.style.display = 'block';
    container.innerHTML = state.files.map((file, i) => `
        <div class="file-item animate-in">
            <div class="file-item-info">
                <span class="file-item-icon">${getFileIcon(file.name)}</span>
                <span class="file-item-name">${file.name}</span>
                <span class="file-item-size">${formatFileSize(file.size)}</span>
            </div>
            <button class="file-item-remove" onclick="event.stopPropagation(); removeFile(${i})" title="Remove">\u2715</button>
        </div>
    `).join('');
}

// ─── Upload & Pipeline ──────────────────────────────────────────────────────

async function startAnalysis() {
    if (state.files.length === 0) return;
    const btn = $('#analyze-btn');
    btn.disabled = true;
    btn.innerHTML = '\u23F3 Uploading...';
    $('.progress-section').classList.add('active');
    $('.upload-zone').classList.add('processing');
    updateStatusDot('processing');

    // Reset state
    state.events = [];
    state.alerts = [];
    state.summary = {};

    const formData = new FormData();
    for (const file of state.files) formData.append('files', file);

    try {
        const response = await fetch('/api/upload', { method: 'POST', body: formData });
        if (!response.ok) { const err = await response.json(); throw new Error(err.detail || 'Upload failed'); }
        const data = await response.json();
        state.pipelineId = data.pipeline_id;
        connectWebSocket(data.pipeline_id);
    } catch (error) {
        console.error('Upload failed:', error);
        alert('Upload failed: ' + error.message);
        btn.disabled = false;
        btn.innerHTML = '\u{1F52C} Analyze Files';
        $('.progress-section').classList.remove('active');
        $('.upload-zone').classList.remove('processing');
        updateStatusDot('offline');
    }
}

function connectWebSocket(pipelineId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${protocol}//${window.location.host}/ws/${pipelineId}`);
    state.ws.onmessage = (event) => handleWSMessage(JSON.parse(event.data));
    state.ws.onerror = (error) => console.error('WebSocket error:', error);
}

function handleWSMessage(msg) {
    switch (msg.type) {
        case 'progress': updateProgress(msg); break;
        case 'events': receiveEventBatch(msg); break;
        case 'alerts': receiveAlerts(msg); break;
        case 'summary': receiveSummary(msg); break;
        case 'complete': onPipelineComplete(); break;
        case 'error': onPipelineError(msg.message); break;
    }
}

const STAGE_ORDER = ['parsing', 'normalization', 'processing', 'detection', 'streaming', 'complete'];

function updateProgress(msg) {
    const { stage, percent, detail } = msg;
    const bar = $('.progress-bar');
    if (bar) bar.style.width = `${percent}%`;
    const detailEl = $('.progress-detail');
    if (detailEl) detailEl.textContent = detail || '';
    const stageIdx = STAGE_ORDER.indexOf(stage);
    $$('.pipeline-stage').forEach((el, i) => {
        el.classList.remove('active', 'complete');
        if (i < stageIdx) el.classList.add('complete');
        else if (i === stageIdx) el.classList.add('active');
    });
}

function receiveEventBatch(msg) { state.events.push(...(msg.batch || [])); }
function receiveAlerts(msg) { state.alerts = msg.data || []; }
function receiveSummary(msg) { state.summary = msg.data || {}; }

function onPipelineComplete() {
    setTimeout(() => {
        $('.progress-section').classList.remove('active');
        $('.dashboard').classList.add('active');
        updateStatusDot('online');
        renderSummaryCards();
        renderAlerts();
        renderDetectionCards();
        renderTimeline();
        renderEventsTable();
        const btn = $('#analyze-btn');
        btn.disabled = false;
        btn.innerHTML = '\u{1F52C} Analyze Files';
        $('.upload-zone').classList.remove('processing');
    }, 500);
}

function onPipelineError(message) {
    alert('Pipeline error: ' + message);
    $('.progress-section').classList.remove('active');
    updateStatusDot('offline');
    const btn = $('#analyze-btn');
    btn.disabled = false;
    btn.innerHTML = '\u{1F52C} Analyze Files';
    $('.upload-zone').classList.remove('processing');
}

// ─── Summary Cards ───────────────────────────────────────────────────────────

function renderSummaryCards() {
    const s = state.summary;
    const riskVal = $('#risk-value');
    if (riskVal) {
        riskVal.textContent = s.risk_score || 0;
        const level = s.risk_score >= 70 ? 'critical' : s.risk_score >= 40 ? 'high' : s.risk_score >= 15 ? 'medium' : 'low';
        $('#risk-subtitle').textContent = level.charAt(0).toUpperCase() + level.slice(1) + ' Risk';
        const fill = $('#risk-meter-fill');
        fill.className = 'risk-meter-fill ' + level;
        fill.style.width = `${s.risk_score}%`;
    }
    const eventsVal = $('#events-value');
    if (eventsVal) eventsVal.textContent = (s.total_events || 0).toLocaleString();
    const eventsSub = $('#events-subtitle');
    if (eventsSub) {
        const cats = s.category_distribution || {};
        eventsSub.textContent = Object.entries(cats).map(([k, v]) => `${v} ${k}`).slice(0, 3).join(', ');
    }
    const alertsVal = $('#alerts-value');
    if (alertsVal) alertsVal.textContent = s.total_alerts || 0;
    const filesVal = $('#files-value');
    if (filesVal) filesVal.textContent = (s.source_files || []).length;
}

// ─── Alerts Panel ────────────────────────────────────────────────────────────

function renderAlerts() {
    const container = $('#alerts-grid');
    const countEl = $('#alerts-count');
    if (!container) return;
    if (countEl) countEl.textContent = state.alerts.length;

    if (state.alerts.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">\u2705</div><div class="empty-text">No threats detected</div></div>';
        return;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...state.alerts].sort((a, b) => (severityOrder[a.severity] || 9) - (severityOrder[b.severity] || 9));

    container.innerHTML = sorted.map((alert, i) => `
        <div class="alert-card ${alert.severity} animate-in" onclick="toggleAlertEvidence(this)" style="animation-delay: ${i * 0.05}s">
            <div class="alert-header">
                <div class="alert-title">${escapeHtml(alert.title)}</div>
                <span class="alert-badge ${alert.severity}">${alert.severity}</span>
            </div>
            <div class="alert-description">${escapeHtml(alert.description)}</div>
            <div class="alert-meta">
                ${alert.source_ip ? `<div class="alert-meta-item"><span class="label">Source:</span> <span class="value">${escapeHtml(alert.source_ip)}</span></div>` : ''}
                ${alert.target ? `<div class="alert-meta-item"><span class="label">Target:</span> <span class="value">${escapeHtml(alert.target)}</span></div>` : ''}
                ${alert.mitre_technique ? `<div class="alert-meta-item"><span class="label">MITRE:</span> <span class="value">${escapeHtml(alert.mitre_technique)}</span></div>` : ''}
                ${alert.confidence ? `<div class="alert-meta-item"><span class="label">Confidence:</span> <span class="value">${(alert.confidence * 100).toFixed(0)}%</span></div>` : ''}
            </div>
            ${alert.evidence && alert.evidence.length > 0 ? `
                <div class="alert-evidence">
                    <div style="font-size:0.72rem;font-weight:600;color:var(--text-tertiary);margin-bottom:6px;">EVIDENCE</div>
                    ${alert.evidence.map(e => `<div class="evidence-item">${escapeHtml(e)}</div>`).join('')}
                </div>
            ` : ''}
        </div>
    `).join('');
}

function toggleAlertEvidence(card) { card.classList.toggle('expanded'); }

// ─── Detection Cards ─────────────────────────────────────────────────────────

function renderDetectionCards() {
    const dc = state.summary.detection_counts || {};
    const detectors = [
        { key: 'brute_force', name: 'Brute Force', icon: '\u{1F513}' },
        { key: 'new_ip', name: 'New IP', icon: '\u{1F310}' },
        { key: 'privilege_escalation', name: 'Priv Escalation', icon: '\u2B06\uFE0F' },
        { key: 'file_access_anomaly', name: 'File Access', icon: '\u{1F4C1}' },
        { key: 'data_exfiltration', name: 'Data Exfil', icon: '\u{1F4E4}' },
    ];
    const container = $('#detection-grid');
    if (!container) return;
    container.innerHTML = detectors.map((d, i) => {
        const count = dc[d.key] || 0;
        return `<div class="detection-card ${count > 0 ? 'active' : 'clear'} animate-in" style="animation-delay: ${i * 0.08}s">
            <div class="det-icon">${d.icon}</div><div class="det-name">${d.name}</div><div class="det-count">${count}</div>
        </div>`;
    }).join('');
}

// ─── Timeline (Vis.js) ──────────────────────────────────────────────────────

function renderTimeline() {
    const container = document.getElementById('timeline-vis');
    if (!container || state.events.length === 0) return;

    const groupMap = {
        authentication: { id: 1, content: '\u{1F510} Authentication', style: 'color: #a855f7;' },
        network: { id: 2, content: '\u{1F310} Network', style: 'color: #00f0ff;' },
        system: { id: 3, content: '\u2699\uFE0F System', style: 'color: #94a3b8;' },
        file_access: { id: 4, content: '\u{1F4C1} File Access', style: 'color: #ffaa00;' },
    };
    const groups = new vis.DataSet(Object.values(groupMap));

    const severityColors = {
        critical: '#ff3366', high: '#ffaa00', medium: '#3b82f6', low: '#00ff88', info: '#64748b',
    };

    // Sample events for performance (max 2000)
    const maxItems = 2000;
    let events = state.events;
    if (events.length > maxItems) {
        const alertEvents = events.filter(e => e.alerts && e.alerts.length > 0);
        const sampled = events.filter((_, i) => i % Math.ceil(events.length / (maxItems - alertEvents.length)) === 0);
        events = [...new Set([...alertEvents, ...sampled])].slice(0, maxItems);
    }

    const items = new vis.DataSet(
        events.map((event, i) => {
            const group = groupMap[event.category] || groupMap.system;
            const color = severityColors[event.severity] || severityColors.info;
            const hasAlert = event.alerts && event.alerts.length > 0;
            const d = new Date(event.timestamp);
            if (isNaN(d.getTime())) return null;
            return {
                id: i, group: group.id, start: d,
                content: event.event_id,
                title: `${event.event_id}: ${event.message}`.substring(0, 200),
                style: `background-color: ${color}; opacity: ${hasAlert ? 1 : 0.7};`,
            };
        }).filter(Boolean)
    );

    if (state.timeline) state.timeline.destroy();
    state.timeline = new vis.Timeline(container, items, groups, {
        width: '100%', height: '320px', margin: { item: 4 },
        orientation: 'top', stack: true, showCurrentTime: false,
        zoomMin: 1000 * 60, zoomMax: 1000 * 60 * 60 * 24 * 365,
        tooltip: { followMouse: true, overflowMethod: 'cap' },
        type: 'point',
    });
}

// ─── Events Table ────────────────────────────────────────────────────────────

function setupTableControls() {
    const searchInput = $('#event-search');
    if (searchInput) searchInput.addEventListener('input', (e) => { state.searchTerm = e.target.value.toLowerCase(); state.currentPage = 1; renderEventsTable(); });
    const severityFilter = $('#severity-filter');
    if (severityFilter) severityFilter.addEventListener('change', (e) => { state.severityFilter = e.target.value; state.currentPage = 1; renderEventsTable(); });
    const categoryFilter = $('#category-filter');
    if (categoryFilter) categoryFilter.addEventListener('change', (e) => { state.categoryFilter = e.target.value; state.currentPage = 1; renderEventsTable(); });
}

function getFilteredEvents() {
    let filtered = state.events;
    if (state.searchTerm) {
        filtered = filtered.filter(e =>
            e.message.toLowerCase().includes(state.searchTerm) ||
            e.event_id.toLowerCase().includes(state.searchTerm) ||
            (e.source_ip || '').toLowerCase().includes(state.searchTerm) ||
            (e.username || '').toLowerCase().includes(state.searchTerm) ||
            (e.source || '').toLowerCase().includes(state.searchTerm)
        );
    }
    if (state.severityFilter !== 'all') filtered = filtered.filter(e => e.severity === state.severityFilter);
    if (state.categoryFilter !== 'all') filtered = filtered.filter(e => e.category === state.categoryFilter);
    filtered.sort((a, b) => {
        let vA = a[state.sortColumn] || '', vB = b[state.sortColumn] || '';
        if (typeof vA === 'string') vA = vA.toLowerCase();
        if (typeof vB === 'string') vB = vB.toLowerCase();
        return vA < vB ? (state.sortDirection === 'asc' ? -1 : 1) : vA > vB ? (state.sortDirection === 'asc' ? 1 : -1) : 0;
    });
    return filtered;
}

function renderEventsTable() {
    const filtered = getFilteredEvents();
    const totalPages = Math.max(1, Math.ceil(filtered.length / state.pageSize));
    const start = (state.currentPage - 1) * state.pageSize;
    const pageEvents = filtered.slice(start, start + state.pageSize);
    const tbody = $('#events-tbody');
    if (!tbody) return;

    if (pageEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-tertiary);">No events match your filters</td></tr>';
    } else {
        tbody.innerHTML = pageEvents.map(event => {
            const hasAlert = event.alerts && event.alerts.length > 0;
            return `<tr class="${hasAlert ? 'has-alert' : ''}">
                <td class="timestamp">${formatTimestamp(event.timestamp)}</td>
                <td class="event-id">${escapeHtml(event.event_id)}</td>
                <td><span class="severity-badge ${event.severity}">${event.severity}</span></td>
                <td><span class="category-tag ${event.category}">${event.category}</span></td>
                <td>${escapeHtml(event.source || '')}</td>
                <td title="${escapeHtml(event.message)}">${escapeHtml(event.message.substring(0, 100))}</td>
                <td>${hasAlert ? `<span class="alert-indicator">${event.alerts.length}</span>` : ''}</td>
            </tr>`;
        }).join('');
    }

    const info = $('.pagination-info');
    if (info) info.textContent = `Showing ${filtered.length > 0 ? start + 1 : 0}\u2013${Math.min(start + state.pageSize, filtered.length)} of ${filtered.length}`;
    renderPagination(totalPages);
}

function renderPagination(totalPages) {
    const container = $('.pagination-controls');
    if (!container) return;
    let html = `<button class="pagination-btn" onclick="goToPage(1)" ${state.currentPage === 1 ? 'disabled' : ''}>\u00AB</button>`;
    html += `<button class="pagination-btn" onclick="goToPage(${state.currentPage - 1})" ${state.currentPage === 1 ? 'disabled' : ''}>\u2039</button>`;
    const maxBtn = 5;
    let sp = Math.max(1, state.currentPage - Math.floor(maxBtn / 2));
    let ep = Math.min(totalPages, sp + maxBtn - 1);
    sp = Math.max(1, ep - maxBtn + 1);
    for (let p = sp; p <= ep; p++) html += `<button class="pagination-btn ${p === state.currentPage ? 'active' : ''}" onclick="goToPage(${p})">${p}</button>`;
    html += `<button class="pagination-btn" onclick="goToPage(${state.currentPage + 1})" ${state.currentPage >= totalPages ? 'disabled' : ''}>\u203A</button>`;
    html += `<button class="pagination-btn" onclick="goToPage(${totalPages})" ${state.currentPage >= totalPages ? 'disabled' : ''}>\u00BB</button>`;
    container.innerHTML = html;
}

function goToPage(page) { const total = Math.max(1, Math.ceil(getFilteredEvents().length / state.pageSize)); state.currentPage = Math.max(1, Math.min(page, total)); renderEventsTable(); }

function sortTable(column) {
    if (state.sortColumn === column) state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
    else { state.sortColumn = column; state.sortDirection = 'asc'; }
    $$('.events-table thead th').forEach(th => th.classList.remove('sorted-asc', 'sorted-desc'));
    const th = $(`.events-table thead th[data-column="${column}"]`);
    if (th) th.classList.add(`sorted-${state.sortDirection}`);
    renderEventsTable();
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function escapeHtml(str) { if (!str) return ''; const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try { const d = new Date(ts); return isNaN(d.getTime()) ? ts : d.toLocaleString('en-US', { year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false }); } catch { return ts; }
}
function updateStatusDot(status) {
    const dot = $('.status-dot');
    const text = $('.status-text');
    if (dot) { dot.className = 'status-dot'; if (status !== 'online') dot.classList.add(status); }
    if (text) text.textContent = { online: 'Ready', processing: 'Processing...', offline: 'Offline' }[status] || status;
}
