// ============================================================
// 过滤条件 + 定时刷新 + 快捷时间
// ============================================================

let refreshTimer = null;

function applyFilters() {
    currentPage = 1;
    loadAlerts();
}

function clearFilters() {
    ['filterSrcIP', 'filterDstIP', 'filterAttackType'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    const sev = document.getElementById('filterSeverity');
    if (sev) sev.value = '';
    ['filterTimeFrom', 'filterTimeTo'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    currentPage = 1;
    loadAlerts();
}

function setRefreshInterval() {
    const select = document.getElementById('refreshInterval');
    if (!select) return;
    const minutes = parseInt(select.value);
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
    if (minutes === 0) return;
    refreshTimer = setInterval(() => {
        if (document.getElementById('alerts-tab')?.classList.contains('active')) {
            loadAlerts();
            loadStats();
        }
    }, minutes * 60 * 1000);
}

function setQuickTime(minutes) {
    const now = new Date();
    const from = new Date(now.getTime() - minutes * 60 * 1000);
    const fromEl = document.getElementById('filterTimeFrom');
    const toEl = document.getElementById('filterTimeTo');
    if (fromEl) fromEl.value = formatLocal(from);
    if (toEl) toEl.value = formatLocal(now);
    applyFilters();
}