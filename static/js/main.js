// ============================================================
// 主入口 - 初始化所有模块
// ============================================================

// 全局模式变量
var currentMode = 'monitor';
// 视图：main=主视图（默认）/ internal=内网源视图（源 IP 命中豁免规则）
var currentView = 'main';

// ----- 告警详情 -----
async function showDetail(alertId) {
    if (!alertId || alertId === 'undefined') {
        alert('告警ID无效，请刷新页面重试');
        return;
    }
    const body = document.getElementById('detailBody');
    if (!body) return;
    body.innerHTML = '加载中...';
    try {
        const r = await apiCall('/alerts', { action: 'detail', alert_id: alertId });
        if (r.code !== 0) {
            body.innerHTML = `<div class="alert alert-danger">${escapeHtml(r.msg)}</div>`;
            new bootstrap.Modal(document.getElementById('detailModal')).show();
            return;
        }
        const d = r.data;
        window.currentDetailSrcIp = d.src_ip || '';
        body.innerHTML = `
            <div class="mb-2">
                <button class="btn btn-outline-primary btn-sm" onclick="queryByIp()">🔎 关联该攻击 IP 的报文</button>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <table class="table table-sm table-borderless">
                        <tr><th>告警ID</th><td><code>${escapeHtml(d.alert_id || '-')}</code></td></tr>
                        <tr><th>源IP</th><td><strong>${escapeHtml(d.src_ip || '-')}</strong></td></tr>
                        <tr><th>目的IP</th><td>${escapeHtml(d.dest_ip || '-')}</td></tr>
                        <tr><th>URI</th><td>${escapeHtml(d.uri || '-')}</td></tr>
                        <tr><th>方法</th><td>${escapeHtml(d.method || '-')}</td></tr>
                        <tr><th>攻击类型</th><td><span class="badge bg-${getSeverityClass(d.severity)}">${escapeHtml(d.attack_type || 'UNKNOWN')}</span></td></tr>
                        <tr><th>严重等级</th><td><span class="badge bg-${getSeverityClass(d.severity)}">${escapeHtml(d.severity || 'INFO')}</span></td></tr>
                        <tr><th>优先级分数</th><td class="${getPriorityColor(d.priority_score, d.below_red_line)}">${d.priority_score !== undefined ? d.priority_score.toFixed(1) : '-'}</td></tr>
                        <tr><th>状态</th><td>${d.is_blocked ? '<span class="badge bg-secondary">已沉底</span>' : '<span class="badge bg-danger">待处理</span>'}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <div class="mb-2"><strong>攻击载荷</strong></div>
                    <div class="raw-log">${escapeHtml(d.payload || '(无)')}</div>
                </div>
            </div>
            ${(d.hidden_by && d.hidden_by.length) ? `
            <hr>
            <div class="mb-2"><strong>命中规则（本条被以下规则隐去）</strong></div>
            <table class="table table-sm">
                <thead><tr><th>规则ID</th><th>条件</th><th>作用域</th><th>创建人</th><th>原因</th></tr></thead>
                <tbody>
                    ${d.hidden_by.map(x => `<tr>
                        <td><code>${escapeHtml(x.rule_id || '-')}</code></td>
                        <td>${escapeHtml(x.field || '-')} ${escapeHtml(x.operator || '')} <code>${escapeHtml(x.value || '')}</code></td>
                        <td>${escapeHtml(x.scope || 'personal')}</td>
                        <td>${escapeHtml(x.creator || '-')}</td>
                        <td>${escapeHtml(x.reason || '-')}</td>
                    </tr>`).join('')}
                </tbody>
            </table>` : ''}
            <hr>
            <div class="mb-2"><strong>原始日志</strong></div>
            <div class="raw-log" style="max-height:300px;">${escapeHtml(d.raw_message || '(无)')}</div>
        `;
        new bootstrap.Modal(document.getElementById('detailModal')).show();
    } catch (e) {
        body.innerHTML = `<div class="alert alert-danger">网络错误: ${escapeHtml(e.message)}</div>`;
        new bootstrap.Modal(document.getElementById('detailModal')).show();
    }
}

// ----- 关联该攻击 IP 的报文（含已沉底，便于看证据） -----
function queryByIp() {
    const srcIp = window.currentDetailSrcIp || '';
    if (!srcIp) { alert('该告警没有源IP'); return; }
    const modalEl = document.getElementById('detailModal');
    const modal = bootstrap.Modal.getInstance(modalEl);
    if (modal) modal.hide();
    // 仅保留源IP，清掉其它过滤，避免过度收窄
    ['filterDstIP', 'filterAttackType'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    const sev = document.getElementById('filterSeverity');
    if (sev) sev.value = '';
    const srcEl = document.getElementById('filterSrcIP');
    if (srcEl) srcEl.value = srcIp;
    // 切到告警列表 Tab
    const tabEl = document.getElementById('alerts-tab');
    if (tabEl) new bootstrap.Tab(tabEl).show();
    // 调查模式 => ignore_filters=true，结果包含已沉底
    setMode('investigate');
}

// ----- 模式切换 -----
function setMode(mode) {
    currentMode = mode;
    const monitorBtn = document.getElementById('modeMonitor');
    const investBtn = document.getElementById('modeInvestigate');
    if (monitorBtn && investBtn) {
        monitorBtn.className = `btn btn-outline-${mode === 'monitor' ? 'primary active' : 'secondary'}`;
        investBtn.className = `btn btn-outline-${mode === 'investigate' ? 'primary active' : 'secondary'}`;
    }
    const badge = document.getElementById('modeBadge');
    if (badge) {
        badge.textContent = mode === 'monitor' ? '监控模式' : '调查模式';
        badge.className = `badge ${mode === 'monitor' ? 'bg-primary' : 'bg-warning text-dark'}`;
    }
    currentPage = 1;
    loadAlerts();
}

// ----- 视图切换：主视图 / 内网源 / 排查中 -----
const VIEW_IDS = { main: 'viewMain', internal: 'viewInternal', processing: 'viewProcessing' };

function setView(view) {
    currentView = view;
    Object.keys(VIEW_IDS).forEach(v => {
        const el = document.getElementById(VIEW_IDS[v]);
        if (el) el.className = `btn btn-outline-${v === view ? 'primary active' : 'secondary'}`;
    });
    currentPage = 1;
    loadAlerts();
}

// ----- 分页（全局变量） -----
var currentPage = 1;
var currentSize = 25;

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage < 1) return;
    currentPage = newPage;
    loadAlerts();
}

function changePageSize() {
    const sel = document.getElementById('pageSizeSelect');
    if (sel) currentSize = parseInt(sel.value);
    currentPage = 1;
    loadAlerts();
}

// ============================================================
// 初始化（直接执行）
// ============================================================

(function init() {
    // 用户身份
    const user = getCurrentUser();
    const display = document.getElementById('currentUserDisplay');
    if (display) display.textContent = user;

    // 设置默认时间范围（近7天）
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    sevenDaysAgo.setHours(0, 0, 0, 0);
    now.setSeconds(0, 0);
    const fromEl = document.getElementById('filterTimeFrom');
    const toEl = document.getElementById('filterTimeTo');
    if (fromEl) fromEl.value = formatLocal(sevenDaysAgo);
    if (toEl) toEl.value = formatLocal(now);

    // 设置模式初始状态
    setMode('monitor');

    // 加载所有模块
    loadAlerts();
    loadStats();
    loadRules();
    loadAssets();
    loadHistory();
    refreshPromotionTab();
    setRefreshInterval();

    // Tab切换事件
    document.querySelectorAll('.filter-section input, .filter-section select').forEach(el => {
        el.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') applyFilters();
        });
    });

    document.addEventListener('change', function(e) {
        if (e.target.classList.contains('alert-checkbox') || e.target.id === 'selectAll') {
            updateBatchBar();
        }
    });

    document.getElementById('rules-tab')?.addEventListener('shown.bs.tab', loadRules);
    document.getElementById('assets-tab')?.addEventListener('shown.bs.tab', loadAssets);
    document.getElementById('history-tab')?.addEventListener('shown.bs.tab', loadHistory);
    document.getElementById('promotions-tab')?.addEventListener('shown.bs.tab', loadPromotions);

    console.log('告警研判引擎已初始化');
})();

// 暴露到全局
window.showDetail = showDetail;
window.queryByIp = queryByIp;
window.setMode = setMode;
window.setView = setView;
window.changePage = changePage;
window.changePageSize = changePageSize;
window.currentPage = currentPage;
window.currentSize = currentSize;
window.currentMode = currentMode;
