// ============================================================
// 主入口 - 初始化所有模块
// ============================================================

// 全局模式变量
var currentMode = 'monitor';

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
            body.innerHTML = `<div class="alert alert-danger">${r.msg}</div>`;
            new bootstrap.Modal(document.getElementById('detailModal')).show();
            return;
        }
        const d = r.data;
        body.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <table class="table table-sm table-borderless">
                        <tr><th>告警ID</th><td><code>${d.alert_id || '-'}</code></td></tr>
                        <tr><th>源IP</th><td><strong>${d.src_ip || '-'}</strong></td></tr>
                        <tr><th>目的IP</th><td>${d.dest_ip || '-'}</td></tr>
                        <tr><th>URI</th><td>${d.uri || '-'}</td></tr>
                        <tr><th>方法</th><td>${d.method || '-'}</td></tr>
                        <tr><th>攻击类型</th><td><span class="badge bg-${getSeverityClass(d.severity)}">${d.attack_type || 'UNKNOWN'}</span></td></tr>
                        <tr><th>严重等级</th><td><span class="badge bg-${getSeverityClass(d.severity)}">${d.severity || 'INFO'}</span></td></tr>
                        <tr><th>优先级分数</th><td class="${getPriorityColor(d.priority_score)}">${d.priority_score !== undefined ? d.priority_score.toFixed(1) : '-'}</td></tr>
                        <tr><th>状态</th><td>${d.is_blocked ? '<span class="badge bg-secondary">已沉底</span>' : '<span class="badge bg-danger">待处理</span>'}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <div class="mb-2"><strong>攻击载荷</strong></div>
                    <div class="raw-log">${d.payload || '(无)'}</div>
                </div>
            </div>
            <hr>
            <div class="mb-2"><strong>原始日志</strong></div>
            <div class="raw-log" style="max-height:300px;">${d.raw_message || '(无)'}</div>
        `;
        new bootstrap.Modal(document.getElementById('detailModal')).show();
    } catch (e) {
        body.innerHTML = `<div class="alert alert-danger">网络错误: ${e.message}</div>`;
        new bootstrap.Modal(document.getElementById('detailModal')).show();
    }
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

    console.log('告警研判引擎已初始化');
})();

// 暴露到全局
window.showDetail = showDetail;
window.setMode = setMode;
window.changePage = changePage;
window.changePageSize = changePageSize;
window.currentPage = currentPage;
window.currentSize = currentSize;
window.currentMode = currentMode;
