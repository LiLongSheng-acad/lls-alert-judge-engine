// ============================================================
// 日报统计模块（只报真实存在的状态）
// 总告警 / 已沉底 / 剩余未研判，支持自选时间范围。
// ============================================================

function openDailyReport() {
    const now = new Date();
    const from = new Date(now);
    from.setHours(0, 0, 0, 0);
    const fromEl = document.getElementById('reportFrom');
    const toEl = document.getElementById('reportTo');
    if (fromEl) fromEl.value = formatLocal(from);
    if (toEl) toEl.value = formatLocal(now);
    new bootstrap.Modal(document.getElementById('reportModal')).show();
    loadDailyReport();
}

async function loadDailyReport() {
    const fromInput = document.getElementById('reportFrom')?.value || '';
    const toInput = document.getElementById('reportTo')?.value || '';
    const payload = { action: 'report' };
    if (fromInput) payload.time_from = fromInput.replace('T', ' ') + ':00';
    if (toInput) payload.time_to = toInput.replace('T', ' ') + ':59';

    const tbody = document.getElementById('reportTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td class="text-muted">加载中...</td></tr>';
    try {
        const r = await apiCall('/alerts', payload);
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td class="text-danger">加载失败: ${escapeHtml(r.msg)}</td></tr>`;
            return;
        }
        const d = r.data;
        tbody.innerHTML = `
            <tr><th style="width:130px;">统计区间</th><td>${escapeHtml(d.time_from)} ~ ${escapeHtml(d.time_to)}</td></tr>
            <tr><th>总告警数</th><td><strong>${d.total}</strong></td></tr>
            <tr><th>已沉底</th><td>${d.blocked}</td></tr>
            <tr><th>剩余未研判</th><td>${d.remaining}</td></tr>
        `;
    } catch (e) {
        tbody.innerHTML = `<tr><td class="text-danger">网络错误: ${escapeHtml(e.message)}</td></tr>`;
    }
}

// 暴露到全局
window.openDailyReport = openDailyReport;
window.loadDailyReport = loadDailyReport;
