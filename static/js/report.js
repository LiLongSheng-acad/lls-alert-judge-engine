// ============================================================
// 日报统计模块
// 总告警 / 动作沉底 / 规则沉底 / 剩余未研判 / 沉底占比
// + 规则维度明细（每条规则在区间内的隐去量）
// + 未分类攻击类型（损失表未配置 → 交由管理员评判后补录）
// 支持自选时间范围。
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
    const breakdown = document.getElementById('reportRuleBreakdown');
    const unclassifiedBox = document.getElementById('reportUnclassified');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td class="text-muted">加载中...</td></tr>';
    if (breakdown) breakdown.innerHTML = '';
    if (unclassifiedBox) unclassifiedBox.innerHTML = '';
    try {
        const r = await apiCall('/alerts', payload);
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td class="text-danger">加载失败: ${escapeHtml(r.msg)}</td></tr>`;
            return;
        }
        const d = r.data;
        const ratioPct = ((d.sunk_ratio ?? 0) * 100).toFixed(1);
        tbody.innerHTML = `
            <tr><th style="width:130px;">统计区间</th><td>${escapeHtml(d.time_from)} ~ ${escapeHtml(d.time_to)}</td></tr>
            <tr><th>总告警数</th><td><strong>${d.total}</strong></td></tr>
            <tr><th>动作沉底</th><td>${d.action_sunk ?? 0}</td></tr>
            <tr><th>规则沉底</th><td>${d.rule_sunk ?? 0}</td></tr>
            <tr><th>已沉底合计</th><td>${d.sunk_total ?? d.blocked ?? 0}</td></tr>
            <tr><th>剩余未研判</th><td>${d.remaining}</td></tr>
            <tr><th>沉底占比</th><td>${ratioPct}%</td></tr>
        `;
        if (breakdown) {
            const rows = (d.by_rule || []).map(x => `
                <tr>
                    <td><code>${escapeHtml(x.rule_id || '-')}</code></td>
                    <td>${escapeHtml(x.field || '-')} ${escapeHtml(x.operator || '')} <code>${escapeHtml(x.value || '')}</code></td>
                    <td><span class="badge ${x.scope === 'global' ? 'bg-primary' : 'bg-secondary'}">${escapeHtml(x.scope || 'personal')}</span></td>
                    <td>${escapeHtml(x.creator || '-')}</td>
                    <td class="text-end"><strong>${x.hidden_count ?? 0}</strong></td>
                </tr>`).join('');
            breakdown.innerHTML = `
                <div class="mb-2"><strong>规则维度明细</strong><span class="text-muted small ms-2">（按当前规则重算）</span></div>
                <table class="table table-sm">
                    <thead><tr><th>规则ID</th><th>条件</th><th>作用域</th><th>创建人</th><th class="text-end">隐去量</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="5" class="text-muted">区间内无规则隐去记录</td></tr>'}</tbody>
                </table>`;
        }
        if (unclassifiedBox) {
            const u = d.unclassified || [];
            const urows = u.map(x => `
                <tr>
                    <td><code>${escapeHtml(x.attack_type)}</code></td>
                    <td class="text-end"><strong>${x.count ?? 0}</strong></td>
                </tr>`).join('');
            unclassifiedBox.innerHTML = `
                <div class="mb-2"><strong>未分类攻击类型</strong><span class="text-muted small ms-2">（损失表未配置，暂按全局兜底值计 → 请管理员评判后补录配置）</span></div>
                <table class="table table-sm">
                    <thead><tr><th>攻击类型</th><th class="text-end">条数</th></tr></thead>
                    <tbody>${urows || '<tr><td colspan="2" class="text-muted">无</td></tr>'}</tbody>
                </table>`;
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td class="text-danger">网络错误: ${escapeHtml(e.message)}</td></tr>`;
    }
}

// 暴露到全局
window.openDailyReport = openDailyReport;
window.loadDailyReport = loadDailyReport;
