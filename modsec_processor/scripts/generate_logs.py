// ============================================================
// 告警列表模块
// ============================================================

let currentPage = 1;
let currentSize = 25;
let currentMode = 'monitor';
let refreshTimer = null;
let selectedAlertIds = [];

// ----- 加载统计数据 -----
async function loadStats() {
    try {
        const r = await apiCall('/alerts', { action: 'stats' });
        if (r.code === 0) {
            document.getElementById('statTotal').textContent = r.data.total ?? '-';
            document.getElementById('statPending').textContent = r.data.pending ?? '-';
            document.getElementById('statBlocked').textContent = r.data.blocked ?? '-';
            document.getElementById('statToday').textContent = r.data.today ?? '-';
        }
    } catch (e) { console.error('统计加载失败', e); }
}

// ----- 加载告警列表 -----
async function loadAlerts() {
    const pane = document.getElementById('alerts-pane');
    pane.innerHTML = buildAlertsPage();
    const tbody = document.getElementById('alertTableBody');
    tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted">加载中...</td></tr>';

    try {
        const ignoreSink = (currentMode === 'investigate');
        const aggregate = (currentMode === 'monitor');
        const payload = {
            action: 'list',
            page: currentPage,
            size: currentSize,
            ignore_filters: ignoreSink,
            aggregate: aggregate,
            filters: {}
        };

        const srcIp = document.getElementById('filterSrcIP')?.value.trim() || '';
        const dstIp = document.getElementById('filterDstIP')?.value.trim() || '';
        const attackType = document.getElementById('filterAttackType')?.value.trim() || '';
        const severity = document.getElementById('filterSeverity')?.value || '';
        const fromInput = document.getElementById('filterTimeFrom')?.value || '';
        const toInput = document.getElementById('filterTimeTo')?.value || '';

        if (srcIp) payload.filters.src_ip = srcIp;
        if (dstIp) payload.filters.dst_ip = dstIp;
        if (attackType) payload.filters.attack_type = attackType;
        if (severity) payload.filters.severity = severity;
        if (fromInput) payload.time_from = fromInput.replace('T', ' ') + ':00';
        if (toInput) payload.time_to = toInput.replace('T', ' ') + ':59';

        const r = await apiCall('/alerts', payload);
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td colspan="11" class="text-center text-danger">加载失败: ${r.msg}</td></tr>`;
            return;
        }

        const data = r.data;
        const items = data.items || [];
        const total = data.total || 0;
        const aggregated = data.aggregated || false;

        document.getElementById('paginationInfo').textContent = `共 ${total} 条，第 ${currentPage} 页，每页 ${currentSize} 条`;

        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted">暂无告警</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(item => {
            const detailId = aggregated ? (item.sample_alert_id || item.fingerprint) : (item.alert_id || '');
            if (aggregated) {
                // ========== 聚合模式（包含 dest_ip） ==========
                return `
                    <tr class="alert-row">
                        <td><input type="checkbox" class="alert-checkbox" data-alert-id="${item.fingerprint}"></td>
                        <td><code class="small">${escapeHtml(item.fingerprint || '-')}</code></td>
                        <td><strong>${escapeHtml(item.src_ip || '-')}</strong></td>
                        <td>${escapeHtml(item.dest_ip || '-')}</td>
                        <td class="small">${escapeHtml(item.uri || '-')}</td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${escapeHtml(item.attack_type || 'UNKNOWN')}</span></td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${escapeHtml(item.severity || 'INFO')}</span></td>
                        <td class="${getPriorityColor(item.max_priority_score)}">${item.max_priority_score !== undefined ? item.max_priority_score.toFixed(1) : '-'}</td>
                        <td><span class="badge bg-info">${item.count} 次</span></td>
                        <td class="log-time">${formatTime(item.last_log_time)}</td>
                        <td>
                            <button class="btn btn-outline-primary btn-sm" onclick="showDetail('${detailId}')">详情</button>
                            <button class="btn btn-outline-danger btn-sm sink-btn" onclick="showAggregateSink('${item.fingerprint}')">聚合沉底</button>
                            <button class="btn btn-outline-warning btn-sm sink-btn" onclick="showIpSink('${item.src_ip}')">IP批量沉底</button>
                        </td>
                    </tr>
                `;
            } else {
                // ========== 明细模式 ==========
                return `
                    <tr class="alert-row">
                        <td><input type="checkbox" class="alert-checkbox" data-alert-id="${item.alert_id || ''}"></td>
                        <td><code class="small">${escapeHtml(item.alert_id || '-')}</code></td>
                        <td><strong>${escapeHtml(item.src_ip || '-')}</strong></td>
                        <td>${escapeHtml(item.dest_ip || '-')}</td>
                        <td class="small">${escapeHtml(item.uri || '-')}</td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${escapeHtml(item.attack_type || 'UNKNOWN')}</span></td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${escapeHtml(item.severity || 'INFO')}</span></td>
                        <td class="${getPriorityColor(item.priority_score)}">${item.priority_score !== undefined ? item.priority_score.toFixed(1) : '-'}</td>
                        <td>${item.is_blocked ? '<span class="badge bg-secondary">已沉底</span>' : '<span class="badge bg-danger">待处理</span>'}</td>
                        <td class="log-time">${formatTime(item.log_time)}</td>
                        <td>
                            <button class="btn btn-outline-primary btn-sm" onclick="showDetail('${detailId}')">详情</button>
                            ${!item.is_blocked ? `<button class="btn btn-outline-danger btn-sm sink-btn" onclick="showSink('${item.alert_id}')">沉底</button>` : ''}
                        </td>
                    </tr>
                `;
            }
        }).join('');

        updateBatchBar();
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="11" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

// ----- 聚合沉底 -----
async function showAggregateSink(fingerprint) {
    const parts = fingerprint.split('|');
    const src_ip = parts[0] || '';
    const dest_ip = parts[1] || '';
    const attack_type = parts[2] || '';
    const uri = parts[3] || '';

    if (!src_ip || !attack_type) {
        alert('聚合信息不完整，无法沉底');
        return;
    }

    if (!confirm(`确定要沉底该聚合下的所有告警吗？\n\n源IP: ${src_ip}\n目标IP: ${dest_ip || '(空)'}\n攻击类型: ${attack_type}\nURI: ${uri || '(空)'}`)) return;

    const reason = prompt('请输入沉底原因：') || '聚合沉底';

    try {
        const r = await apiCall('/actions/aggregate_sink', {
            src_ip: src_ip,
            attack_type: attack_type,
            uri: uri,
            reason: reason
        });
        if (r.code === 0) {
            alert(`成功沉底 ${r.data.affected_count} 条告警`);
            refreshData();
        } else {
            alert('沉底失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- IP批量沉底（监控模式快捷入口） -----
async function showIpSink(src_ip) {
    if (!src_ip || src_ip === '') {
        alert('该聚合条目没有有效的源IP');
        return;
    }
    if (!confirm(`确定要沉底 IP ${src_ip} 的所有告警吗？`)) return;
    const reason = prompt('请输入沉底原因：') || 'IP批量沉底';
    try {
        const r = await apiCall('/actions/ip_sink', {
            src_ip: src_ip,
            reason: reason
        });
        if (r.code === 0) {
            alert(`成功沉底 ${r.data.affected_count} 条告警`);
            refreshData();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- 构建告警页面 HTML -----
function buildAlertsPage() {
    return `
        <!-- 统计卡片 -->
        <div class="row mb-4" id="statsCards">
            <div class="col-md-3 mb-2"><div class="card stats-card"><div class="card-body"><h6 class="card-subtitle text-muted">总告警</h6><h2 class="card-title mb-0" id="statTotal">-</h2></div></div></div>
            <div class="col-md-3 mb-2"><div class="card stats-card border-danger"><div class="card-body"><h6 class="card-subtitle text-danger">待处理</h6><h2 class="card-title mb-0 text-danger" id="statPending">-</h2></div></div></div>
            <div class="col-md-3 mb-2"><div class="card stats-card border-secondary"><div class="card-body"><h6 class="card-subtitle text-secondary">已沉底</h6><h2 class="card-title mb-0 text-secondary" id="statBlocked">-</h2></div></div></div>
            <div class="col-md-3 mb-2"><div class="card stats-card border-primary"><div class="card-body"><h6 class="card-subtitle text-primary">今日新增</h6><h2 class="card-title mb-0 text-primary" id="statToday">-</h2></div></div></div>
        </div>

        <!-- 过滤栏 -->
        <div class="filter-section mb-3">
            <div class="row align-items-end">
                <div class="col-auto">
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-primary active" id="modeMonitor" onclick="setMode('monitor')">📊 监控</button>
                        <button type="button" class="btn btn-outline-secondary" id="modeInvestigate" onclick="setMode('investigate')">🔍 调查</button>
                    </div>
                </div>
                <div class="col-auto"><div class="filter-label">源IP</div><input type="text" class="form-control form-control-sm filter-input" id="filterSrcIP" placeholder="精确IP 或 10. 前缀"></div>
                <div class="col-auto"><div class="filter-label">目的IP</div><input type="text" class="form-control form-control-sm filter-input" id="filterDstIP" placeholder="精确IP 或 192.168. 前缀"></div>
                <div class="col-auto"><div class="filter-label">攻击类型</div><input type="text" class="form-control form-control-sm filter-input-sm" id="filterAttackType" placeholder="XSS"></div>
                <div class="col-auto">
                    <div class="filter-label">威胁等级</div>
                    <select class="form-select form-select-sm filter-input-sm" id="filterSeverity">
                        <option value="">全部</option>
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                        <option value="INFO">INFO</option>
                    </select>
                </div>
                <div class="col-auto"><div class="filter-label">开始时间</div><input type="datetime-local" class="form-control form-control-sm filter-input" id="filterTimeFrom"></div>
                <div class="col-auto"><div class="filter-label">结束时间</div><input type="datetime-local" class="form-control form-control-sm filter-input" id="filterTimeTo"></div>
                <div class="col-auto">
                    <div class="filter-label">每页数量</div>
                    <select class="form-select form-select-sm filter-input-sm" id="pageSizeSelect" onchange="changePageSize()">
                        <option value="10">10</option><option value="25" selected>25</option>
                        <option value="50">50</option><option value="100">100</option>
                        <option value="200">200</option>
                        <option value="500">500</option>
                        <option value="1000">1000</option>
                    </select>
                </div>
                <div class="col-auto">
                    <div class="filter-label">定时刷新</div>
                    <select class="form-select form-select-sm filter-input-sm" id="refreshInterval" onchange="setRefreshInterval()">
                        <option value="0">关闭</option>
                        <option value="5" selected>5分钟</option>
                        <option value="10">10分钟</option>
                        <option value="20">20分钟</option>
                        <option value="30">30分钟</option>
                        <option value="60">60分钟</option>
                    </select>
                </div>
                <div class="col-auto">
                    <div class="btn-group btn-group-sm" role="group">
                        <button class="btn btn-outline-secondary" onclick="setQuickTime(10)">10分钟</button>
                        <button class="btn btn-outline-secondary" onclick="setQuickTime(60)">1小时</button>
                        <button class="btn btn-outline-secondary" onclick="setQuickTime(1440)">1天</button>
                        <button class="btn btn-outline-secondary" onclick="setQuickTime(10080)">7天</button>
                    </div>
                </div>
                <div class="col-auto">
                    <button class="btn btn-primary btn-sm" onclick="applyFilters()">🔍 搜索</button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="clearFilters()">清空</button>
                </div>
            </div>
        </div>

        <!-- 批量操作栏 -->
        <div class="batch-bar" id="batchBar">
            <span class="text-muted small" id="selectedCount">已选 0 条</span>
            <button class="btn btn-danger btn-sm" onclick="batchSink()">⬇️ 批量沉底</button>
            <button class="btn btn-outline-secondary btn-sm" onclick="clearSelection()">取消选择</button>
        </div>

        <!-- 告警列表 -->
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead>
                    <tr>
                        <th class="checkbox-col"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                        <th style="width:140px;">告警ID</th>
                        <th>源IP</th>
                        <th>目的IP</th>
                        <th>URI</th>
                        <th>攻击类型</th>
                        <th>等级</th>
                        <th style="width:100px;">优先级</th>
                        <th style="width:80px;">状态</th>
                        <th style="width:160px;">时间</th>
                        <th style="width:120px;">操作</th>
                    </tr>
                </thead>
                <tbody id="alertTableBody">
                    <tr><td colspan="11" class="text-center text-muted">加载中...</td></tr>
                </tbody>
            </table>
        </div>

        <!-- 分页 -->
        <div class="d-flex justify-content-between align-items-center mt-3">
            <span class="text-muted small" id="paginationInfo">共 0 条</span>
            <nav><ul class="pagination pagination-sm mb-0" id="paginationControls">
                <li class="page-item"><a class="page-link" href="#" onclick="changePage(-1)">上一页</a></li>
                <li class="page-item"><a class="page-link" href="#" onclick="changePage(1)">下一页</a></li>
            </ul></nav>
        </div>
    `;
}

// ----- 模式切换 -----
function setMode(mode) {
    currentMode = mode;
    currentPage = 1;
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
    loadAlerts();
}

function applyFilters() { currentPage = 1; loadAlerts(); }
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

function changePageSize() {
    const sel = document.getElementById('pageSizeSelect');
    if (sel) currentSize = parseInt(sel.value);
    currentPage = 1;
    loadAlerts();
}

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage < 1) return;
    currentPage = newPage;
    loadAlerts();
}

function refreshData() { loadStats(); loadAlerts(); }

// ----- 定时刷新 -----
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

// ----- 批量操作 -----
function toggleSelectAll() {
    const checked = document.getElementById('selectAll')?.checked || false;
    document.querySelectorAll('.alert-checkbox').forEach(cb => cb.checked = checked);
    updateBatchBar();
}

function getSelectedAlertIds() {
    const ids = [];
    document.querySelectorAll('.alert-checkbox:checked').forEach(cb => {
        if (cb.dataset.alertId) ids.push(cb.dataset.alertId);
    });
    return ids;
}

function updateBatchBar() {
    const ids = getSelectedAlertIds();
    const bar = document.getElementById('batchBar');
    const countEl = document.getElementById('selectedCount');
    if (countEl) countEl.textContent = `已选 ${ids.length} 条`;
    if (bar) {
        if (ids.length > 0) bar.classList.add('show');
        else bar.classList.remove('show');
    }
}

function clearSelection() {
    document.querySelectorAll('.alert-checkbox').forEach(cb => cb.checked = false);
    const selAll = document.getElementById('selectAll');
    if (selAll) selAll.checked = false;
    updateBatchBar();
}

async function batchSink() {
    const ids = getSelectedAlertIds();
    if (ids.length === 0) { alert('请至少选择一条告警'); return; }
    if (!confirm(`确定要沉底选中的 ${ids.length} 条告警吗？`)) return;
    const reason = prompt('请输入沉底原因：') || '批量沉底';
    try {
        const r = await apiCall('/actions/batch', {
            action: 'batch_sink',
            alert_ids: ids,
            reason: reason
        });
        if (r.code === 0) {
            alert(`成功沉底 ${r.data.affected_count} 条告警`);
            clearSelection();
            refreshData();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) { alert('网络错误: ' + e.message); }
}