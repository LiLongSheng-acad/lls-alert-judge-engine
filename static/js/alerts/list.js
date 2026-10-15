// ============================================================
// 告警列表渲染 + 分页
// ============================================================

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
                <div class="col-auto">
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-primary active" id="viewMain" onclick="setView('main')">🌐 全部</button>
                        <button type="button" class="btn btn-outline-secondary" id="viewInternal" onclick="setView('internal')">🏠 内网源</button>
                        <button type="button" class="btn btn-outline-secondary" id="viewProcessing" onclick="setView('processing')">🔎 排查中</button>
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
            <button class="btn btn-danger btn-sm" onclick="batchSink()">⬇️ 批量处置</button>
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

async function loadAlerts() {
    const pane = document.getElementById('alerts-pane');
    if (!pane) return;

    // 1. 读取当前输入值（在重建之前）
    const srcIp = document.getElementById('filterSrcIP')?.value.trim() || '';
    const dstIp = document.getElementById('filterDstIP')?.value.trim() || '';
    const attackType = document.getElementById('filterAttackType')?.value.trim() || '';
    const severity = document.getElementById('filterSeverity')?.value || '';
    const fromInput = document.getElementById('filterTimeFrom')?.value || '';
    const toInput = document.getElementById('filterTimeTo')?.value || '';

    // 2. 重建页面
    pane.innerHTML = buildAlertsPage();

    // 3. 恢复输入值
    const srcIpEl = document.getElementById('filterSrcIP');
    if (srcIpEl) srcIpEl.value = srcIp;
    const dstIpEl = document.getElementById('filterDstIP');
    if (dstIpEl) dstIpEl.value = dstIp;
    const attackTypeEl = document.getElementById('filterAttackType');
    if (attackTypeEl) attackTypeEl.value = attackType;
    const severityEl = document.getElementById('filterSeverity');
    if (severityEl) severityEl.value = severity;
    const fromEl = document.getElementById('filterTimeFrom');
    if (fromEl) fromEl.value = fromInput;
    const toEl = document.getElementById('filterTimeTo');
    if (toEl) toEl.value = toInput;

    const tbody = document.getElementById('alertTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted">加载中...</td></tr>';

    try {
        // 使用全局变量 currentMode（由 main.js 维护）
        const ignoreSink = (currentMode === 'investigate');
        const aggregate = (currentMode === 'monitor');

        const payload = {
            action: 'list',
            page: currentPage,
            size: currentSize,
            ignore_filters: ignoreSink,
            aggregate: aggregate,
            view: (typeof currentView !== 'undefined' ? currentView : 'main'),
            filters: {}
        };

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

        const items = r.data.items || [];
        const total = r.data.total || 0;
        const aggregated = r.data.aggregated || false;

        const info = document.getElementById('paginationInfo');
        if (info) info.textContent = `共 ${total} 条，第 ${currentPage} 页，每页 ${currentSize} 条`;

        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted">暂无告警</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(item => {
            const detailId = aggregated ? (item.sample_alert_id || item.fingerprint) : (item.alert_id || '');
            if (aggregated) {
                return `
                    <tr class="alert-row">
                        <td><input type="checkbox" class="alert-checkbox" disabled title="聚合行代表多条告警，不支持按 ID 批量处置 —— 请用本行的「聚合处置」"></td>
                        <td><code class="small">${item.fingerprint || '-'}</code></td>
                        <td><strong>${item.src_ip || '-'}</strong></td>
                        <td>${item.dest_ip || '-'}</td>
                        <td class="small">${item.uri || '-'}</td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${item.attack_type || 'UNKNOWN'}</span></td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${item.severity || 'INFO'}</span></td>
                        <td class="${getPriorityColor(item.max_priority_score, item.below_red_line)}">${item.max_priority_score !== undefined ? item.max_priority_score.toFixed(1) : '-'}</td>
                        <td><span class="badge bg-info">${item.count} 次</span>${item.has_processing ? ' <span class="badge bg-warning text-dark">排查中</span>' : ''}</td>
                        <td class="log-time">${formatTime(item.last_log_time)}</td>
                        <td>
                            <button class="btn btn-outline-primary btn-sm" onclick="showDetail('${detailId}')">详情</button>
                            <button class="btn btn-outline-danger btn-sm sink-btn"
                                    data-src="${escapeHtml(item.src_ip)}"
                                    data-dst="${escapeHtml(item.dest_ip)}"
                                    data-uri="${escapeHtml(item.uri)}"
                                    data-type="${escapeHtml(item.attack_type)}"
                                    onclick="showAggregateSink(this)">聚合处置</button>
                            <button class="btn btn-outline-warning btn-sm sink-btn" onclick="showIpSink('${item.src_ip}')">IP批量处置</button>
                        </td>
                    </tr>
                `;
            } else {
                return `
                    <tr class="alert-row">
                        <td><input type="checkbox" class="alert-checkbox" data-alert-id="${item.alert_id || ''}"></td>
                        <td><code class="small">${item.alert_id || '-'}</code></td>
                        <td><strong>${item.src_ip || '-'}</strong></td>
                        <td>${item.dest_ip || '-'}</td>
                        <td class="small">${item.uri || '-'}</td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${item.attack_type || 'UNKNOWN'}</span></td>
                        <td><span class="badge bg-${getSeverityClass(item.severity)}">${item.severity || 'INFO'}</span></td>
                        <td class="${getPriorityColor(item.priority_score, item.below_red_line)}">${item.priority_score !== undefined ? item.priority_score.toFixed(1) : '-'}</td>
                        <td>${item.is_blocked
                            ? '<span class="badge bg-secondary">已沉底</span>'
                            : (item.is_processed
                                ? '<span class="badge bg-warning text-dark">排查中</span>'
                                : '<span class="badge bg-danger">待处理</span>')}</td>
                        <td class="log-time">${formatTime(item.log_time)}</td>
                        <td>
                            <button class="btn btn-outline-primary btn-sm" onclick="showDetail('${detailId}')">详情</button>
                            ${!item.is_blocked ? `<button class="btn btn-outline-danger btn-sm sink-btn" onclick="showSink('${item.alert_id}')">处置</button>` : ''}
                        </td>
                    </tr>
                `;
            }
        }).join('');

        updateBatchBar();
        loadStats();

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="11" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

// 暴露到全局
window.loadAlerts = loadAlerts;
