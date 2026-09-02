// ============================================================
// 操作历史模块（含沉底、规则、资产审计）
// ============================================================

let historyPage = 1;
let historySize = 20;
let historyTotal = 0;
let historyFilterAction = '';
let historyFilterOperator = '';

function buildHistoryPage() {
    return `
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="mb-0">操作历史</h5>
            <div>
                <button class="btn btn-outline-secondary btn-sm" onclick="loadHistory()">🔄 刷新</button>
            </div>
        </div>
        <div class="row mb-3">
            <div class="col-auto">
                <label class="form-label small">操作类型</label>
                <select class="form-select form-select-sm" id="historyFilterAction" onchange="applyHistoryFilter()">
                    <option value="">全部</option>
                    <option value="create">创建</option>
                    <option value="delete">删除</option>
                    <option value="enable">启用</option>
                    <option value="disable">禁用</option>
                    <option value="sink">沉底</option>
                    <option value="ip_sink">IP批量沉底</option>
                    <option value="aggregate_sink">聚合沉底</option>
                </select>
            </div>
            <div class="col-auto">
                <label class="form-label small">操作人</label>
                <input type="text" class="form-control form-control-sm" id="historyFilterOperator" placeholder="输入用户名" style="width:120px;">
            </div>
            <div class="col-auto d-flex align-items-end">
                <button class="btn btn-primary btn-sm" onclick="applyHistoryFilter()">搜索</button>
                <button class="btn btn-outline-secondary btn-sm" onclick="clearHistoryFilter()">清空</button>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead><tr>
                    <th>时间</th><th>操作人</th><th>操作</th><th>目标</th>
                    <th>详情</th><th>来源IP</th>
                </tr></thead>
                <tbody id="historyTableBody"><tr><td colspan="6" class="text-center text-muted">加载中...</td></tr></tbody>
            </table>
        </div>
        <div class="d-flex justify-content-between align-items-center mt-3">
            <span class="text-muted small" id="historyPaginationInfo">共 0 条</span>
            <nav><ul class="pagination pagination-sm mb-0" id="historyPaginationControls">
                <li class="page-item"><a class="page-link" href="#" onclick="changeHistoryPage(-1)">上一页</a></li>
                <li class="page-item"><a class="page-link" href="#" onclick="changeHistoryPage(1)">下一页</a></li>
            </ul></nav>
        </div>
    `;
}

function getHistoryActionLabel(action) {
    const map = {
        'create': '创建',
        'delete': '删除',
        'enable': '启用',
        'disable': '禁用',
        'sink': '沉底',
        'ip_sink': 'IP批量沉底',
        'aggregate_sink': '聚合沉底',
        'update': '更新'
    };
    return map[action] || action;
}

function getHistoryActionBadge(action) {
    const map = {
        'create': 'bg-success',
        'delete': 'bg-danger',
        'enable': 'bg-primary',
        'disable': 'bg-secondary',
        'sink': 'bg-warning text-dark',
        'ip_sink': 'bg-info text-dark',
        'aggregate_sink': 'bg-light text-dark',
        'update': 'bg-primary'
    };
    return map[action] || 'bg-secondary';
}

async function loadHistory() {
    const pane = document.getElementById('history-pane');
    if (!pane) return;
    if (!pane.querySelector('table')) {
        pane.innerHTML = buildHistoryPage();
    }

    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">加载中...</td></tr>';

    const filterAction = document.getElementById('historyFilterAction')?.value || '';
    const filterOperator = document.getElementById('historyFilterOperator')?.value.trim() || '';
    const params = { action: 'list', page: historyPage, size: historySize };
    if (filterAction) params.filter_action = filterAction;
    if (filterOperator) params.filter_operator = filterOperator;

    let allItems = [];

    try {
        // 并行请求三个审计源
        const [ruleResp, assetResp, sinkResp] = await Promise.all([
            apiCall('/audit/rules', params).catch(() => ({ code: 0, data: { items: [] } })),
            apiCall('/audit/assets', params).catch(() => ({ code: 0, data: { items: [] } })),
            apiCall('/actions/history', {}).catch(() => ({ code: 0, data: { items: [] } }))
        ]);

        // 规则审计
        if (ruleResp.code === 0) {
            ruleResp.data.items.forEach(item => {
                item._type = 'rule';
                item._target = item.rule_id || '-';
                allItems.push(item);
            });
        }

        // 资产审计
        if (assetResp.code === 0) {
            assetResp.data.items.forEach(item => {
                item._type = 'asset';
                item._target = item.asset_id || '-';
                // 将 asset_data 转为可读字符串
                if (item.asset_data && typeof item.asset_data === 'object') {
                    item._detail = JSON.stringify(item.asset_data);
                } else {
                    item._detail = item.detail || '-';
                }
                allItems.push(item);
            });
        }

        // 沉底审计（原有的 sink_audit.log）
        if (sinkResp.code === 0) {
            sinkResp.data.items.forEach(item => {
                item._type = 'sink';
                item._target = item.src_ip || item.alert_id || '-';
                item._detail = item.reason || '-';
                allItems.push(item);
            });
        }

        // 按时间排序（降序）
        allItems.sort((a, b) => (a.created_at || '').localeCompare(b.created_at || '') * -1);

        // 分页处理
        const total = allItems.length;
        const start = (historyPage - 1) * historySize;
        const end = Math.min(start + historySize, total);
        const pageItems = allItems.slice(start, end);

        document.getElementById('historyPaginationInfo').textContent = `共 ${total} 条，第 ${historyPage} 页，每页 ${historySize} 条`;

        if (pageItems.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">暂无操作记录</td></tr>';
            return;
        }

        tbody.innerHTML = pageItems.map(item => {
            let target = item._target || '-';
            let detail = item._detail || '-';
            let actionLabel = getHistoryActionLabel(item.action);
            let badgeClass = getHistoryActionBadge(item.action);
            let created = item.created_at || item.timestamp || '-';
            let operator = item.operator || '-';
            let client_ip = item.client_ip || '-';

            // 如果是规则审计，显示规则ID和详情
            if (item._type === 'rule') {
                detail = item.detail || '-';
            }

            return `
                <tr>
                    <td class="small">${created}</td>
                    <td>${operator}</td>
                    <td><span class="badge ${badgeClass}">${actionLabel}</span></td>
                    <td><code>${target}</code></td>
                    <td class="small">${detail}</td>
                    <td>${client_ip}</td>
                </tr>
            `;
        }).join('');

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

function applyHistoryFilter() {
    historyPage = 1;
    loadHistory();
}

function clearHistoryFilter() {
    const actionEl = document.getElementById('historyFilterAction');
    const operatorEl = document.getElementById('historyFilterOperator');
    if (actionEl) actionEl.value = '';
    if (operatorEl) operatorEl.value = '';
    historyPage = 1;
    loadHistory();
}

function changeHistoryPage(delta) {
    const newPage = historyPage + delta;
    if (newPage < 1) return;
    historyPage = newPage;
    loadHistory();
}


window.loadHistory = loadHistory;
window.applyHistoryFilter = applyHistoryFilter;
window.clearHistoryFilter = clearHistoryFilter;
window.changeHistoryPage = changeHistoryPage;