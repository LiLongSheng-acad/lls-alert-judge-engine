// ============================================================
// 规则管理模块
// ============================================================

let rulePage = 1, ruleSize = 20, ruleTotal = 0;

// ----- 构建规则管理页面 HTML -----
function buildRulesPage() {
    return `
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="mb-0">沉底规则列表</h5>
            <div>
                <button class="btn btn-primary btn-sm" onclick="showCreateRule()">➕ 新增规则</button>
                <button class="btn btn-outline-secondary btn-sm" onclick="loadRules()">🔄 刷新</button>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead><tr>
                    <th>规则ID</th><th>字段</th><th>操作符</th><th>匹配值</th>
                    <th>作用域</th><th>创建人</th><th>状态</th><th>过期时间</th><th>原因</th><th style="width:120px;">操作</th>
                </tr></thead>
                <tbody id="ruleTableBody"><tr><td colspan="10" class="text-center text-muted">加载中...</td></tr></tbody>
            </table>
        </div>
        <div class="d-flex justify-content-between align-items-center mt-3">
            <span class="text-muted small" id="rulePaginationInfo">共 0 条</span>
            <nav><ul class="pagination pagination-sm mb-0" id="rulePaginationControls">
                <li class="page-item"><a class="page-link" href="#" onclick="changeRulePage(-1)">上一页</a></li>
                <li class="page-item"><a class="page-link" href="#" onclick="changeRulePage(1)">下一页</a></li>
            </ul></nav>
        </div>
    `;
}

// ----- 加载规则列表 -----
async function loadRules() {
    const pane = document.getElementById('rules-pane');
    if (!pane) return;

    if (!pane.querySelector('table')) {
        pane.innerHTML = buildRulesPage();
    }

    const tbody = document.getElementById('ruleTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted">加载中...</td></tr>';
    try {
        const r = await apiCall('/rules', { action: 'list', page: rulePage, size: ruleSize });
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="text-center text-danger">加载失败: ${r.msg}</td></tr>`;
            return;
        }
        const items = r.data.items || [];
        ruleTotal = r.data.total || 0;
        const info = document.getElementById('rulePaginationInfo');
        if (info) info.textContent = `共 ${ruleTotal} 条，第 ${rulePage} 页，每页 ${ruleSize} 条`;
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted">暂无规则</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(rule => `
            <tr>
                <td><code>${rule.id || '-'}</code></td>
                <td>${rule.field || '-'}</td>
                <td>${rule.operator || '-'}</td>
                <td><code>${rule.value || '-'}</code></td>
                <td><span class="badge ${rule.scope === 'global' ? 'bg-primary' : 'bg-secondary'}">${rule.scope || 'personal'}</span></td>
                <td>${rule.creator || '-'}</td>
                <td>${rule.enabled !== false ? '<span class="badge bg-success">启用</span>' : '<span class="badge bg-secondary">禁用</span>'}</td>
                <td class="small">${rule.expire_at ? new Date(rule.expire_at).toLocaleString() : '-'}</td>
                <td class="small">${rule.reason || '-'}</td>
                <td>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteRule('${rule.id}')">删除</button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="toggleRule('${rule.id}', ${!rule.enabled})">${rule.enabled !== false ? '禁用' : '启用'}</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

function changeRulePage(delta) {
    const newPage = rulePage + delta;
    if (newPage < 1) return;
    rulePage = newPage;
    loadRules();
}

// ----- 创建规则 -----
function showCreateRule() {
    const now = new Date();
    now.setHours(now.getHours() + 1);
    const expireEl = document.getElementById('ruleExpireAt');
    if (expireEl) expireEl.value = now.toISOString().slice(0, 16);
    const reasonEl = document.getElementById('ruleReason');
    if (reasonEl) reasonEl.value = '';
    const valueEl = document.getElementById('ruleValue');
    if (valueEl) valueEl.value = '';
    const templateEl = document.getElementById('ruleTemplate');
    if (templateEl) templateEl.value = '';
    new bootstrap.Modal(document.getElementById('createRuleModal')).show();
}

function applyTemplate() {
    const select = document.getElementById('ruleTemplate');
    if (!select || !select.value) return;
    try {
        const template = JSON.parse(select.value);
        const fieldEl = document.getElementById('ruleField');
        const operatorEl = document.getElementById('ruleOperator');
        const valueEl = document.getElementById('ruleValue');
        if (fieldEl) fieldEl.value = template.field;
        if (operatorEl) operatorEl.value = template.operator;
        if (valueEl) valueEl.value = template.value;
    } catch (e) { console.error('模板解析失败', e); }
}

async function confirmCreateRule() {
    const field = document.getElementById('ruleField')?.value || '';
    const operator = document.getElementById('ruleOperator')?.value || '';
    const value = document.getElementById('ruleValue')?.value.trim() || '';
    const scope = document.getElementById('ruleScope')?.value || '';
    const expire_at = document.getElementById('ruleExpireAt')?.value || '';
    const reason = document.getElementById('ruleReason')?.value.trim() || '';

    if (!value || !reason) { alert('请完整填写必填字段'); return; }
    const isGlobal = (scope === 'global');
    if (!expire_at) {
        // 留空：仅全局规则允许，表示长期有效（升格后的长期规则形态）
        if (!isGlobal) { alert('个人规则必须填写过期时间（最长24小时）'); return; }
    } else {
        const expire = new Date(expire_at);
        const now = new Date();
        const diffHours = (expire - now) / (1000 * 60 * 60);
        if (diffHours <= 0) { alert('过期时间必须是将来的时间'); return; }
        if (!isGlobal && diffHours > 24) { alert('个人规则过期时间不能超过24小时'); return; }
    }

    try {
        const r = await apiCall('/rules', {
            action: 'create',
            field, operator, value, scope,
            expire_at, reason
        });
        if (r.code === 0) {
            alert('规则创建成功');
            bootstrap.Modal.getInstance(document.getElementById('createRuleModal')).hide();
            loadRules();
        } else {
            alert('创建失败: ' + r.msg);
        }
    } catch (e) { alert('网络错误: ' + e.message); }
}

// ----- 删除规则 -----
async function deleteRule(ruleId) {
    if (!confirm('确定要删除规则 ' + ruleId + ' 吗？')) return;
    try {
        const r = await apiCall('/rules', { action: 'delete', rule_id: ruleId });
        if (r.code === 0) {
            alert('删除成功');
            loadRules();
        } else {
            alert('删除失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- 启用/禁用规则 -----
async function toggleRule(ruleId, enabled) {
    try {
        const r = await apiCall('/rules', { action: 'toggle', rule_id: ruleId, enabled });
        if (r.code === 0) {
            alert(r.msg);
            loadRules();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ============================================================
// 暴露函数到全局（确保 onclick 能访问）
// ============================================================
window.deleteRule = deleteRule;
window.toggleRule = toggleRule;
window.showCreateRule = showCreateRule;
window.confirmCreateRule = confirmCreateRule;
window.applyTemplate = applyTemplate;
window.changeRulePage = changeRulePage;
window.loadRules = loadRules;