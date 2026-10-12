// ============================================================
// 规则升格候选（通知）模块
// 同一规则指纹在窗口期内被「多人多次」提出时，作为一条通知推送到本界面。
// 管理员可「知晓」（15天内不再重复通知）或据此「新建长期规则」。只读展示。
// ============================================================

let promotionMode = 'loose';
let promotionItems = [];

// ----- 构建页面 -----
function buildPromotionsPage() {
    return `
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="mb-0">规则升格候选（通知）</h5>
            <div class="d-flex align-items-center gap-2">
                <label class="form-label small mb-0">判定标准</label>
                <select class="form-select form-select-sm" id="promotionMode" style="width:190px;" onchange="onPromotionModeChange()">
                    <option value="loose">宽松（2人 × 每人2次）</option>
                    <option value="strict">严格（3人 × 每人3次）</option>
                </select>
                <button class="btn btn-outline-secondary btn-sm" onclick="loadPromotions()">🔄 刷新</button>
            </div>
        </div>
        <p class="text-muted small" id="promotionSummary">加载中...</p>
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead><tr>
                    <th>匹配字段</th><th>操作符</th><th>匹配值</th>
                    <th>提出人数</th><th>总次数</th><th>提出人明细</th><th>最近提出</th>
                    <th style="width:210px;">操作</th>
                </tr></thead>
                <tbody id="promotionTableBody"><tr><td colspan="8" class="text-center text-muted">加载中...</td></tr></tbody>
            </table>
        </div>
    `;
}

// ----- 加载候选 -----
async function loadPromotions() {
    const pane = document.getElementById('promotions-pane');
    if (!pane) return;
    if (!pane.querySelector('table')) {
        pane.innerHTML = buildPromotionsPage();
    }
    const modeEl = document.getElementById('promotionMode');
    if (modeEl) modeEl.value = promotionMode;

    const tbody = document.getElementById('promotionTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">加载中...</td></tr>';

    try {
        const r = await apiCall('/promotions', { action: 'list', mode: promotionMode });
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">加载失败: ${r.msg}</td></tr>`;
            return;
        }
        promotionItems = r.data.items || [];
        const summary = document.getElementById('promotionSummary');
        if (summary) {
            summary.textContent = `窗口 ${r.data.window_days} 天，判定：≥${r.data.min_creators} 人且每人≥${r.data.min_per_creator} 次；知晓后 ${r.data.window_days} 天内不再重复通知。当前 ${r.data.total} 条`;
        }
        updatePromotionsBadge(r.data.total || 0);

        if (promotionItems.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">暂无候选</td></tr>';
            return;
        }

        tbody.innerHTML = promotionItems.map((item, idx) => {
            const creators = (item.creators || []).map(c => `${escapeHtml(c.operator)}×${c.count}`).join('、');
            return `
                <tr>
                    <td>${escapeHtml(item.field)}</td>
                    <td>${escapeHtml(item.operator)}</td>
                    <td><code>${escapeHtml(item.value)}</code></td>
                    <td><span class="badge bg-info">${item.creator_count} 人</span></td>
                    <td>${item.total_count} 次</td>
                    <td class="small">${creators}</td>
                    <td class="small">${escapeHtml(item.last_time || '-')}</td>
                    <td>
                        <button class="btn btn-outline-primary btn-sm" onclick="createRuleFromCandidate(${idx})">新建长期规则</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="ackCandidate(${idx})">知晓</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

// ----- 小红点 -----
function updatePromotionsBadge(count) {
    const badge = document.getElementById('promotionsBadge');
    if (!badge) return;
    if (count > 0) {
        badge.textContent = count;
        badge.style.display = '';
    } else {
        badge.style.display = 'none';
    }
}

// ----- 控制 Tab 显隐（仅 admin） -----
function refreshPromotionTab() {
    const item = document.getElementById('promotions-tab-item');
    if (!item) return;
    if (getCurrentUser() === 'admin') {
        item.style.display = '';
        loadPromotions();
    } else {
        item.style.display = 'none';
    }
}

function onPromotionModeChange() {
    const modeEl = document.getElementById('promotionMode');
    if (modeEl) promotionMode = modeEl.value;
    loadPromotions();
}

// ----- 知晓：15 天内不再重复通知 -----
async function ackCandidate(idx) {
    const item = promotionItems[idx];
    if (!item) return;
    if (!confirm(`确认已知晓该升格通知吗？\n\n${item.field} ${item.operator} ${item.value}\n\n知晓后 ${15} 天内同一规则不再重复通知。`)) return;
    try {
        const r = await apiCall('/promotions', {
            action: 'ack',
            fingerprint: item.fingerprint,
            field: item.field,
            rule_operator: item.operator,
            value: item.value
        });
        if (r.code === 0) {
            loadPromotions();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) { alert('网络错误: ' + e.message); }
}

// ----- 据候选预填「新建规则」弹窗（升格为全局长期规则） -----
function createRuleFromCandidate(idx) {
    if (getCurrentUser() !== 'admin') { alert('只有管理员可以创建全局规则'); return; }
    const item = promotionItems[idx];
    if (!item) return;
    if (typeof showCreateRule === 'function') showCreateRule();
    const fieldEl = document.getElementById('ruleField');
    if (fieldEl) fieldEl.value = item.field;
    const operatorEl = document.getElementById('ruleOperator');
    if (operatorEl) operatorEl.value = item.operator;
    const valueEl = document.getElementById('ruleValue');
    if (valueEl) valueEl.value = item.value;
    const scopeEl = document.getElementById('ruleScope');
    if (scopeEl) scopeEl.value = 'global';
    // 升格目标为长期规则：留空过期时间
    const expireEl = document.getElementById('ruleExpireAt');
    if (expireEl) expireEl.value = '';
}

// 暴露到全局
window.loadPromotions = loadPromotions;
window.onPromotionModeChange = onPromotionModeChange;
window.ackCandidate = ackCandidate;
window.createRuleFromCandidate = createRuleFromCandidate;
window.refreshPromotionTab = refreshPromotionTab;
