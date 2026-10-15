// ============================================================
// 批量操作（选择、批量沉底）
// ============================================================

function toggleSelectAll() {
    const checked = document.getElementById('selectAll')?.checked || false;
    document.querySelectorAll('.alert-checkbox').forEach(cb => cb.checked = checked);
    updateBatchBar();
}

function getSelectedAlertIds() {
    const ids = [];
    document.querySelectorAll('.alert-checkbox:checked').forEach(cb => {
        // 聚合行的勾选框是 disabled 的（其 data 里没有真实 alert_id）——
        // 必须跳过，否则会把 fingerprint 当成 alert_id 发出去，静默匹配 0 条
        if (cb.disabled) return;
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

// 批量处置：统一走同一个研判弹窗（不再用 prompt 绕过留痕）
function batchSink() {
    const ids = getSelectedAlertIds();
    if (ids.length === 0) { alert('请至少选择一条告警'); return; }
    window.showBatchSink(ids);
}