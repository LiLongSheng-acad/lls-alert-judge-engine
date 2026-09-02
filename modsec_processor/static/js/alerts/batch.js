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
            loadAlerts();
            loadStats();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) { alert('网络错误: ' + e.message); }
}