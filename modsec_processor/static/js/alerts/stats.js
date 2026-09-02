// ============================================================
// 统计卡片模块
// ============================================================

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