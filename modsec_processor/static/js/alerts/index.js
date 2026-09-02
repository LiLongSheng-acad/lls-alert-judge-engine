// ============================================================
// 告警模块入口 - 统一暴露所有函数到全局
// ============================================================

// 确保全局变量存在（由 main.js 定义，但防止加载顺序问题）
if (typeof currentPage === 'undefined') window.currentPage = 1;
if (typeof currentSize === 'undefined') window.currentSize = 25;

// 暴露所有告警相关函数
window.loadAlerts = loadAlerts;
window.loadStats = loadStats;
window.applyFilters = applyFilters;
window.clearFilters = clearFilters;
window.setRefreshInterval = setRefreshInterval;
window.setQuickTime = setQuickTime;
window.changePage = changePage;
window.changePageSize = changePageSize;
window.toggleSelectAll = toggleSelectAll;
window.batchSink = batchSink;
window.clearSelection = clearSelection;
window.showSink = showSink;
window.confirmSink = confirmSink;
window.showAggregateSink = showAggregateSink;
window.showIpSink = showIpSink;
window.setMode = setMode;
window.updateBatchBar = updateBatchBar;

console.log('告警模块已加载');
