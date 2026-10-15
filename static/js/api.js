// ============================================================
// API 调用 + 工具函数
// ============================================================

const API_BASE = window.location.origin + '/api';

// ----- 用户管理 -----
function getCurrentUser() {
    const match = document.cookie.match(/alert_user=([^;]+)/);
    return match ? match[1] : 'system';
}

function switchUser(username) {
    if (!username || username.trim() === '') return;
    username = username.trim();
    document.cookie = `alert_user=${username}; path=/; max-age=604800`;
    const display = document.getElementById('currentUserDisplay');
    if (display) display.textContent = username;
    if (typeof loadAlerts === 'function') loadAlerts();
    if (typeof loadStats === 'function') loadStats();
    if (typeof loadRules === 'function') loadRules();
    if (typeof loadHistory === 'function') loadHistory();
    if (typeof refreshPromotionTab === 'function') refreshPromotionTab();
}

// ----- XSS 防御 -----
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
    };
    return String(text).replace(/[&<>"'/]/g, function(s) { return map[s]; });
}

// ----- 通用 API 调用 -----
async function apiCall(endpoint, payload) {
    const resp = await fetch(API_BASE + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        credentials: 'include'
    });
    if (resp.status === 401) {
        alert('认证失败，请检查用户名和密码');
        throw new Error('Unauthorized');
    }
    const data = await resp.json();

    // 转义数据中的字符串字段（XSS 防御）
    if (data.data && data.data.items) {
        data.data.items = data.data.items.map(item => {
            const escaped = {};
            for (const [key, value] of Object.entries(item)) {
                if (typeof value === 'string') {
                    escaped[key] = escapeHtml(value);
                } else {
                    escaped[key] = value;
                }
            }
            return escaped;
        });
    }
    return data;
}

// ----- 工具函数 -----
function getSeverityClass(sev) {
    const map = { 'CRITICAL': 'danger', 'HIGH': 'danger', 'MEDIUM': 'warning', 'LOW': 'success', 'INFO': 'info' };
    return map[sev] || 'secondary';
}

function formatTime(t) {
    if (!t) return '';
    try {
        const parts = t.split(' ');
        if (parts.length >= 2) return parts[0] + ' ' + parts[1].substring(0, 8);
        return t;
    } catch { return t; }
}

// 优先级着色：低于红线 = 看了就亏（可以不看）→ 绿；高于红线 → 红
function getPriorityColor(score, belowRedLine) {
    if (score === null || score === undefined) return '';
    if (score < 0) return 'text-secondary';
    if (belowRedLine) return 'text-success';
    return 'text-danger fw-bold';
}

function formatLocal(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
}
