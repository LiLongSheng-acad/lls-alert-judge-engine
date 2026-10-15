// ============================================================
// 研判处置模块（统一弹窗）
// 三个结论：忽略 / 排查 / 封堵
//   - **只有「忽略」需要理由**（二级枚举）——三个动作里只有它能凭空让告警消失
//   - 排查 / 封堵 的下游痕迹在系统外（拉人、沟通、截图），系统不再要说明
//   - 三者都从主视图移出；「排查」额外标记 is_processed，可用「🔎 排查中」视图找回
// 落库效果见 api/routes/actions.py 的 VERDICT_EFFECT
// ============================================================

// 批量处置时暂存选中的告警 ID
let batchAlertIds = [];

// ----- 二级理由：选「其他」才显示补充说明 -----
function onReasonCodeChange() {
    const code = document.getElementById('sinkReasonCode')?.value || '';
    const noteEl = document.getElementById('sinkReasonNote');
    if (noteEl) noteEl.style.display = (code === '__other__') ? 'block' : 'none';
}

// ----- 结论切换：只有「忽略」显示理由区 -----
function onVerdictChange() {
    const verdict = document.querySelector('input[name="sinkVerdict"]:checked')?.value || 'ignore';
    const wrapper = document.getElementById('sinkReasonWrapper');
    if (wrapper) wrapper.style.display = (verdict === 'ignore') ? 'block' : 'none';
    syncRuleWrapperByMode();
}

// 同步规则勾选框：仅「IP 批量 / 单条切到 IP」且为结案（忽略/封堵）时显示
function syncRuleWrapperByMode() {
    const wrapper = document.getElementById('sinkRuleSyncWrapper');
    if (!wrapper) return;
    const mode = document.getElementById('sinkMode')?.value || 'single';
    const verdict = document.querySelector('input[name="sinkVerdict"]:checked')?.value || 'ignore';
    const radioMode = document.querySelector('input[name="sinkModeRadio"]:checked')?.value || 'single';
    const show = (mode === 'ip_temp' || radioMode === 'ip_temp') && verdict !== 'investigate';
    wrapper.style.display = show ? 'block' : 'none';
    if (show) {
        const cb = document.getElementById('sinkCreateRule');
        if (cb) cb.checked = true;
    }
}

// ----- 复位弹窗 -----
function resetSinkModal(title) {
    const titleEl = document.getElementById('sinkModalTitle');
    if (titleEl) titleEl.textContent = title;

    const ignore = document.getElementById('verdictIgnore');
    if (ignore) ignore.checked = true;
    const code = document.getElementById('sinkReasonCode');
    if (code) code.value = '非攻击';
    const note = document.getElementById('sinkReasonNote');
    if (note) { note.value = ''; note.style.display = 'none'; }

    onVerdictChange();
}

// ----- 单条处置 -----
function showSink(alertId) {
    document.getElementById('sinkAlertId').value = alertId;
    document.getElementById('sinkTarget').value = '';
    document.getElementById('sinkMode').value = 'single';

    resetSinkModal('研判处置');

    const row = document.querySelector(`button[onclick*="showSink('${alertId}')"]`)?.closest('tr');
    if (row) {
        const cells = row.querySelectorAll('td');
        const srcIp = cells[2]?.textContent || '';
        const uri = cells[4]?.textContent || '';
        const attackType = cells[5]?.textContent || '';
        document.getElementById('sinkAlertPreview').textContent = `${srcIp} | ${uri} | ${attackType}`;
    }

    document.querySelector('.sink-mode-options').style.display = 'block';
    document.getElementById('sinkModeSingle').checked = true;
    syncRuleWrapperByMode();

    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- 聚合处置（统一走弹窗，不再用 prompt 绕过留痕） -----
// 参数经由 data-* 传入（button 本身），**不把值拼进 onclick 字符串**：
//   ① 原先把 fingerprint 按 `|` 切分，而后端顺序是 src|dest|uri|attack_type，
//      代码却把 parts[2] 当 attack_type、parts[3] 当 uri —— 顺序反了，导致永远匹配 0 条；
//   ② 值里只要出现单引号（URI 常见，如 `?id=1'`），onclick 属性就会被截断，按钮直接点不动。
function showAggregateSink(btn) {
    const d = (btn && btn.dataset) || {};
    const src_ip = d.src || '';
    const uri = d.uri || '';
    const attack_type = d.type || '';

    if (!src_ip || !attack_type) {
        alert('聚合信息不完整，无法处置');
        return;
    }

    document.getElementById('sinkAlertId').value = '';
    document.getElementById('sinkTarget').value = src_ip;
    document.getElementById('sinkMode').value = 'aggregate';
    document.getElementById('sinkAggAttackType').value = attack_type;
    document.getElementById('sinkAggUri').value = uri;

    resetSinkModal('聚合处置');
    document.getElementById('sinkAlertPreview').textContent =
        `源IP ${src_ip} · 类型 ${attack_type} · URI ${uri || '(空)'} 下的全部告警`;

    document.querySelector('.sink-mode-options').style.display = 'none';
    syncRuleWrapperByMode();

    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- IP 批量处置 -----
function showIpSink(src_ip) {
    if (!src_ip) { alert('该聚合条目没有有效的源IP'); return; }

    document.getElementById('sinkAlertId').value = '';
    document.getElementById('sinkTarget').value = src_ip;
    document.getElementById('sinkMode').value = 'ip_temp';

    resetSinkModal('IP 批量处置');
    document.getElementById('sinkAlertPreview').textContent = `IP ${src_ip} 的全部告警`;

    document.querySelector('.sink-mode-options').style.display = 'none';
    syncRuleWrapperByMode();

    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- 批量处置（多选） -----
function showBatchSink(ids) {
    if (!ids || ids.length === 0) { alert('请至少选择一条告警'); return; }

    batchAlertIds = ids;
    document.getElementById('sinkAlertId').value = '';
    document.getElementById('sinkTarget').value = '';
    document.getElementById('sinkMode').value = 'batch';

    resetSinkModal('批量处置');
    document.getElementById('sinkAlertPreview').textContent = `已选 ${ids.length} 条告警`;

    document.querySelector('.sink-mode-options').style.display = 'none';
    syncRuleWrapperByMode();

    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- 确认（统一处理四个入口） -----
async function confirmSink() {
    const alertId = document.getElementById('sinkAlertId').value;
    const target = document.getElementById('sinkTarget').value;
    const mode = document.getElementById('sinkMode').value;
    const verdict = document.querySelector('input[name="sinkVerdict"]:checked')?.value || 'ignore';
    const createRule = document.getElementById('sinkCreateRule')?.checked || false;

    // 只有「忽略」需要理由
    let reason = '';
    if (verdict === 'ignore') {
        const code = document.getElementById('sinkReasonCode')?.value || '';
        if (code === '__other__') {
            reason = (document.getElementById('sinkReasonNote')?.value || '').trim();
            if (!reason) { alert('选择「其他」时请补充说明'); return; }
        } else {
            reason = code;
        }
    }

    try {
        let endpoint, payload;

        if (mode === 'aggregate') {
            endpoint = '/actions/aggregate_sink';
            payload = {
                src_ip: target,
                attack_type: document.getElementById('sinkAggAttackType').value,
                uri: document.getElementById('sinkAggUri').value,
                verdict, reason
            };
        } else if (mode === 'batch') {
            endpoint = '/actions/batch';
            payload = { action: 'batch_sink', alert_ids: batchAlertIds, verdict, reason };
        } else if (mode === 'ip_temp') {
            endpoint = '/actions/ip_sink';
            payload = { src_ip: target, verdict, reason, create_rule: createRule };
        } else {
            const radioMode = document.querySelector('input[name="sinkModeRadio"]:checked')?.value || 'single';
            endpoint = '/actions/sink';
            payload = { action: 'sink', alert_id: alertId, mode: radioMode, verdict, reason, create_rule: createRule };
        }

        const r = await apiCall(endpoint, payload);
        if (r.code === 0) {
            const n = r.data?.affected_count;
            alert(n === undefined ? r.msg : `${r.msg}（影响 ${n} 条）`);
            bootstrap.Modal.getInstance(document.getElementById('sinkModal')).hide();
            if (mode === 'batch' && typeof clearSelection === 'function') clearSelection();
            loadAlerts();
            loadStats();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- 事件绑定（处置范围 radio 切换） -----
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('input[name="sinkModeRadio"]').forEach(el => {
        el.addEventListener('change', syncRuleWrapperByMode);
    });
});

// 暴露到全局（供 HTML onclick 调用）
window.showSink = showSink;
window.showAggregateSink = showAggregateSink;
window.showIpSink = showIpSink;
window.showBatchSink = showBatchSink;
window.confirmSink = confirmSink;
window.onVerdictChange = onVerdictChange;
window.onReasonCodeChange = onReasonCodeChange;
