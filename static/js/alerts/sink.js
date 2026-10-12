// ============================================================
// 沉底操作模块（统一弹窗）
// ============================================================

// ----- 单条沉底 -----
function showSink(alertId) {
    // 设置隐藏字段
    document.getElementById('sinkAlertId').value = alertId;
    document.getElementById('sinkTarget').value = '';
    document.getElementById('sinkMode').value = 'single';

    // 标题
    document.getElementById('sinkModalTitle').textContent = '沉底操作';

    // 预览信息
    const row = document.querySelector(`button[onclick*="showSink('${alertId}')"]`)?.closest('tr');
    if (row) {
        const cells = row.querySelectorAll('td');
        const srcIp = cells[2]?.textContent || '';
        const uri = cells[4]?.textContent || '';
        const attackType = cells[5]?.textContent || '';
        document.getElementById('sinkAlertPreview').textContent = `${srcIp} | ${uri} | ${attackType}`;
    }

    // 显示单选框（单条沉底模式）
    document.querySelector('.sink-mode-options').style.display = 'block';
    document.getElementById('sinkModeSingle').checked = true;

    // 隐藏同步规则勾选框（单条沉底默认不显示）
    document.getElementById('sinkRuleSyncWrapper').style.display = 'none';

    // 清空原因
    document.getElementById('sinkReason').value = '';

    // 显示弹窗
    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- 聚合沉底 -----
async function showAggregateSink(fingerprint) {
    const parts = fingerprint.split('|');
    const src_ip = parts[0] || '';
    const dest_ip = parts[1] || '';
    const attack_type = parts[2] || '';
    const uri = parts[3] || '';

    if (!src_ip || !attack_type) {
        alert('聚合信息不完整，无法沉底');
        return;
    }

    if (!confirm(`确定要沉底该聚合下的所有告警吗？\n\n源IP: ${src_ip}\n目标IP: ${dest_ip || '(空)'}\n攻击类型: ${attack_type}\nURI: ${uri || '(空)'}`)) return;

    const reason = prompt('请输入沉底原因：') || '聚合沉底';

    try {
        const r = await apiCall('/actions/aggregate_sink', {
            src_ip: src_ip,
            attack_type: attack_type,
            uri: uri,
            reason: reason
        });
        if (r.code === 0) {
            alert(`成功沉底 ${r.data.affected_count} 条告警`);
            loadAlerts();
            loadStats();
        } else {
            alert('沉底失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- IP批量沉底（聚合模式专用，合并弹窗） -----
function showIpSink(src_ip) {
    if (!src_ip || src_ip === '') {
        alert('该聚合条目没有有效的源IP');
        return;
    }

    // 设置隐藏字段
    document.getElementById('sinkAlertId').value = '';
    document.getElementById('sinkTarget').value = src_ip;
    document.getElementById('sinkMode').value = 'ip_temp';

    // 标题
    document.getElementById('sinkModalTitle').textContent = 'IP批量沉底';

    // 预览信息
    document.getElementById('sinkAlertPreview').textContent = `确定要沉底 IP ${src_ip} 的所有告警吗？`;

    // 隐藏单选框（IP批量沉底不需要选择）
    document.querySelector('.sink-mode-options').style.display = 'none';

    // 显示同步规则勾选框（默认勾选）
    document.getElementById('sinkRuleSyncWrapper').style.display = 'block';
    document.getElementById('sinkCreateRule').checked = true;

    // 清空原因
    document.getElementById('sinkReason').value = '';

    // 显示弹窗
    new bootstrap.Modal(document.getElementById('sinkModal')).show();
}

// ----- 确认沉底（统一处理） -----
async function confirmSink() {
    const alertId = document.getElementById('sinkAlertId').value;
    const target = document.getElementById('sinkTarget').value;
    const mode = document.getElementById('sinkMode').value;
    const reason = document.getElementById('sinkReason').value.trim();
    const createRule = document.getElementById('sinkCreateRule')?.checked || false;

    if (!reason) {
        alert('请填写沉底原因');
        return;
    }

    try {
        let endpoint;
        let payload;

        if (mode === 'ip_temp' && target) {
            // IP批量沉底
            endpoint = '/actions/ip_sink';
            payload = {
                src_ip: target,
                reason: reason,
                create_rule: createRule
            };
        } else {
            // 单条沉底（从 radio 取值）
            const radioMode = document.querySelector('input[name="sinkModeRadio"]:checked')?.value || 'single';
            endpoint = '/actions/sink';
            payload = {
                action: 'sink',
                alert_id: alertId,
                mode: radioMode,
                reason: reason,
                create_rule: createRule
            };
        }

        const r = await apiCall(endpoint, payload);
        if (r.code === 0) {
            alert(`沉底成功！影响告警数: ${r.data.affected_count || 0}`);
            bootstrap.Modal.getInstance(document.getElementById('sinkModal')).hide();
            loadAlerts();
            loadStats();
        } else {
            alert('沉底失败: ' + r.msg);
        }
    } catch (e) {
        alert('网络错误: ' + e.message);
    }
}

// ----- 事件绑定（radio 切换） -----
document.addEventListener('DOMContentLoaded', function() {
    // 监听 radio 切换，控制同步规则勾选框的显示
    document.querySelectorAll('input[name="sinkModeRadio"]').forEach(el => {
        el.addEventListener('change', function() {
            const wrapper = document.getElementById('sinkRuleSyncWrapper');
            if (this.value === 'ip_temp' && this.checked) {
                wrapper.style.display = 'block';
            } else {
                wrapper.style.display = 'none';
            }
        });
    });
});

// 暴露到全局（供 HTML onclick 调用）
window.showSink = showSink;
window.showAggregateSink = showAggregateSink;
window.showIpSink = showIpSink;
window.confirmSink = confirmSink;