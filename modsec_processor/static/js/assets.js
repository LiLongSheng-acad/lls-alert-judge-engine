// ============================================================
// 资产管理模块
// ============================================================

let assetPage = 1, assetSize = 20, assetTotal = 0;

function buildAssetsPage() {
    const admin = getCurrentUser() === 'admin';
    return `
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="mb-0">资产列表</h5>
            <div>
                ${admin ? `<button class="btn btn-primary btn-sm" onclick="showCreateAsset()">➕ 新增资产</button>` : ''}
                <button class="btn btn-outline-secondary btn-sm" onclick="loadAssets()">🔄 刷新</button>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover table-sm">
                <thead><tr>
                    <th>资产标识</th><th>名称</th><th>基础权重</th><th>当前权重</th>
                    <th>负责人</th><th>备注</th><th>状态</th>
                    ${admin ? '<th style="width:160px;">操作</th>' : ''}
                </tr></thead>
                <tbody id="assetTableBody"><tr><td colspan="${admin ? 8 : 7}" class="text-center text-muted">加载中...</td></tr></tbody>
            </table>
        </div>
        <div class="d-flex justify-content-between align-items-center mt-3">
            <span class="text-muted small" id="assetPaginationInfo">共 0 条</span>
            <nav><ul class="pagination pagination-sm mb-0" id="assetPaginationControls">
                <li class="page-item"><a class="page-link" href="#" onclick="changeAssetPage(-1)">上一页</a></li>
                <li class="page-item"><a class="page-link" href="#" onclick="changeAssetPage(1)">下一页</a></li>
            </ul></nav>
        </div>
    `;
}

async function loadAssets() {
    const pane = document.getElementById('assets-pane');
    if (!pane) return;
    if (!pane.querySelector('table')) {
        pane.innerHTML = buildAssetsPage();
    }
    const tbody = document.getElementById('assetTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">加载中...</td></tr>';
    try {
        const r = await apiCall('/assets', { action: 'list', page: assetPage, size: assetSize });
        if (r.code !== 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">加载失败: ${r.msg}</td></tr>`;
            return;
        }
        const items = r.data.items || [];
        assetTotal = r.data.total || 0;
        const info = document.getElementById('assetPaginationInfo');
        if (info) info.textContent = `共 ${assetTotal} 条，第 ${assetPage} 页，每页 ${assetSize} 条`;
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">暂无资产</td></tr>';
            return;
        }
        const admin = getCurrentUser() === 'admin';
        tbody.innerHTML = items.map(asset => {
            const isTempActive = asset._is_temp_active;
            const currentWeight = asset._current_weight || asset.base_weight;
            let actions = '';
            if (admin) {
                actions = `
                    <button class="btn btn-outline-primary btn-sm" onclick="editAsset('${asset.id}')">编辑</button>
                    <button class="btn btn-outline-danger btn-sm" onclick="deleteAsset('${asset.id}')">删除</button>
                `;
            }
            return `<tr>
                <td><code>${asset.identifier || '-'}</code></td>
                <td>${asset.name || '-'}</td>
                <td>${asset.base_weight || 1.0}</td>
                <td>${isTempActive ? `<span class="fw-bold text-danger">${currentWeight} 🔥</span>` : currentWeight}${isTempActive ? '<span class="temp-badge">临时</span>' : ''}</td>
                <td>${asset.owner || '-'}</td>
                <td>${asset.remark || '-'}</td>
                <td>${asset.enabled !== false ? '<span class="badge bg-success">启用</span>' : '<span class="badge bg-secondary">禁用</span>'}</td>
                ${admin ? `<td>${actions}</td>` : ''}
            </tr>`;
        }).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">网络错误: ${e.message}</td></tr>`;
    }
}

function changeAssetPage(delta) {
    const newPage = assetPage + delta;
    if (newPage < 1) return;
    assetPage = newPage;
    loadAssets();
}

function showCreateAsset() {
    if (getCurrentUser() !== 'admin') { alert('只有管理员可以管理资产'); return; }
    document.getElementById('assetModalTitle').textContent = '新增资产';
    document.getElementById('editAssetId').value = '';
    ['assetIdentifier', 'assetName', 'assetOwner', 'assetRemark'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('assetBaseWeight').value = '1.0';
    document.getElementById('assetTempWeight').value = '';
    document.getElementById('assetTempExpireAt').value = '';
    document.getElementById('assetEnabled').value = 'true';
    new bootstrap.Modal(document.getElementById('assetModal')).show();
}

async function editAsset(assetId) {
    if (getCurrentUser() !== 'admin') { alert('只有管理员可以管理资产'); return; }
    try {
        const r = await apiCall('/assets', { action: 'detail', asset_id: assetId });
        if (r.code !== 0) { alert(r.msg || '加载资产失败'); return; }
        const asset = r.data;
        document.getElementById('assetModalTitle').textContent = '编辑资产';
        document.getElementById('editAssetId').value = assetId;
        document.getElementById('assetIdentifier').value = asset.identifier || '';
        document.getElementById('assetName').value = asset.name || '';
        document.getElementById('assetBaseWeight').value = asset.base_weight || 1.0;
        document.getElementById('assetTempWeight').value = asset.temp_weight !== null ? asset.temp_weight : '';
        document.getElementById('assetTempExpireAt').value = asset.temp_expire_at ? asset.temp_expire_at.slice(0, 16) : '';
        document.getElementById('assetOwner').value = asset.owner || '';
        document.getElementById('assetRemark').value = asset.remark || '';
        document.getElementById('assetEnabled').value = asset.enabled !== false ? 'true' : 'false';
        new bootstrap.Modal(document.getElementById('assetModal')).show();
    } catch (e) { alert('网络错误: ' + e.message); }
}

async function confirmAssetSave() {
    if (getCurrentUser() !== 'admin') { alert('只有管理员可以管理资产'); return; }
    const identifier = document.getElementById('assetIdentifier')?.value.trim() || '';
    const name = document.getElementById('assetName')?.value.trim() || '';
    const base_weight = parseFloat(document.getElementById('assetBaseWeight')?.value || '0');
    const tempWeightInput = document.getElementById('assetTempWeight')?.value.trim() || '';
    const temp_weight = tempWeightInput ? parseFloat(tempWeightInput) : null;
    const temp_expire_at = document.getElementById('assetTempExpireAt')?.value || null;
    const owner = document.getElementById('assetOwner')?.value.trim() || null;
    const remark = document.getElementById('assetRemark')?.value.trim() || null;
    const enabled = document.getElementById('assetEnabled')?.value === 'true';
    if (!identifier || !name || isNaN(base_weight)) {
        alert('请完整填写必填字段'); return;
    }
    if (temp_weight && temp_expire_at) {
        const expire = new Date(temp_expire_at);
        if (expire <= new Date()) { alert('过期时间必须是将来的时间'); return; }
    }
    const assetId = document.getElementById('editAssetId')?.value || '';
    const action = assetId ? 'update' : 'create';
    const payload = { action, identifier, name, base_weight, temp_weight, temp_expire_at, owner, remark, enabled };
    if (action === 'update') payload.asset_id = assetId;
    try {
        const r = await apiCall('/assets', payload);
        if (r.code === 0) {
            alert(assetId ? '资产更新成功' : '资产创建成功');
            bootstrap.Modal.getInstance(document.getElementById('assetModal')).hide();
            loadAssets();
        } else {
            alert('操作失败: ' + r.msg);
        }
    } catch (e) { alert('网络错误: ' + e.message); }
}

async function deleteAsset(assetId) {
    if (getCurrentUser() !== 'admin') { alert('只有管理员可以管理资产'); return; }
    if (!confirm('确定要删除资产 ' + assetId + ' 吗？')) return;
    try {
        const r = await apiCall('/assets', { action: 'delete', asset_id: assetId });
        if (r.code === 0) { alert('删除成功'); loadAssets(); }
        else alert('删除失败: ' + r.msg);
    } catch (e) { alert('网络错误: ' + e.message); }
}

// 暴露到全局
window.loadAssets = loadAssets;
window.showCreateAsset = showCreateAsset;
window.editAsset = editAsset;
window.confirmAssetSave = confirmAssetSave;
window.deleteAsset = deleteAsset;
window.changeAssetPage = changeAssetPage;
