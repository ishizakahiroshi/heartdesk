// heartdesk カード: Vendor Dashboard (vendor-dashboard)
// 依存: shared.js の escHtml / getAppBase / formatCount、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-dashboard';

	// ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	// ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_dashboard', renderVendorDashboard, { includeAgent: false });
	}

	function renderVendorDashboard(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}

		var html = '<div class="vdb-stats">'
			+ statBox('テナント数', data.tenant_count || 0, '')
			+ statBox('Agent 数', data.agent_count || 0, '')
			+ statBox('有効ライセンス', data.active_license_count || 0, '')
			+ statBox('失効数', data.revoked_count || 0, 'vdb-stat-warn')
			+ statBox('集約ログ（24h）', data.audit_24h_count || 0, '')
			+ '</div>';

		var recent = data.recent_ledger || [];
		if (recent.length) {
			html += '<h3 class="vdb-section-title">最近のライセンス操作（直近 10 件）</h3>';
			html += '<div class="table-scroll"><table class="log-table vdb-table"><thead><tr>'
				+ '<th>日時</th><th>操作</th><th>テナント</th><th>Agent</th><th>操作者</th><th>備考</th>'
				+ '</tr></thead><tbody>';
			for (var i = 0; i < recent.length; i++) {
				var e = recent[i];
				var actionClass = e.action === 'revoke' ? 'vdb-action-revoke' : 'vdb-action-issue';
				html += '<tr>'
					+ '<td class="mono">' + esc(e.ts || '') + '</td>'
					+ '<td><span class="' + actionClass + '">' + esc(e.action || '') + '</span></td>'
					+ '<td class="mono">' + esc(e.tenant_id || '') + '</td>'
					+ '<td class="mono">' + esc(e.agent_id || '') + '</td>'
					+ '<td>' + esc(e.actor || '-') + '</td>'
					+ '<td>' + esc(e.reason || '') + '</td>'
					+ '</tr>';
			}
			html += '</tbody></table></div>';
		}

		el.innerHTML = html;
	}

	function statBox(label, value, cls) {
		var fmt = typeof formatCount === 'function' ? formatCount(value) : value;
		return '<div class="vdb-stat' + (cls ? ' ' + cls : '') + '">'
			+ '<div class="vdb-stat-value">' + esc(String(fmt)) + '</div>'
			+ '<div class="vdb-stat-label">' + esc(label) + '</div>'
			+ '</div>';
	}

	CardRegistry.register('VendorDashboard', {
		cardKey:    'VENDOR_DASHBOARD',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_dashboard',
		wrap: function(el, data) {
			if (data && data.tenant_count != null) {
				renderVendorDashboard(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
