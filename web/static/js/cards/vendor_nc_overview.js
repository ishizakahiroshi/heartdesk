// heartdesk カード: Nextcloud 運用監視 (vendor-nc-overview)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-nc-overview';

	// ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	// ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_nc_overview', render, { includeAgent: false });
	}

	function diskPctNum(pct) {
		if (!pct) return 0;
		return parseInt(pct, 10) || 0;
	}

	function errClass(n) {
		if (n > 50) return 'vnc-cell-danger';
		if (n > 10) return 'vnc-cell-warn';
		return '';
	}

	function warnClass(n) {
		if (n > 100) return 'vnc-cell-warn';
		return '';
	}

	function diskClass(pct) {
		var n = diskPctNum(pct);
		if (n > 90) return 'vnc-cell-danger';
		if (n > 80) return 'vnc-cell-warn';
		return '';
	}

	function render(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}
		var rows = (data && data.rows) || [];
		if (!rows.length) {
			el.innerHTML = '<p class="empty">Nextcloud 対応 Agent が見つかりません</p>';
			return;
		}

		var tbody = '';
		for (var i = 0; i < rows.length; i++) {
			var r = rows[i];
			var ec = errClass(r.errors_24h);
			var wc = warnClass(r.warnings_24h);
			var dc = diskClass(r.disk_pct);
			var nameHtml = r.tenant_name ? '<br><span class="vtn-tenant-name">' + esc(r.tenant_name) + '</span>' : '';
			tbody += '<tr>'
				+ '<td class="mono">' + esc(r.tenant_id) + nameHtml + '</td>'
				+ '<td>' + esc(r.agent_label || r.agent_id) + '</td>'
				+ '<td class="' + ec + '">' + r.errors_24h + '</td>'
				+ '<td class="' + wc + '">' + r.warnings_24h + '</td>'
				+ '<td class="' + dc + '">' + esc(r.disk_pct || '-') + '</td>'
				+ '</tr>';
		}

		el.innerHTML = '<div class="table-scroll">'
			+ '<table class="log-table vnc-table">'
			+ '<thead><tr>'
			+ '<th>テナント</th>'
			+ '<th>Agent</th>'
			+ '<th>エラー (24h)</th>'
			+ '<th>警告 (24h)</th>'
			+ '<th>Disk</th>'
			+ '</tr></thead>'
			+ '<tbody>' + tbody + '</tbody>'
			+ '</table>'
			+ '</div>'
			+ '<p class="vnc-legend">エラー: <span class="vnc-cell-warn">10超</span> / <span class="vnc-cell-danger">50超</span>　警告: <span class="vnc-cell-warn">100超</span>　Disk: <span class="vnc-cell-warn">80%超</span> / <span class="vnc-cell-danger">90%超</span></p>';
	}

	CardRegistry.register('VendorNcOverview', {
		cardKey:    'VENDOR_NC_OVERVIEW',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_nc_overview',
		wrap: function(el, data) {
			if (data && data.rows) {
				render(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
