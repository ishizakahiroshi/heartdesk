// SAB カード: サーバー健全性 (vendor-server-health)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-server-health';

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== "undefined" && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? "" : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	// C9-C4: ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_server_health', render, { includeAgent: false });
	}

	function sslClass(row) {
		if (row.ssl_unavailable) return '';
		if (row.ssl_days <= 7)  return 'svc-down';
		if (row.ssl_days <= 30) return 'svc-warn';
		return 'svc-ok';
	}

	function kernelClass(row) {
		return row.kernel_outdated ? 'svc-warn' : 'svc-ok';
	}

	function heldClass(row) {
		return row.held_count > 0 ? 'svc-warn' : 'svc-ok';
	}

	function render(el, data) {
		var rows = data && data.rows ? data.rows : [];
		if (rows.length === 0) {
			el.innerHTML = '<p class="empty">対象エージェントがありません</p>';
			return;
		}

		var html = '<table class="vsh-table">'
			+ '<thead><tr>'
			+ '<th>サーバー</th>'
			+ '<th>SSL残日数</th>'
			+ '<th>カーネル</th>'
			+ '<th>apt hold</th>'
			+ '<th>更新可能</th>'
			+ '</tr></thead><tbody>';

		rows.forEach(function(row) {
			var monitorBase = base();
			var tenantLink = monitorBase + '/?agent=' + encodeURIComponent(row.agent_id);

			// SSL セル（ssl_unavailable = SSL未設定 → 空、has_data なし → "-"）
			var sslCell;
			if (row.ssl_unavailable) {
				sslCell = '';
			} else if (!row.has_data) {
				sslCell = '<span class="vsh-na">-</span>';
			} else {
				sslCell = '<span class="svc-dot ' + sslClass(row) + '"></span> '
					+ esc(String(row.ssl_days)) + ' 日';
			}

			// カーネル セル
			var kernelCell;
			if (!row.has_data || !row.has_updates_data) {
				kernelCell = '<span class="vsh-na">-</span>';
			} else if (row.kernel_outdated) {
				kernelCell = '<span class="svc-dot svc-warn"></span> 更新あり'
					+ (row.kernel_latest ? '<br><small>' + esc(row.kernel_latest) + '</small>' : '');
			} else {
				kernelCell = '<span class="svc-dot svc-ok"></span> 最新';
			}

			// apt hold セル
			var heldCell;
			if (!row.has_data) {
				heldCell = '<span class="vsh-na">-</span>';
			} else if (row.held_count > 0) {
				var pkgTitle = row.held_packages ? row.held_packages.join('\n') : '';
				heldCell = '<span class="svc-dot svc-warn" title="' + esc(pkgTitle) + '"></span> '
					+ esc(String(row.held_count)) + ' 件';
			} else {
				heldCell = '<span class="svc-dot svc-ok"></span> なし';
			}

			// 更新可能数セル
			var updateCell;
			if (!row.has_data) {
				updateCell = '<span class="vsh-na">-</span>';
			} else if (row.update_count > 0) {
				updateCell = '<span class="svc-dot svc-warn"></span> ' + esc(String(row.update_count)) + ' 件';
			} else {
				updateCell = '<span class="svc-dot svc-ok"></span> 0 件';
			}

			html += '<tr>'
				+ '<td><a href="' + esc(tenantLink) + '" class="vsh-agent-link">' + esc(row.label) + '</a></td>'
				+ '<td>' + sslCell + '</td>'
				+ '<td>' + kernelCell + '</td>'
				+ '<td>' + heldCell + '</td>'
				+ '<td>' + updateCell + '</td>'
				+ '</tr>';
		});

		html += '</tbody></table>';
		el.innerHTML = html;
	}

	CardRegistry.register('VendorServerHealth', {
		cardKey:    'VENDOR_SERVER_HEALTH',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_server_health',
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
