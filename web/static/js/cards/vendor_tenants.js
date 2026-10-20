// heartdesk カード: テナント × Agent ビュー (vendor-tenants)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-tenants';

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	// C9-C4: ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_tenants', renderVendorTenants, { includeAgent: false });
	}

	function renderVendorTenants(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}

		var tenants = (data && data.tenants) || [];

		var countEl = document.getElementById(CARD_ID + '-count');
		if (countEl) countEl.textContent = tenants.length + ' テナント';

		if (!tenants.length) {
			el.innerHTML = '<p class="empty">テナントデータがありません</p>';
			return;
		}

		var html = '<div class="table-scroll"><table class="log-table vtn-table">';
		html += '<thead><tr><th>テナント</th>';

		// 全 Agent ID の集合（列ヘッダー用）
		var allAgents = [];
		var agentSet = {};
		for (var i = 0; i < tenants.length; i++) {
			var agents = tenants[i].agents || [];
			for (var j = 0; j < agents.length; j++) {
				if (!agentSet[agents[j].agent_id]) {
					agentSet[agents[j].agent_id] = true;
					allAgents.push(agents[j].agent_id);
				}
			}
		}
		for (var k = 0; k < allAgents.length; k++) {
			html += '<th class="mono vtn-agent-col">' + esc(allAgents[k]) + '</th>';
		}
		html += '</tr></thead><tbody>';

		for (var ti = 0; ti < tenants.length; ti++) {
			var tenant = tenants[ti];
			var nameHtml = tenant.name ? '<br><span class="vtn-tenant-name">' + esc(tenant.name) + '</span>' : '';
		html += '<tr><td class="mono"><strong>' + esc(tenant.id) + '</strong>' + nameHtml + '</td>';

			// agent_id → cell のマップを作る
			var agentCells = {};
			var tAgents = tenant.agents || [];
			for (var ai = 0; ai < tAgents.length; ai++) {
				agentCells[tAgents[ai].agent_id] = tAgents[ai];
			}

			for (var ki = 0; ki < allAgents.length; ki++) {
				var cell = agentCells[allAgents[ki]];
				if (!cell) {
					html += '<td class="vtn-cell vtn-na">—</td>';
				} else {
					var statusClass = 'vtn-status-' + (cell.status || 'unknown');
					var tooltip = cell.label || cell.agent_id;
					if (cell.received_at) {
						tooltip += '\n最終: ' + cell.received_at + ' (' + cell.minutes_ago + '分前)';
					}
					html += '<td class="vtn-cell ' + statusClass + '" title="' + esc(tooltip) + '">'
						+ '<span class="vtn-dot"></span>'
						+ '</td>';
				}
			}
			html += '</tr>';
		}
		html += '</tbody></table></div>';

		// 凡例
		html += '<div class="vtn-legend">'
			+ '<span class="vtn-legend-item"><span class="vtn-dot vtn-status-ok"></span> 5分以内</span>'
			+ '<span class="vtn-legend-item"><span class="vtn-dot vtn-status-warn"></span> 5〜30分</span>'
			+ '<span class="vtn-legend-item"><span class="vtn-dot vtn-status-alert"></span> 30分以上</span>'
			+ '<span class="vtn-legend-item"><span class="vtn-dot vtn-status-unknown"></span> 未受信</span>'
			+ '</div>';

		el.innerHTML = html;
	}

	CardRegistry.register('VendorTenants', {
		cardKey:    'VENDOR_TENANTS',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_tenants',
		wrap: function(el, data) {
			if (data && data.tenants) {
				renderVendorTenants(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
