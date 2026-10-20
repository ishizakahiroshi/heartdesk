// SAB カード: Agent 一覧 (vendor-agents)
// 依存: shared.js の escHtml / getAppBase / formatCount、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-agents';
	var sortKey = 'agent_id';
	var sortAsc = true;

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	// C9-C4: ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_agents', renderVendorAgents, { includeAgent: false });
	}

	function renderVendorAgents(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}

		var agents = (data && data.agents) || [];

		var countEl = document.getElementById(CARD_ID + '-count');
		if (countEl) countEl.textContent = agents.length + ' エージェント';

		if (!agents.length) {
			el.innerHTML = '<p class="empty">Agent データがありません</p>';
			return;
		}

		// ソート
		agents = agents.slice().sort(function(a, b) {
			var va = a[sortKey] || '';
			var vb = b[sortKey] || '';
			if (sortKey === 'minutes_ago') {
				va = a.has_data ? a.minutes_ago : 999999;
				vb = b.has_data ? b.minutes_ago : 999999;
				return sortAsc ? va - vb : vb - va;
			}
			if (va < vb) return sortAsc ? -1 : 1;
			if (va > vb) return sortAsc ? 1 : -1;
			return 0;
		});

		var cols = [
			{key: 'agent_id', label: 'Agent ID'},
			{key: 'tenant_id', label: 'テナント'},
			{key: 'label', label: 'ラベル'},
			{key: 'agent_type', label: 'タイプ'},
			{key: 'minutes_ago', label: '最終報告'},
			{key: 'status', label: '状態'},
		];

		var html = '<div class="table-scroll"><table class="log-table vag-table"><thead><tr>';
		for (var ci = 0; ci < cols.length; ci++) {
			var col = cols[ci];
			var indicator = '';
			if (sortKey === col.key) indicator = sortAsc ? ' ▲' : ' ▼';
			html += '<th class="vag-sortable" data-key="' + esc(col.key) + '">' + esc(col.label) + indicator + '</th>';
		}
		html += '</tr></thead><tbody>';

		for (var i = 0; i < agents.length; i++) {
			var a = agents[i];
			var statusClass = 'vag-status-' + (a.status || 'unknown');
			var lastReport = a.has_data
				? esc(a.received_at) + ' (' + a.minutes_ago + '分前)'
				: '—';
			html += '<tr>'
				+ '<td class="mono">' + esc(a.agent_id || '') + '</td>'
				+ '<td class="mono">' + esc(a.tenant_id || '') + '</td>'
				+ '<td>' + esc(a.label || '') + '</td>'
				+ '<td class="mono">' + esc(a.agent_type || '') + '</td>'
				+ '<td class="mono">' + lastReport + '</td>'
				+ '<td><span class="vag-status ' + statusClass + '">' + esc(a.status || 'unknown') + '</span></td>'
				+ '</tr>';
		}
		html += '</tbody></table></div>';
		el.innerHTML = html;

		// ソートヘッダーのイベント
		el.querySelectorAll('.vag-sortable').forEach(function(th) {
			th.style.cursor = 'pointer';
			th.addEventListener('click', function() {
				var key = th.dataset.key;
				if (sortKey === key) {
					sortAsc = !sortAsc;
				} else {
					sortKey = key;
					sortAsc = true;
				}
				renderVendorAgents(el, data);
			});
		});
	}

	CardRegistry.register('VendorAgents', {
		cardKey:    'VENDOR_AGENTS',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_agents',
		wrap: function(el, data) {
			if (data && data.agents) {
				renderVendorAgents(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
