// heartdesk カード: 監査ログ（集約）(vendor-audit-log)
// 依存: shared.js の escHtml / getAppBase / formatCount、card_runtime.js の CardRegistry。

(function() {
	'use strict';

	var CARD_ID = 'vendor-audit-log';

	function getState(el) {
		if (!el._vialState) {
			el._vialState = {
				params: { tenant: '', agent_id: '', user: '', event: '', from: '', to: '', limit: 100, offset: 0 },
				tenants: []
			};
		}
		return el._vialState;
	}

	function buildApiUrl(params) {
		var base = (typeof getAppBase === 'function' ? getAppBase() : '/monitor') + '/?api=vendor_audit_log';
		var parts = [base];
		if (params.tenant)   parts.push('tenant='    + encodeURIComponent(params.tenant));
		if (params.agent_id) parts.push('agent_id='  + encodeURIComponent(params.agent_id));
		if (params.user)     parts.push('user='      + encodeURIComponent(params.user));
		if (params.event)    parts.push('event='     + encodeURIComponent(params.event));
		if (params.from)     parts.push('from='      + encodeURIComponent(params.from));
		if (params.to)       parts.push('to='        + encodeURIComponent(params.to));
		parts.push('limit='  + (params.limit  || 100));
		parts.push('offset=' + (params.offset || 0));
		return parts.join('&');
	}

	// C9-C4: ローカル doFetch を fetchData に改名し、エラー class を section-error に統一。
	// クエリパラメータ付き API のため loadJsonCard ではなく専用 fetch を維持する。
	function fetchData(el, params) {
		el.innerHTML = '<p class="section-loading">読み込み中...</p>';
		fetch(buildApiUrl(params))
			.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
			.then(function(data) { renderVendorAuditLog(el, data); })
			.catch(function(e) { el.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + esc(e.message) + '</p>'; });
	}

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function renderVendorAuditLog(el, data) {
		var st = getState(el);
		if (data && data.tenants && data.tenants.length) st.tenants = data.tenants;

		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}

		var total  = (data && data.total)  || 0;
		var logs   = (data && data.logs)   || [];
		var limit  = (data && data.limit)  || st.params.limit;
		var offset = (data && data.offset != null ? data.offset : st.params.offset);

		var totalEl = document.getElementById(CARD_ID + '-total');
		if (totalEl) totalEl.textContent = (typeof formatCount === 'function' ? formatCount(total) : total) + '件';

		el.innerHTML = buildFilterForm(st) + buildTable(logs) + buildPager(total, limit, offset);
		setupEvents(el, st, total, limit, offset);
	}

	function buildFilterForm(st) {
		var p = st.params;
		var tenantOpts = '<option value="">（全テナント）</option>';
		for (var i = 0; i < st.tenants.length; i++) {
			var t = st.tenants[i];
			tenantOpts += '<option value="' + esc(t) + '"' + (p.tenant === t ? ' selected' : '') + '>' + esc(t) + '</option>';
		}
		var limitOpts = [20, 50, 100, 200, 500].map(function(n) {
			return '<option value="' + n + '"' + (p.limit === n ? ' selected' : '') + '>' + n + '件</option>';
		}).join('');
		return '<div class="vial-filter">'
			+ '<div class="vial-filter-row">'
			+ '<div class="vial-fi"><label>テナント</label><select id="vial-tenant" class="filter-select">' + tenantOpts + '</select></div>'
			+ '<div class="vial-fi"><label>Agent ID</label><input id="vial-agent" type="text" class="filter-input" value="' + esc(p.agent_id || '') + '" placeholder="alpha-vps-host1"></div>'
			+ '<div class="vial-fi"><label>ユーザー</label><input id="vial-user" type="text" class="filter-input" value="' + esc(p.user || '') + '" placeholder="admin"></div>'
			+ '<div class="vial-fi"><label>イベント</label><input id="vial-event" type="text" class="filter-input" value="' + esc(p.event || '') + '" placeholder="LOGIN"></div>'
			+ '</div>'
			+ '<div class="vial-filter-row">'
			+ '<div class="vial-fi"><label>開始（RFC3339）</label><input id="vial-from" type="text" class="filter-input" value="' + esc(p.from || '') + '" placeholder="2026-01-01T00:00:00+09:00"></div>'
			+ '<div class="vial-fi"><label>終了（RFC3339）</label><input id="vial-to" type="text" class="filter-input" value="' + esc(p.to || '') + '" placeholder="2026-12-31T23:59:59+09:00"></div>'
			+ '<div class="vial-fi"><label>表示件数</label><select id="vial-limit" class="filter-select">' + limitOpts + '</select></div>'
			+ '<div class="vial-fi vial-filter-actions">'
			+ '<button type="button" id="vial-search-btn" class="btn-primary btn-sm">絞り込み</button>'
			+ '<button type="button" id="vial-clear-btn" class="btn-secondary btn-sm">クリア</button>'
			+ '</div>'
			+ '</div>'
			+ '</div>';
	}

	function buildTable(logs) {
		if (!logs.length) return '<p class="empty">該当するログがありません</p>';
		var rows = '';
		for (var i = 0; i < logs.length; i++) {
			var r = logs[i];
			rows += '<tr class="vial-row" data-details="' + esc(r.details || '') + '">'
				+ '<td class="mono vial-ts">' + esc(r.ts) + '</td>'
				+ '<td class="mono">' + esc(r.tenant_id) + '</td>'
				+ '<td class="mono">' + esc(r.agent_id) + '</td>'
				+ '<td class="mono">' + esc(r.user || '-') + '</td>'
				+ '<td class="mono">' + esc(r.event_type || '-') + '</td>'
				+ '<td><span class="vial-result vial-result-' + esc(r.result || '') + '">' + esc(r.result || '-') + '</span></td>'
				+ '<td class="mono">' + esc(r.ip_address || '-') + '</td>'
				+ '<td><button type="button" class="btn-secondary btn-xs vial-detail-btn">詳細</button></td>'
				+ '</tr>';
		}
		return '<div class="table-scroll"><table class="log-table vial-table">'
			+ '<thead><tr><th>時刻</th><th>テナント</th><th>Agent</th><th>ユーザー</th><th>イベント</th><th>結果</th><th>IP</th><th></th></tr></thead>'
			+ '<tbody>' + rows + '</tbody>'
			+ '</table></div>';
	}

	function buildPager(total, limit, offset) {
		if (total <= limit) return '';
		var page  = Math.floor(offset / limit) + 1;
		var pages = Math.ceil(total / limit);
		var cnt   = typeof formatCount === 'function' ? formatCount(total) : total;
		return '<div class="vial-pager">'
			+ '<button type="button" id="vial-prev-btn" class="btn-secondary btn-sm"' + (offset > 0 ? '' : ' disabled') + '>前へ</button>'
			+ '<span class="vial-pager-info">' + page + ' / ' + pages + ' ページ（' + cnt + '件）</span>'
			+ '<button type="button" id="vial-next-btn" class="btn-secondary btn-sm"' + (offset + limit < total ? '' : ' disabled') + '>次へ</button>'
			+ '</div>';
	}

	function val(el, id) { var e = el.querySelector('#' + id); return e ? e.value : ''; }

	function setupEvents(el, st, total, limit, offset) {
		var searchBtn = el.querySelector('#vial-search-btn');
		if (searchBtn) {
			searchBtn.addEventListener('click', function() {
				st.params = {
					tenant:   val(el, 'vial-tenant'),
					agent_id: val(el, 'vial-agent'),
					user:     val(el, 'vial-user'),
					event:    val(el, 'vial-event'),
					from:     val(el, 'vial-from'),
					to:       val(el, 'vial-to'),
					limit:    parseInt(val(el, 'vial-limit'), 10) || 100,
					offset:   0
				};
				fetchData(el, st.params);
			});
		}

		var clearBtn = el.querySelector('#vial-clear-btn');
		if (clearBtn) {
			clearBtn.addEventListener('click', function() {
				st.params = { tenant: '', agent_id: '', user: '', event: '', from: '', to: '', limit: 100, offset: 0 };
				fetchData(el, st.params);
			});
		}

		var prevBtn = el.querySelector('#vial-prev-btn');
		if (prevBtn) {
			prevBtn.addEventListener('click', function() {
				st.params.offset = Math.max(0, offset - limit);
				fetchData(el, st.params);
			});
		}

		var nextBtn = el.querySelector('#vial-next-btn');
		if (nextBtn) {
			nextBtn.addEventListener('click', function() {
				if (offset + limit < total) {
					st.params.offset = offset + limit;
					fetchData(el, st.params);
				}
			});
		}

		el.querySelectorAll('.vial-detail-btn').forEach(function(btn) {
			btn.addEventListener('click', function() {
				var row = btn.closest('tr');
				if (!row) return;
				var next = row.nextElementSibling;
				if (next && next.classList.contains('vial-detail-row')) {
					next.remove();
					btn.textContent = '詳細';
					return;
				}
				var raw = row.dataset.details || '';
				var pretty = '';
				try { pretty = JSON.stringify(JSON.parse(raw), null, 2); } catch(e) { pretty = raw; }
				var dr = document.createElement('tr');
				dr.className = 'vial-detail-row';
				dr.innerHTML = '<td colspan="8"><pre class="vial-detail-pre">' + esc(pretty) + '</pre></td>';
				row.parentNode.insertBefore(dr, row.nextSibling);
				btn.textContent = '閉じる';
			});
		});
	}

	CardRegistry.register('VendorAuditLog', {
		cardKey:    'VENDOR_AUDIT_LOG',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_audit_log',
		wrap: function(el, data) {
			renderVendorAuditLog(el, data || {});
		},
		screens: 'monitor'
	});
})();
