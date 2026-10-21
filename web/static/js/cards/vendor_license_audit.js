// heartdesk カード: ライセンス台帳監査 (vendor-license-audit)
// 依存: shared.js の escHtml / getAppBase / formatCount、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-license-audit';

	function getState(el) {
		if (!el._vlaState) {
			el._vlaState = {
				params: { user: '', action: '', from: '', to: '', limit: 50, offset: 0 }
			};
		}
		return el._vlaState;
	}

	function buildApiUrl(params) {
		var base = (typeof getAppBase === 'function' ? getAppBase() : '/monitor') + '/?api=vendor_license_audit';
		var parts = [base];
		if (params.user)   parts.push('user='   + encodeURIComponent(params.user));
		if (params.action) parts.push('action=' + encodeURIComponent(params.action));
		if (params.from)   parts.push('from='   + encodeURIComponent(params.from));
		if (params.to)     parts.push('to='     + encodeURIComponent(params.to));
		parts.push('limit='  + (params.limit  || 50));
		parts.push('offset=' + (params.offset || 0));
		return parts.join('&');
	}

	// ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	// ローカル doFetch を fetchData に改名し、エラー class を section-error に統一。
	// クエリパラメータ付き API のため loadJsonCard ではなく専用 fetch を維持する。
	function fetchData(el, params) {
		el.innerHTML = '<p class="section-loading">読み込み中...</p>';
		fetch(buildApiUrl(params))
			.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
			.then(function(data) { renderVendorLicenseAudit(el, data); })
			.catch(function(e) { el.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + esc(e.message) + '</p>'; });
	}

	function renderVendorLicenseAudit(el, data) {
		var st = getState(el);
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}

		var total   = (data && data.total)  || 0;
		var entries = (data && data.entries) || [];
		var limit   = (data && data.limit)  || st.params.limit;
		var offset  = (data && data.offset != null ? data.offset : st.params.offset);

		var totalEl = document.getElementById(CARD_ID + '-total');
		if (totalEl) totalEl.textContent = (typeof formatCount === 'function' ? formatCount(total) : total) + '件';

		el.innerHTML = buildFilterForm(st) + buildTable(entries) + buildPager(total, limit, offset);
		setupEvents(el, st, total, limit, offset);
	}

	function buildFilterForm(st) {
		var p = st.params;
		var limitOpts = [20, 50, 100, 200].map(function(n) {
			return '<option value="' + n + '"' + (p.limit === n ? ' selected' : '') + '>' + n + '件</option>';
		}).join('');
		var actionOpts = ['', 'issue', 'revoke'].map(function(a) {
			return '<option value="' + a + '"' + (p.action === a ? ' selected' : '') + '>' + (a || '（全操作）') + '</option>';
		}).join('');
		return '<div class="vial-filter">'
			+ '<div class="vial-filter-row">'
			+ '<div class="vial-fi"><label>操作者</label><input id="vla-user" type="text" class="filter-input" value="' + esc(p.user || '') + '" placeholder="admin"></div>'
			+ '<div class="vial-fi"><label>操作種別</label><select id="vla-action" class="filter-select">' + actionOpts + '</select></div>'
			+ '<div class="vial-fi"><label>開始（RFC3339）</label><input id="vla-from" type="text" class="filter-input" value="' + esc(p.from || '') + '" placeholder="YYYY-MM-DDT00:00:00+09:00"></div>'
			+ '<div class="vial-fi"><label>終了（RFC3339）</label><input id="vla-to" type="text" class="filter-input" value="' + esc(p.to || '') + '" placeholder="YYYY-MM-DDT23:59:59+09:00"></div>'
			+ '<div class="vial-fi"><label>表示件数</label><select id="vla-limit" class="filter-select">' + limitOpts + '</select></div>'
			+ '<div class="vial-fi vial-filter-actions">'
			+ '<button type="button" id="vla-search-btn" class="btn-primary btn-sm">絞り込み</button>'
			+ '<button type="button" id="vla-clear-btn" class="btn-secondary btn-sm">クリア</button>'
			+ '</div>'
			+ '</div>'
			+ '</div>';
	}

	function buildTable(entries) {
		if (!entries.length) return '<p class="empty">該当するエントリがありません</p>';
		var rows = '';
		for (var i = 0; i < entries.length; i++) {
			var e = entries[i];
			var actionClass = e.action === 'revoke' ? 'vdb-action-revoke' : 'vdb-action-issue';
			rows += '<tr>'
				+ '<td class="mono">' + esc(e.ts || '') + '</td>'
				+ '<td><span class="' + actionClass + '">' + esc(e.action || '') + '</span></td>'
				+ '<td class="mono">' + esc(e.tenant_id || '') + '</td>'
				+ '<td class="mono">' + esc(e.agent_id || '') + '</td>'
				+ '<td class="mono">' + esc(e.kid || '') + '</td>'
				+ '<td class="mono">' + esc(e.key_prefix || '') + '</td>'
				+ '<td>' + esc(e.actor || '-') + '</td>'
				+ '<td>' + esc(e.reason || '') + '</td>'
				+ '</tr>';
		}
		return '<div class="table-scroll"><table class="log-table vla-table">'
			+ '<thead><tr><th>日時</th><th>操作</th><th>テナント</th><th>Agent</th><th>KID</th><th>キープレフィックス</th><th>操作者</th><th>備考</th></tr></thead>'
			+ '<tbody>' + rows + '</tbody>'
			+ '</table></div>';
	}

	function buildPager(total, limit, offset) {
		if (total <= limit) return '';
		var page  = Math.floor(offset / limit) + 1;
		var pages = Math.ceil(total / limit);
		var cnt   = typeof formatCount === 'function' ? formatCount(total) : total;
		return '<div class="vial-pager">'
			+ '<button type="button" id="vla-prev-btn" class="btn-secondary btn-sm"' + (offset > 0 ? '' : ' disabled') + '>前へ</button>'
			+ '<span class="vial-pager-info">' + page + ' / ' + pages + ' ページ（' + cnt + '件）</span>'
			+ '<button type="button" id="vla-next-btn" class="btn-secondary btn-sm"' + (offset + limit < total ? '' : ' disabled') + '>次へ</button>'
			+ '</div>';
	}

	function val(el, id) { var e = el.querySelector('#' + id); return e ? e.value : ''; }

	function setupEvents(el, st, total, limit, offset) {
		var searchBtn = el.querySelector('#vla-search-btn');
		if (searchBtn) {
			searchBtn.addEventListener('click', function() {
				st.params = {
					user:   val(el, 'vla-user'),
					action: val(el, 'vla-action'),
					from:   val(el, 'vla-from'),
					to:     val(el, 'vla-to'),
					limit:  parseInt(val(el, 'vla-limit'), 10) || 50,
					offset: 0
				};
				fetchData(el, st.params);
			});
		}

		var clearBtn = el.querySelector('#vla-clear-btn');
		if (clearBtn) {
			clearBtn.addEventListener('click', function() {
				st.params = { user: '', action: '', from: '', to: '', limit: 50, offset: 0 };
				fetchData(el, st.params);
			});
		}

		var prevBtn = el.querySelector('#vla-prev-btn');
		if (prevBtn) {
			prevBtn.addEventListener('click', function() {
				st.params.offset = Math.max(0, offset - limit);
				fetchData(el, st.params);
			});
		}

		var nextBtn = el.querySelector('#vla-next-btn');
		if (nextBtn) {
			nextBtn.addEventListener('click', function() {
				if (offset + limit < total) {
					st.params.offset = offset + limit;
					fetchData(el, st.params);
				}
			});
		}
	}

	CardRegistry.register('VendorLicenseAudit', {
		cardKey:    'VENDOR_LICENSE_AUDIT',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_license_audit',
		wrap: function(el, data) {
			renderVendorLicenseAudit(el, data || {});
		},
		screens: 'monitor'
	});
})();
