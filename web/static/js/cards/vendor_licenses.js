// heartdesk カード: ライセンス管理 (vendor-licenses)
// 依存: shared.js の escHtml / getAppBase / getCsrfToken、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID  = 'vendor-licenses';
	var COUNT_ID = CARD_ID + '-count';

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	function postAction(api, params, cb) {
		var body = new URLSearchParams(params).toString();
		fetch(base() + '/?api=' + api, {
			method: 'POST',
			headers: {
				'X-Requested-With': 'XMLHttpRequest',
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: body
		})
			.then(function(r) { return r.json(); })
			.then(cb)
			.catch(function(e) { cb({ok: false, message: e.message}); });
	}

	// C9-C4: ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_licenses', render, { includeAgent: false });
	}

	function render(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}
		var entries = (data && data.entries) || [];
		var countEl = document.getElementById(COUNT_ID);
		if (countEl) countEl.textContent = entries.length + ' 件';

		var activeTab = el._vlmTab || 'list';
		var html = buildTabs(activeTab) + '<div class="vlm-tab-body">';
		if (activeTab === 'list')   html += buildListTab(entries);
		if (activeTab === 'issue')  html += buildIssueTab();
		if (activeTab === 'revoke') html += buildRevokeTab(entries);
		html += '</div>';
		el.innerHTML = html;
		setupEvents(el, data, entries);
	}

	function buildTabs(active) {
		var tabs = [
			{id: 'list',   label: '一覧'},
			{id: 'issue',  label: '新規発行'},
			{id: 'revoke', label: '失効'}
		];
		var html = '<div class="vlm-tabs">';
		for (var i = 0; i < tabs.length; i++) {
			var t = tabs[i];
			html += '<button type="button" class="vlm-tab' + (active === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>';
		}
		return html + '</div>';
	}

	function buildListTab(entries) {
		if (!entries.length) return '<p class="empty">台帳エントリがありません</p>';
		var rows = '';
		for (var i = 0; i < entries.length; i++) {
			var e = entries[i];
			var cls = e.action === 'revoke' ? 'vdb-action-revoke' : (e.action === 'offline_issue' ? 'vlm-action-offline' : 'vdb-action-issue');
			rows += '<tr>'
				+ '<td class="mono">' + esc(e.ts) + '</td>'
				+ '<td><span class="' + cls + '">' + esc(e.action) + '</span></td>'
				+ '<td class="mono">' + esc(e.tenant_id) + '</td>'
				+ '<td class="mono">' + esc(e.agent_id) + '</td>'
				+ '<td class="mono">' + esc(e.key_prefix || '') + '</td>'
				+ '<td>' + esc(e.actor || '-') + '</td>'
				+ '<td>' + esc(e.reason || '') + '</td>'
				+ '</tr>';
		}
		return '<div class="table-scroll"><table class="log-table vlm-table">'
			+ '<thead><tr><th>日時</th><th>操作</th><th>テナント</th><th>Agent</th><th>キープレフィックス</th><th>操作者</th><th>備考</th></tr></thead>'
			+ '<tbody>' + rows + '</tbody>'
			+ '</table></div>';
	}

	function buildIssueTab() {
		return '<div class="vlm-form">'
			+ '<div class="vlm-form-row">'
			+ '<label>Agent ID</label>'
			+ '<input id="vlm-issue-agent" type="text" class="filter-input" placeholder="例: alpha-vps-host1">'
			+ '</div>'
			+ '<div class="vlm-form-actions">'
			+ '<button type="button" id="vlm-issue-btn" class="btn-primary btn-sm">発行</button>'
			+ '</div>'
			+ '<div id="vlm-issue-result"></div>'
			+ '</div>';
	}

	function buildRevokeTab(entries) {
		// 発行済み Agent リストをセレクトに
		var agentSet = {};
		for (var i = 0; i < entries.length; i++) {
			if (entries[i].action === 'issue' || entries[i].action === 'offline_issue') {
				agentSet[entries[i].agent_id] = true;
			}
		}
		var agentList = Object.keys(agentSet).sort();
		var opts = '<option value="">Agent を選択...</option>';
		for (var j = 0; j < agentList.length; j++) {
			opts += '<option value="' + esc(agentList[j]) + '">' + esc(agentList[j]) + '</option>';
		}
		return '<div class="vlm-form">'
			+ '<div class="vlm-form-row">'
			+ '<label>Agent ID</label>'
			+ '<select id="vlm-revoke-agent" class="filter-select">' + opts + '</select>'
			+ '</div>'
			+ '<div class="vlm-form-row">'
			+ '<label>失効理由</label>'
			+ '<input id="vlm-revoke-reason" type="text" class="filter-input" placeholder="任意">'
			+ '</div>'
			+ '<div class="vlm-form-actions">'
			+ '<button type="button" id="vlm-revoke-btn" class="btn-secondary btn-sm vlm-btn-revoke">失効実行</button>'
			+ '</div>'
			+ '<div id="vlm-revoke-result"></div>'
			+ '</div>';
	}

	function setupEvents(el, data, entries) {
		// タブ切替
		el.querySelectorAll('.vlm-tab').forEach(function(btn) {
			btn.addEventListener('click', function() {
				el._vlmTab = btn.dataset.tab;
				render(el, data);
			});
		});

		// 発行ボタン
		var issueBtn = el.querySelector('#vlm-issue-btn');
		if (issueBtn) {
			issueBtn.addEventListener('click', function() {
				var agentEl = el.querySelector('#vlm-issue-agent');
				var agentID = agentEl ? agentEl.value.trim() : '';
				if (!agentID) { showResult(el, '#vlm-issue-result', false, 'agent_id を入力してください'); return; }
				issueBtn.disabled = true;
				postAction('vendor_license_issue', {agent_id: agentID}, function(res) {
					issueBtn.disabled = false;
					if (res.ok) {
						showIssueKey(el, res);
						// リスト更新
						fetch(base() + '/?api=vendor_licenses')
							.then(function(r) { return r.json(); })
							.then(function(d) { data = d; entries = d.entries || []; });
					} else {
						showResult(el, '#vlm-issue-result', false, res.message || '発行に失敗しました');
					}
				});
			});
		}

		// 失効ボタン
		var revokeBtn = el.querySelector('#vlm-revoke-btn');
		if (revokeBtn) {
			revokeBtn.addEventListener('click', function() {
				var agentEl  = el.querySelector('#vlm-revoke-agent');
				var reasonEl = el.querySelector('#vlm-revoke-reason');
				var agentID  = agentEl  ? agentEl.value.trim()  : '';
				var reason   = reasonEl ? reasonEl.value.trim() : '';
				if (!agentID) { showResult(el, '#vlm-revoke-result', false, 'Agent を選択してください'); return; }
				confirmRevoke(agentID).then(function(ok) {
					if (!ok) return;
					revokeBtn.disabled = true;
					postAction('vendor_license_revoke', {agent_id: agentID, reason: reason}, function(res) {
						revokeBtn.disabled = false;
						showResult(el, '#vlm-revoke-result', res.ok, res.message || (res.ok ? '失効しました' : '失効に失敗しました'));
						if (res.ok) { load(el); }
					});
				});
			});
		}
	}

	function confirmRevoke(agentID) {
		var msg = agentID + ' を失効させます。よろしいですか？';
		if (typeof window.confirmModal === 'function') return window.confirmModal(msg);
		return Promise.resolve(confirm(msg));
	}

	function showResult(el, selector, ok, msg) {
		var r = el.querySelector(selector);
		if (!r) return;
		r.innerHTML = '<p class="' + (ok ? 'vlm-result-ok' : 'section-error') + '">' + esc(msg) + '</p>';
	}

	function showIssueKey(el, res) {
		var r = el.querySelector('#vlm-issue-result');
		if (!r) return;
		r.innerHTML = '<div class="vlm-key-result">'
			+ '<p class="vlm-key-once-notice">⚠️ このキーは一度だけ表示されます。必ずコピーしてください。</p>'
			+ '<div class="vlm-key-box"><code id="vlm-key-text">' + esc(res.license_key || '') + '</code></div>'
			+ '<button type="button" id="vlm-key-copy" class="btn-secondary btn-sm" style="margin-top:6px">クリップボードにコピー</button>'
			+ '</div>';
		var copyBtn = r.querySelector('#vlm-key-copy');
		if (copyBtn) {
			copyBtn.addEventListener('click', function() {
				var txt = res.license_key || '';
				if (navigator.clipboard) {
					navigator.clipboard.writeText(txt).then(function() { copyBtn.textContent = 'コピーしました'; });
				} else {
					var ta = document.createElement('textarea');
					ta.value = txt;
					document.body.appendChild(ta);
					ta.select();
					document.execCommand('copy');
					document.body.removeChild(ta);
					copyBtn.textContent = 'コピーしました';
				}
			});
		}
	}

	CardRegistry.register('VendorLicenses', {
		cardKey:    'VENDOR_LICENSES',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_licenses',
		wrap: function(el, data) {
			if (data && data.entries) {
				render(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
