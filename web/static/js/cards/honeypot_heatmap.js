// heartdesk カード: ハニーポットヒートマップ (sec-honeypot-heatmap)
// monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / HM_DAYS / buildHeatmapTable / HP_TRIGGER_LABELS /
//       isWhitelisted / ipBadges / openIpModal / addRowNumbers、
//       card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderHoneypotHeatmap(el, d) {
		var hd = d && d.heatmap ? d.heatmap : d;
		if (!hd || !hd.heatmap_total || hd.heatmap_max === 0) {
			el.innerHTML = '<p>直近7日間にハニーポットアクセスはありません</p>'; return;
		}
		var HP_RGB = '108,92,231';
		var trigLabels = (typeof HP_TRIGGER_LABELS !== 'undefined' && HP_TRIGGER_LABELS) ? HP_TRIGGER_LABELS : {
			dotfile: 'ドットファイル', wordpress: 'WordPress', db_tool: 'DBツール',
			microsoft: 'Microsoft系', framework: 'フレームワーク',
			backdoor: 'バックドア/シェル', query_string: 'クエリ攻撃', other: 'その他'
		};
		var html = buildHeatmapTable(hd.heatmap_total, hd.heatmap_max, '🍯 全trigger合計（直近7日）', null, null, HP_RGB, '件', 'all');
		if (hd.heatmap) {
			Object.keys(hd.heatmap).forEach(function(trig) {
				var cells = hd.heatmap[trig];
				var sum = 0;
				for (var d2 = 0; d2 < 7; d2++) for (var h = 0; h < 24; h++) sum += (cells[d2] && cells[d2][h]) || 0;
				if (sum === 0) return;
				var label = '📌 ' + (trigLabels[trig] || trig) + ' (' + sum + ' 件)';
				html += buildHeatmapTable(cells, hd.heatmap_max, label, null, null, HP_RGB, '件', trig);
			});
		}
		el.innerHTML = html;

		if (!el.__hmHpClickBound) {
			el.__hmHpClickBound = true;
			el.addEventListener('click', function(ev) {
				var cell = ev.target;
				if (!cell || !cell.classList || !cell.classList.contains('heatmap-cell-hp')) return;
				var trigger = cell.getAttribute('data-trigger') || 'all';
				var dow  = parseInt(cell.getAttribute('data-dow')  || '', 10);
				var hour = parseInt(cell.getAttribute('data-hour') || '', 10);
				if (isNaN(dow) || isNaN(hour)) return;
				openHpHeatmapModal(trigger, dow, hour);
			});
		}
	}

	function openHpHeatmapModal(trigger, dow, hour) {
		var modal = document.getElementById('hp-hm-detail-modal');
		var title = document.getElementById('hp-hm-detail-title');
		var body  = document.getElementById('hp-hm-detail-body');
		if (!modal || !title || !body) return;

		var trigLabels = (typeof HP_TRIGGER_LABELS !== 'undefined' && HP_TRIGGER_LABELS) ? HP_TRIGGER_LABELS : {
			dotfile: 'ドットファイル', wordpress: 'WordPress', db_tool: 'DBツール',
			microsoft: 'Microsoft系', framework: 'フレームワーク',
			backdoor: 'バックドア/シェル', query_string: 'クエリ攻撃', other: 'その他'
		};
		var trigLabel = trigger === 'all' ? '全trigger合計' : (trigLabels[trigger] || trigger);
		title.textContent = 'HPヒートマップ詳細: ' + trigLabel + ' / ' + HM_DAYS[dow] + '曜 ' + hour + ':00';
		body.innerHTML = '<p class="section-loading">読み込み中...</p>';
		modal.style.display = 'flex';

		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
		fetch(appBase + '/?api=honeypot_heatmap_cell&trigger=' + encodeURIComponent(trigger) + '&dow=' + encodeURIComponent(String(dow)) + '&hour=' + encodeURIComponent(String(hour)))
			.then(function(r) { return r.json(); })
			.then(function(data) {
				if (data && data.error) {
					body.innerHTML = '<p class="section-error">' + escHtml(data.error) + '</p>';
					return;
				}
				var entries = (data && data.entries) ? data.entries : [];
				var total   = (data && typeof data.total === 'number') ? data.total : entries.length;
				var html = '<p class="search-summary">' + escHtml(trigLabel) + ' / ' + HM_DAYS[dow] + '曜 ' + hour + ':00 のアクセス: ' + total + ' 件</p>';
				html += '<div style="min-height:1.5em"><span id="hp-hm-ban-msg" class="ban-list-msg"></span></div>';
				if (!entries.length) {
					html += '<p class="empty">該当するアクセスはありません</p>';
					body.innerHTML = html;
					return;
				}
				var flags = (data && data.flags) ? data.flags : {};
				html += '<table class="log-table"><thead><tr><th>時刻</th><th class="col-ip">IP</th><th class="col-country">国</th><th>メソッド</th><th>パス</th><th>トリガー</th><th>User-Agent</th><th style="width:90px;"></th></tr></thead><tbody>';
				for (var i = 0; i < entries.length; i++) {
					var e  = entries[i];
					var ip = e.ip || '';
					var ipEsc = escHtml(ip);
					var wl = (typeof isWhitelisted === 'function') ? isWhitelisted(ip) : false;
					var isBannedNow = (typeof BANNED_IPS !== 'undefined' && BANNED_IPS) ? !!BANNED_IPS[ip] : false;
					var actionHtml = '';
					if (wl) {
						actionHtml = '<span class="wl-badge">WL</span>';
					} else if (isBannedNow) {
						actionHtml = '<button type="button" class="btn-warning btn-sm hp-hm-unban-btn" data-ip="' + ipEsc + '">解除</button>';
					} else {
						actionHtml = '<button type="button" class="btn-ban btn-sm hp-hm-ban-btn" data-ip="' + ipEsc + '">BAN追加</button>';
					}
					var tl = escHtml(trigLabels[e.trigger] || e.trigger || '');
					html += '<tr>';
					html += '<td class="nowrap">' + escHtml(e.ts || '') + '</td>';
					html += '<td class="nowrap"><code class="ip-clickable" onclick="closeHpHeatmapModal(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + (typeof ipBadges === 'function' ? ipBadges(ip) : '') + '</td>';
					html += '<td class="col-country nowrap">' + escHtml((flags[ip] || '-')) + '</td>';
					html += '<td>' + escHtml(e.method || '') + '</td>';
					html += '<td class="text-ellipsis-220" title="' + escHtml(e.path || '') + '">' + escHtml(e.path || '') + '</td>';
					html += '<td><span class="result-badge hp-trig-badge">' + tl + '</span></td>';
					html += '<td class="text-ellipsis-180" title="' + escHtml(e.ua || '') + '">' + escHtml(e.ua || '') + '</td>';
					html += '<td>' + actionHtml + '</td>';
					html += '</tr>';
				}
				html += '</tbody></table>';
				body.innerHTML = html;
				addRowNumbers(body);
				setupHpHeatmapModalEvents();
			})
			.catch(function() {
				body.innerHTML = '<p class="section-error">データ取得に失敗しました</p>';
			});
	}

	function closeHpHeatmapModal() {
		var modal = document.getElementById('hp-hm-detail-modal');
		if (modal) modal.style.display = 'none';
	}

	function setupHpHeatmapModalEvents() {
		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
		var msg = document.getElementById('hp-hm-ban-msg');
		function setMsg(text, isOk) {
			if (!msg) return;
			msg.textContent = text;
			msg.className = 'ban-list-msg' + (typeof isOk === 'boolean' ? (isOk ? ' success' : ' error') : '');
		}
		function bindBtns(selector, api) {
			var btns = document.querySelectorAll('#hp-hm-detail-body ' + selector);
			for (var i = 0; i < btns.length; i++) {
				(function(btn) {
					btn.addEventListener('click', function() {
						var ip = btn.getAttribute('data-ip') || '';
						if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return;
						if (api === 'fail2ban_ban' && (typeof isWhitelisted === 'function') && isWhitelisted(ip)) {
							setMsg('ホワイトリストIPのためBANできません', false);
							return;
						}
						if (api === 'fail2ban_ban' && !confirm(ip + ' をBANしますか？')) return;
						btn.disabled = true;
						setMsg('処理中...');
						var postURL = (typeof monitorApiURL === 'function') ? monitorApiURL(api) : (appBase + '/?api=' + api);
						fetch(postURL, {
							method: 'POST',
							headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
							body: 'ip=' + encodeURIComponent(ip)
						}).then(function(r) { return r.json(); })
						.then(function(res) {
							setMsg(res.message || '完了しました', !!(res.ok || res.success));
							btn.disabled = false;
						})
						.catch(function() {
							setMsg('エラーが発生しました', false);
							btn.disabled = false;
						});
					});
				})(btns[i]);
			}
		}
		bindBtns('.hp-hm-ban-btn',   'fail2ban_ban');
		bindBtns('.hp-hm-unban-btn', 'fail2ban_unban');
	}

	window.renderHoneypotHeatmap = renderHoneypotHeatmap;
	window.openHpHeatmapModal = openHpHeatmapModal;
	window.closeHpHeatmapModal = closeHpHeatmapModal;
	window.setupHpHeatmapModalEvents = setupHpHeatmapModalEvents;

	CardRegistry.register('HoneypotHeatmap', {
		cardKey: 'HONEYPOT_HEATMAP',
		fallbackId: 'sec-honeypot-heatmap',
		apiFallback: 'honeypot_all',
		render: function(el, d) { renderHoneypotHeatmap(el, d); }
	});
})();
