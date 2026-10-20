// SAB カード: BAN ヒートマップ (sec-ban-heatmap)
// Phase 2b (C3): monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / HM_DAYS / buildHeatmapTable / isWhitelisted /
//       ipBadges / openIpModal / addRowNumbers、card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderBanHeatmap(el, d) {
		if (!d || !d.ban_heatmap_total) { el.innerHTML = '<p>データなし</p>'; return; }
		var html = '<div class="stat-summary">アクティブBAN: <strong>' + escHtml(d.total_banned) + ' IP</strong></div>';
		html += buildHeatmapTable(d.ban_heatmap_total, d.heatmap_max, '全jail合計（直近30日）', null, 'all');
		var jails = d.ban_heatmap ? Object.keys(d.ban_heatmap) : [];
		jails.forEach(function(jail) {
			var jailData = d.ban_heatmap[jail];
			var sum = 0;
			for (var di = 0; di < 7; di++) for (var hi = 0; hi < 24; hi++) sum += (jailData[di] && jailData[di][hi]) || 0;
			if (sum === 0) return;
			html += buildHeatmapTable(jailData, d.heatmap_max, jail, sum, jail);
		});
		el.innerHTML = html;
		if (!el.__hmClickBound) {
			el.__hmClickBound = true;
			el.addEventListener('click', function(ev) {
				var cell = ev.target;
				if (!cell || !cell.classList || !cell.classList.contains('heatmap-cell-active')) return;
				var jail = cell.getAttribute('data-jail') || 'all';
				var dow  = parseInt(cell.getAttribute('data-dow')  || '', 10);
				var hour = parseInt(cell.getAttribute('data-hour') || '', 10);
				if (isNaN(dow) || isNaN(hour)) return;
				openBanHeatmapModal(jail, dow, hour);
			});
		}
	}

	function openBanHeatmapModal(jail, dow, hour) {
		var modal = document.getElementById('hm-detail-modal');
		var title = document.getElementById('hm-detail-title');
		var body  = document.getElementById('hm-detail-body');
		if (!modal || !title || !body) return;

		var jailLabel = jail === 'all' ? '全jail合計' : jail;
		title.textContent = 'BANヒートマップ詳細: ' + jailLabel + ' / ' + HM_DAYS[dow] + '曜 ' + hour + ':00';
		body.innerHTML = '<p class="section-loading">読み込み中...</p>';
		modal.style.display = 'flex';

		var appBase = (typeof IH_APP_BASE !== 'undefined') ? IH_APP_BASE : '/monitor';
		fetch(appBase + '/?api=ban_heatmap_cell&jail=' + encodeURIComponent(jail) + '&dow=' + encodeURIComponent(String(dow)) + '&hour=' + encodeURIComponent(String(hour)))
			.then(function(r) { return r.json(); })
			.then(function(data) {
				if (data && data.error) {
					body.innerHTML = '<p class="section-error">' + escHtml(data.error) + '</p>';
					return;
				}
				var entries = (data && data.entries) ? data.entries : [];
				var total   = (data && typeof data.total === 'number') ? data.total : entries.length;
				var html = '<p class="search-summary">' + escHtml(jailLabel) + ' / ' + HM_DAYS[dow] + '曜 ' + hour + ':00 のBAN: ' + total + ' 件</p>';
				html += '<div style="min-height:1.5em"><span id="hm-ban-msg" class="ban-list-msg"></span></div>';
				if (!entries.length) {
					html += '<p class="empty">該当するBANはありません</p>';
					body.innerHTML = html;
					return;
				}
				html += '<div style="overflow-x:auto"><table class="log-table"><thead><tr><th>時刻</th><th class="col-ip">IP</th><th>国</th><th>JAIL</th><th style="width:90px"></th></tr></thead><tbody>';
				for (var i = 0; i < entries.length; i++) {
					var e    = entries[i];
					var ip   = e.ip || '';
					var flag = (data.flags && data.flags[ip]) ? data.flags[ip] : '-';
					var wl   = isWhitelisted(ip);
					var actionHtml = '';
					if (wl) {
						actionHtml = '<span class="wl-badge">WL</span>';
					} else if (e.is_banned) {
						actionHtml = '<button type="button" class="btn-warning btn-sm hm-unban-btn" data-ip="' + escHtml(ip) + '">解除</button>';
					} else {
						actionHtml = '<button type="button" class="btn-ban btn-sm hm-ban-btn" data-ip="' + escHtml(ip) + '">BAN追加</button>';
					}
					html += '<tr>'
						+ '<td class="nowrap">' + escHtml(e.time || '') + '</td>'
						+ '<td class="nowrap"><code class="ip-clickable" onclick="closeBanHeatmapModal();openIpModal(\'' + escHtml(ip) + '\')">' + escHtml(ip) + '</code>' + ipBadges(ip) + '</td>'
						+ '<td class="nowrap">' + escHtml(flag) + '</td>'
						+ '<td class="nowrap">' + escHtml(e.jail || '') + '</td>'
						+ '<td>' + actionHtml + '</td>'
						+ '</tr>';
				}
				html += '</tbody></table></div>';
				body.innerHTML = html;
				addRowNumbers(body);
				setupBanHeatmapModalEvents();
			})
			.catch(function(err) {
				body.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escHtml(err.message) + '</p>';
			});
	}

	function closeBanHeatmapModal() {
		var modal = document.getElementById('hm-detail-modal');
		if (modal) modal.style.display = 'none';
	}

	function setupBanHeatmapModalEvents() {
		var appBase = (typeof IH_APP_BASE !== 'undefined') ? IH_APP_BASE : '/monitor';
		var msg = document.getElementById('hm-ban-msg');
		function setMsg(text, isOk) {
			if (!msg) return;
			msg.textContent = text;
			msg.className = 'ban-list-msg' + (typeof isOk === 'boolean' ? (isOk ? ' success' : ' error') : '');
		}
		function bindBtns(selector, api) {
			var btns = document.querySelectorAll('#hm-detail-body ' + selector);
			for (var i = 0; i < btns.length; i++) {
				(function(btn) {
					btn.addEventListener('click', function() {
						var ip = btn.getAttribute('data-ip') || '';
						if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return;
						if (api === 'fail2ban_ban' && isWhitelisted(ip)) {
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
		bindBtns('.hm-ban-btn',   'fail2ban_ban');
		bindBtns('.hm-unban-btn', 'fail2ban_unban');
	}

	window.renderBanHeatmap = renderBanHeatmap;
	window.openBanHeatmapModal = openBanHeatmapModal;
	window.closeBanHeatmapModal = closeBanHeatmapModal;
	window.setupBanHeatmapModalEvents = setupBanHeatmapModalEvents;

	CardRegistry.register('BanHeatmap', {
		cardKey: 'BAN_HEATMAP',
		fallbackId: 'sec-ban-heatmap',
		apiFallback: 'ban_heatmap',
		render: function(el, d) { renderBanHeatmap(el, d); }
	});
})();
