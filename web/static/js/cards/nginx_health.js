// heartdesk カード: Nginxヘルス (sec-nginx-health)
// Phase 2c (C4): monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / ipBadges / isWhitelisted / addRowNumbers、
//       card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderNginxHealth(el, d) {
		if (!d) { el.innerHTML = '<p>データなし</p>'; return; }
		var w1h  = d.window_1h  || { total: 0, by_class: {} };
		var w24h = d.window_24h || { total: 0, by_class: {} };
		var top5xx = d.top_5xx || [];
		var threshold5xx1h = 5, threshold5xx24h = 20;

		function bar(label, w, threshold5xx) {
			var classes = ['2xx','3xx','4xx','5xx'];
			var html = '<div class="nh-window"><div class="nh-window-title">' + label
				+ ' <span class="nh-total">(合計 ' + (w.total || 0) + ' req)</span>';
			if ((w.by_class && w.by_class['5xx'] || 0) >= threshold5xx) {
				html += ' <span class="ban-badge">5xx 急増</span>';
			}
			html += '</div><div class="nh-bar">';
			for (var i = 0; i < classes.length; i++) {
				var cls = classes[i];
				var c = (w.by_class && w.by_class[cls]) || 0;
				var pct = w.total > 0 ? (c / w.total * 100) : 0;
				if (pct > 0) {
					html += '<div class="nh-seg sc-' + cls.charAt(0) + '" style="width:' + pct.toFixed(2) + '%" title="' + cls + ': ' + c + ' (' + pct.toFixed(1) + '%)">'
						+ (pct >= 8 ? cls + ' ' + c : '') + '</div>';
				}
			}
			html += '</div><div class="nh-legend">';
			for (var j = 0; j < classes.length; j++) {
				var cl = classes[j];
				var cc = (w.by_class && w.by_class[cl]) || 0;
				var pp = w.total > 0 ? (cc / w.total * 100).toFixed(1) : '0.0';
				html += '<span class="nh-leg sc-' + cl.charAt(0) + '">' + cl + ': <strong>' + cc + '</strong> (' + pp + '%)</span>';
			}
			html += '</div></div>';
			return html;
		}

		var html = '<div class="nh-windows">' + bar('直近1時間', w1h, threshold5xx1h) + bar('直近24時間', w24h, threshold5xx24h) + '</div>';
		if (top5xx.length > 0) {
			html += '<div class="nh-window"><div class="nh-window-title">5xx 発生URL TOP <span class="nh-total">(直近24時間)</span></div>';
			html += '<table class="nh-top-table"><thead><tr><th class="actions"></th><th>件数</th><th>ステータス</th><th>URL</th></tr></thead><tbody>';
			for (var k = 0; k < top5xx.length; k++) {
				var t = top5xx[k];
				var url = String(t.url || '');
				html += '<tr>'
					+ '<td class="actions"><button type="button" class="btn-primary btn-sm" data-ngurl-detail="' + escHtml(url) + '">詳細確認</button></td>'
					+ '<td>' + escHtml(String(t.count)) + '</td>'
					+ '<td><span class="sc sc-5">' + escHtml(String(t.status)) + '</span></td>'
					+ '<td><code>' + escHtml(url) + '</code></td>'
					+ '</tr>';
			}
			html += '</tbody></table></div>';
		}
		el.innerHTML = html;
		addRowNumbers(el);

		// 詳細確認ボタンのイベント設定
		var btns = el.querySelectorAll('button[data-ngurl-detail]');
		for (var bi = 0; bi < btns.length; bi++) {
			(function(btn) {
				btn.addEventListener('click', function() {
					openNginxUrlModal(btn.getAttribute('data-ngurl-detail') || '');
				});
			})(btns[bi]);
		}
	}

	// ========================================
	// Nginx URL 詳細 Modal
	// ========================================
	function openNginxUrlModal(url) {
		var modal = document.getElementById('nginx-url-modal');
		var title = document.getElementById('nginx-url-title');
		var body  = document.getElementById('nginx-url-body');
		if (!modal || !title || !body) return;

		title.textContent = 'URL詳細';
		body.innerHTML = '<p class="section-loading">読み込み中...</p>';
		modal.style.display = 'flex';

		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
		fetch(appBase + '/?api=nginx_url_detail&url=' + encodeURIComponent(url))
			.then(function(r) { return r.json(); })
			.then(function(data) {
				if (data.error) {
					body.innerHTML = '<p class="section-error">' + escHtml(data.error) + '</p>';
					return;
				}
				title.textContent = 'URL詳細 (' + (data.total || 0) + '件)';

				var html = '<div class="ngurl-meta">';
				html += '<span class="ngurl-url"><code>' + escHtml(data.url || url) + '</code></span>';
				html += '<span class="stat-sub">対象期間: 直近24時間（cutoff: ' + escHtml(data.cutoff || '-') + '）</span>';
				html += '</div>';
				html += '<div class="ngurl-badges">';
				if (data.by_status) {
					var keys = Object.keys(data.by_status);
					keys.sort(function(a, b) { return Number(b) - Number(a); });
					for (var i = 0; i < keys.length; i++) {
						var st = keys[i];
						var scCls = 'sc-' + String(st).charAt(0);
						html += '<span class="ngurl-badge ' + scCls + '">' + escHtml(st) + ': <strong>' + escHtml(String(data.by_status[st])) + '</strong></span>';
					}
				}
				html += '<span id="ngurl-ban-msg" class="ban-list-msg"></span>';
				html += '</div>';

				// 上位IP
				if (data.top_ips && data.top_ips.length) {
					html += '<div style="margin-bottom:10px;">';
					html += '<div class="stat-label">上位IP（件数）</div>';
					for (var t = 0; t < data.top_ips.length; t++) {
						var e = data.top_ips[t];
						var ip = e.ip || '';
						var flag = (data.flags && data.flags[ip]) ? data.flags[ip] : '-';
						var isJp = data.is_japan_flags && data.is_japan_flags[ip];
						var countryBadge = '';
						if (flag !== '-') {
							if (isJp) {
								countryBadge = '<span class="jp-badge">' + escHtml(flag) + ' 国内</span>';
							} else {
								countryBadge = '<span class="foreign-badge">' + escHtml(flag) + ' 海外</span>';
							}
						}
						html += '<div class="bf-attempt">'
							+ '<code class="ip-clickable" onclick="closeNginxUrlModal(); openIpModal(\'' + escHtml(ip) + '\');">' + escHtml(ip) + '</code>' + ipBadges(ip)
							+ countryBadge
							+ '<span class="bf-count">' + escHtml(String(e.count || 0)) + '</span>'
							+ '</div>';
					}
					html += '</div>';
				}

				// ログエントリテーブル
				var entries = data.entries || [];
				if (!entries.length) {
					html += '<p class="empty">該当ログがありません</p>';
					body.innerHTML = html;
					return;
				}
				html += '<div class="table-scroll"><table class="ngurl-table log-table"><thead><tr>'
					+ '<th>時刻</th><th class="col-ip">IP</th><th>ステータス</th><th>リクエスト</th><th>Referer</th><th>UA</th><th style="width:70px;"></th>'
					+ '</tr></thead><tbody>';
				for (var j = 0; j < entries.length; j++) {
					var rr = entries[j];
					var rip = String(rr.ip || '');
					var status = String(rr.status || '');
					var req = (rr.method ? (String(rr.method) + ' ') : '') + String(rr.path || '');
					var wl = isWhitelisted(rip);
					html += '<tr>'
						+ '<td class="nowrap">' + escHtml(rr.time || '') + '</td>'
						+ '<td class="nowrap"><code class="ip-clickable" onclick="closeNginxUrlModal(); openIpModal(\'' + escHtml(rip) + '\');">' + escHtml(rip) + '</code>' + ipBadges(rip) + '</td>'
						+ '<td class="nowrap"><span class="sc sc-' + (status ? status.charAt(0) : '5') + '">' + escHtml(status) + '</span></td>'
						+ '<td><code title="' + escHtml(req) + '">' + escHtml(req) + '</code></td>'
						+ '<td class="referer" title="' + escHtml(rr.referer || '') + '">' + escHtml(rr.referer || '-') + '</td>'
						+ '<td class="ua" title="' + escHtml(rr.ua || '') + '">' + escHtml(rr.ua || '-') + '</td>'
						+ '<td>' + (wl ? '<span class="wl-badge">WL</span>' : '<button type="button" class="ngurl-ban-single-btn btn-ban btn-sm" data-ip="' + escHtml(rip) + '">BAN</button>') + '</td>'
						+ '</tr>';
				}
				html += '</tbody></table></div>';
				body.innerHTML = html;
				addRowNumbers(body);
				setupNginxUrlModalEvents();
			})
			.catch(function(err) {
				body.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escHtml(err.message) + '</p>';
			});
	}

	function closeNginxUrlModal() {
		var modal = document.getElementById('nginx-url-modal');
		if (modal) modal.style.display = 'none';
	}

	function setupNginxUrlModalEvents() {
		var body = document.getElementById('nginx-url-body');
		if (!body) return;
		body.querySelectorAll('.ngurl-ban-single-btn').forEach(function(btn) {
			btn.addEventListener('click', function() {
				var ip = btn.getAttribute('data-ip') || '';
				if (!ip || !confirm(ip + ' を BAN しますか？')) return;
				var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
				var csrfToken = (typeof getCsrfToken === 'function') ? getCsrfToken() : '';
				var postURL = (typeof monitorApiURL === 'function') ? monitorApiURL('fail2ban_ban') : (appBase + '/?api=fail2ban_ban');
				fetch(postURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: 'ip=' + encodeURIComponent(ip) + '&csrf_token=' + encodeURIComponent(csrfToken || '')
				})
				.then(function(r) { return r.json(); })
				.then(function(d) {
					var msg = document.getElementById('ngurl-ban-msg');
					if (msg) { msg.textContent = d.message || (d.ok ? 'BAN 完了' : 'エラー'); }
					if (d.ok) { btn.replaceWith(document.createTextNode('BAN済')); }
				})
				.catch(function() {});
			});
		});
	}

	window.renderNginxHealth = renderNginxHealth;
	window.openNginxUrlModal = openNginxUrlModal;
	window.closeNginxUrlModal = closeNginxUrlModal;
	window.setupNginxUrlModalEvents = setupNginxUrlModalEvents;

	CardRegistry.register('NginxHealth', {
		cardKey: 'NGINX_HEALTH',
		fallbackId: 'sec-nginx-health',
		apiFallback: 'nginx_health',
		render: function(el, d) { renderNginxHealth(el, d); }
	});
})();
