// heartdesk カード: 要確認IP（高スコア・手動BAN候補） (sec-nc-high-score)
// 依存: shared.js の escHtml / formatDisplayDateTime / ipBadges / isWhitelisted /
//       createFilterHeaderRow / buildIpFilterCell / setupCardFilter /
//       initBulkBan / autoInitCardFromDataset / addRowNumbers / monitorApiURL、
//       card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderNcHighScore(el, d) {
		var scores = (d && d.scores) || [];
		var flags = (d && d.flags) || {};
		var total = (d && typeof d.count === 'number') ? d.count : scores.length;

		if (!scores.length) {
			el.innerHTML = '<p class="empty">要確認の高スコアIPはありません</p>';
			autoInitCardFromDataset(el.closest('section.card'), { total: 0 });
			return;
		}

		var countrySet = {};
		for (var ci = 0; ci < scores.length; ci++) {
			if (scores[ci] && scores[ci].ip && flags[scores[ci].ip]) {
				countrySet[flags[scores[ci].ip]] = true;
			}
		}
		var countryOptions = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); })
			.map(function(c) { return { value: c, label: c }; });

		var html = '<form method="post" data-bulk-ban="nc-high-score" data-bulk-ban-url="?api=bulk_ban">';
		html += '<div class="bulk-ban-bar">'
			+ '<label class="bulk-select-all"><input type="checkbox" data-select-all="nc-high-score"> 全選択</label>'
			+ '<span class="bulk-ban-count" data-count="nc-high-score">0件選択中</span>'
			+ '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nc-high-score" disabled>選択したIPをBAN</button>'
			+ '</div>';
		html += '<table class="log-table"><thead><tr>';
		html += '<th class="cb-col"></th>';
		html += '<th class="col-ip">IP</th>';
		html += '<th class="col-country">国</th>';
		html += '<th>スコア</th>';
		html += '<th class="score-detail">認証失敗</th>';
		html += '<th class="score-detail">NC失敗</th>';
		html += '<th class="score-detail">NC 4xx</th>';
		html += '<th class="score-detail">スキャン</th>';
		html += '<th class="score-detail">海外</th>';
		html += '<th class="score-detail">更新</th>';
		html += '<th></th>';
		html += '</tr></thead><tbody>';

		scores.forEach(function(s) {
			s = s || {};
			var ip = s.ip || '';
			var ipEsc = escHtml(ip);
			var score = Number(s.score || 0);
			var pct = Math.max(4, Math.min(100, Math.round(score / 3)));
			var wl = (typeof isWhitelisted === 'function') ? isWhitelisted(ip) : false;
			var banned = !!(s.is_banned || (typeof BANNED_IPS !== 'undefined' && BANNED_IPS && BANNED_IPS[ip]));
			var known = !!(typeof KNOWN_IPS !== 'undefined' && KNOWN_IPS && KNOWN_IPS[ip]);
			var country = flags[ip] || '-';
			var disableCb = wl || banned || !ip;

			html += '<tr class="ts-row ts-row-high-risk" data-ip="' + ipEsc + '" data-country="' + escHtml(country) + '"'
				+ ' data-foreign="' + (s.is_foreign ? '海外' : '国内') + '"'
				+ (wl ? ' data-wl="1"' : '')
				+ (banned ? ' data-banned="1"' : '')
				+ (known ? ' data-known="1"' : '') + '>';
			html += '<td class="cb-col" onclick="event.stopPropagation();">'
				+ '<input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="nc-high-score"' + (disableCb ? ' disabled' : '') + '></td>';
			html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">'
				+ ipEsc + '</code>' + (typeof ipBadges === 'function' ? ipBadges(ip) : '') + '</td>';
			html += '<td class="col-country">' + escHtml(country) + '</td>';
			html += '<td><div class="score-bar-outer"><div class="score-bar-bg">'
				+ '<div class="score-bar-fill score-danger" style="width:' + pct + '%"></div>'
				+ '</div><span class="score-value">' + escHtml(String(score)) + '</span></div></td>';
			html += '<td class="score-detail">' + escHtml(String(s.auth_fails || 0)) + '</td>';
			html += '<td class="score-detail">' + escHtml(String(s.nc_fails || 0)) + '</td>';
			html += '<td class="score-detail">' + escHtml(String(s.nc_4xx || 0)) + '</td>';
			html += '<td class="score-detail">' + escHtml(String(s.scan_hits || 0)) + '</td>';
			html += '<td class="score-detail">' + (s.is_foreign ? '<span class="foreign-badge">海外</span>' : '-') + '</td>';
			var ts = (typeof formatDisplayDateTime === 'function') ? formatDisplayDateTime(s.timestamp, '-') : (s.timestamp || '-');
			html += '<td class="score-detail nowrap">' + escHtml(ts) + '</td>';
			html += '<td class="nowrap" onclick="event.stopPropagation();">' + actionCell(ipEsc, wl, banned) + '</td>';
			html += '</tr>';
		});

		html += '</tbody></table></form>';
		el.innerHTML = html;

		var thead = el.querySelector('thead');
		if (thead && typeof setupCardFilter === 'function') {
			var ipFilterOpts = (typeof monitorIpFilterOpts === 'function')
				? monitorIpFilterOpts('sec-nc-high-score', {wl:false, wlm:false, wla:false, ban:false, known:false})
				: {wl:false, wlm:false, wla:false, ban:false, known:false};
			thead.appendChild(createFilterHeaderRow([
				{ type: 'checkbox', colClass: 'cb-col' },
				{ type: 'custom', colClass: 'col-ip', content: buildIpFilterCell(ipFilterOpts) },
				{ type: 'select', colClass: 'col-country', dataFilter: 'country', options: [{ value: '', label: '全て' }].concat(countryOptions) },
				{ type: 'empty', colSpan: 5 },
				{ type: 'select', colClass: 'score-detail', dataFilter: 'foreign', options: [{ value: '', label: '全て' }, { value: '海外', label: '海外' }, { value: '国内', label: '国内' }] },
				{ type: 'empty', colClass: 'score-detail' },
				{ type: 'count' }
			]));
		}

		if (typeof initBulkBan === 'function') initBulkBan('nc-high-score', el);
		autoInitCardFromDataset(el.closest('section.card'), { total: total });
		if (typeof setupCardFilter === 'function') setupCardFilter(el.querySelector('.thead-filter-row'), el);
		if (typeof addRowNumbers === 'function') addRowNumbers(el);
		setupNcHighScoreEvents(el);
	}

	function actionCell(ipEsc, wl, banned) {
		if (wl) return '<span class="wl-badge">WL</span>';
		if (banned) return '<span class="jail-tag jail-tag-banned">BAN済</span>';
		return '<button type="button" class="btn-warning btn-sm nchs-dismiss-btn" data-ip="' + ipEsc + '" title="24時間このIPを要確認一覧から除外">24h無視</button> '
			+ '<button type="button" class="btn-ban btn-sm nchs-ban-btn" data-ip="' + ipEsc + '">BAN追加</button>';
	}

	function postIpAction(api, ip, onOK, onErr) {
		var url = (typeof monitorApiURL === 'function') ? monitorApiURL(api) : '/monitor/?api=' + encodeURIComponent(api);
		fetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
			body: 'ip=' + encodeURIComponent(ip)
		})
		.then(function(r) { return r.json(); })
		.then(function(res) {
			if (res && res.ok) { onOK(res); }
			else { onErr((res && res.message) || '操作に失敗しました'); }
		})
		.catch(function() { onErr('通信エラーが発生しました'); });
	}

	function setupNcHighScoreEvents(el) {
		el.querySelectorAll('.nchs-dismiss-btn').forEach(function(btn) {
			btn.addEventListener('click', function(ev) {
				ev.stopPropagation();
				var ip = btn.getAttribute('data-ip') || '';
				if (!ip) return;
				btn.disabled = true;
				postIpAction('highscore_dismiss', ip, function() {
					var tr = btn.closest('tr');
					if (tr) tr.parentNode.removeChild(tr);
					autoInitCardFromDataset(el.closest('section.card'), { total: el.querySelectorAll('tbody tr').length });
				}, function(msg) {
					if (typeof showToast === 'function') showToast(msg, 'error'); else alert(msg);
					btn.disabled = false;
				});
			});
		});

		el.querySelectorAll('.nchs-ban-btn').forEach(function(btn) {
			btn.addEventListener('click', function(ev) {
				ev.stopPropagation();
				var ip = btn.getAttribute('data-ip') || '';
				if (!ip) return;
				if (typeof isWhitelisted === 'function' && isWhitelisted(ip)) {
					alert('ホワイトリストIPのためBANできません');
					return;
				}
				if (!confirm(ip + ' をBANしますか？')) return;
				btn.disabled = true;
				postIpAction('fail2ban_ban', ip, function(res) {
					if (typeof BANNED_IPS !== 'undefined' && BANNED_IPS) BANNED_IPS[ip] = 'recidive';
					var tr = btn.closest('tr');
					if (tr) {
						tr.setAttribute('data-banned', '1');
						var cb = tr.querySelector('input[name="ban_ips[]"]');
						if (cb) cb.disabled = true;
						btn.parentNode.innerHTML = '<span class="jail-tag jail-tag-banned">BAN済</span>';
					}
					if (typeof showToast === 'function') showToast(res.message || 'BANしました');
				}, function(msg) {
					if (typeof showToast === 'function') showToast(msg, 'error'); else alert(msg);
					btn.disabled = false;
				});
			});
		});
	}

	window.renderNcHighScore = renderNcHighScore;

	CardRegistry.register('NcHighScore', {
		cardKey: 'NC_HIGH_SCORE',
		fallbackId: 'sec-nc-high-score',
		apiFallback: 'nc_high_score',
		render: function(el, d) { renderNcHighScore(el, d); }
	});
})();
