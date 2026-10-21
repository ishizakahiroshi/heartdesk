// heartdesk カード: GeoIPキャッシュ (sec-geoip-cache)
// monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / ipBadges / isWhitelisted / addRowNumbers /
//       formatDisplayDateTime / createFilterHeaderRow / buildIpFilterCell /
//       setupCardFilter / autoInitCardFromDataset、
//       nginx_log.js の monitorIpFilterOpts（window 公開）、
//       layout.html の BANNED_IPS / KNOWN_IPS、card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderGeoIPCache(el, d) {
		if (!d) { el.innerHTML = '<p>データなし</p>'; return; }
		var count = d.count || 0;
		var fileSizeKb = d.file_size ? (d.file_size / 1024).toFixed(1) + ' KB' : '-';
		var lastCall = d.last_call_ts ? formatDisplayDateTime(new Date(d.last_call_ts * 1000), 'なし') : 'なし';
		var xRl = d.x_rl != null ? d.x_rl + ' 回残' : '-';
		var xTtl = d.x_ttl != null ? d.x_ttl + ' 秒後リセット' : '-';
		var totalCalls = d.total_calls || 0;

		var html = '<div class="geoip-stats">';
		html += '<div class="geoip-stat-row">';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">登録件数</span><span class="geoip-stat-value">' + count.toLocaleString() + ' 件</span></div>';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">ファイルサイズ</span><span class="geoip-stat-value">' + fileSizeKb + '</span></div>';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">キャッシュ</span><span class="geoip-stat-value">永続保持</span></div>';
		html += '</div>';
		html += '<div class="geoip-stat-row">';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">最終APIコール</span><span class="geoip-stat-value">' + lastCall + '</span></div>';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">API残リクエスト</span><span class="geoip-stat-value">' + xRl + '　' + xTtl + '</span></div>';
		html += '<div class="geoip-stat"><span class="geoip-stat-label">累計コール回数</span><span class="geoip-stat-value">' + totalCalls + ' 回</span></div>';
		html += '</div>';
		html += '</div>';

		var ips = d.ips || [];
		ips.sort(function(a, b) { return (b.ts || 0) - (a.ts || 0); });
		var countryList = [];
		if (ips.length > 0) {
			var countrySet = {};
			for (var ci = 0; ci < ips.length; ci++) {
				if (ips[ci].country) countrySet[ips[ci].country] = true;
			}
			countryList = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
			html += '<table class="log-table"><thead>';
			html += '<tr><th class="col-ip">IP</th><th class="col-country">国</th><th>登録日時</th></tr>';
			html += '</thead><tbody>';
			for (var i = 0; i < ips.length; i++) {
				var item = ips[i];
				var itemWl = isWhitelisted(item.ip);
				var itemBanned = !!(window.BANNED_IPS && window.BANNED_IPS[item.ip]);
				var regStr = item.ts ? formatDisplayDateTime(new Date(item.ts * 1000), '-') : '-';
				html += '<tr data-ip="' + escHtml(item.ip) + '" data-country="' + escHtml(item.country || '') + '"'
					+ ' data-wl="' + (itemWl ? '1' : '0') + '"'
					+ ' data-banned="' + (itemBanned ? '1' : '0') + '"'
					+ (window.KNOWN_IPS && window.KNOWN_IPS[item.ip] ? ' data-known="1"' : '') + '>';
				html += '<td class="col-ip"><code class="ip-clickable" onclick="openIpModal(\'' + escHtml(item.ip) + '\')">' + escHtml(item.ip) + '</code>' + ipBadges(item.ip) + '</td>';
				html += '<td class="col-country">' + escHtml(item.country || '—') + '</td>';
				html += '<td class="nowrap">' + regStr + '</td>';
				html += '</tr>';
			}
			html += '</tbody></table>';
		} else {
			html += '<p class="empty">キャッシュデータがありません</p>';
		}

		el.innerHTML = html;
		if (ips.length > 0) {
			var thead = el.querySelector('thead');
			if (thead) {
				var countryOptions = countryList.map(function(c) { return { value: c, label: c }; });
				var ipFilterOpts = (typeof monitorIpFilterOpts === 'function')
					? monitorIpFilterOpts('sec-geoip-cache', {wl:true,wlm:true,wla:true,ban:true,known:true})
					: {wl:true,wlm:true,wla:true,ban:true,known:true};
				var filterRow = createFilterHeaderRow([
					{ type: 'custom', colClass: 'col-ip', content: buildIpFilterCell(ipFilterOpts) },
					{ type: 'select', colClass: 'col-country', dataFilter: 'country', options: [{ value: '', label: '国絞り込み' }].concat(countryOptions) },
					{ type: 'count', colClass: 'col-count' }
				]);
				thead.appendChild(filterRow);
			}
			setupCardFilter(el.querySelector('.thead-filter-row'), el);
			autoInitCardFromDataset(el.closest('section.card'), { total: ips.length });
			addRowNumbers(el);
		}
	}

	window.renderGeoIPCache = renderGeoIPCache;

	CardRegistry.register('GeoIPCache', {
		cardKey: 'GEOIP_CACHE',
		fallbackId: 'sec-geoip-cache',
		apiFallback: 'geoip_cache',
		render: function(el, d) { renderGeoIPCache(el, d); }
	});
})();
