// heartdesk カード: Nginxアクセスログ (sec-nginx-log)
// Phase 2c (C4): monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / ipBadges / isWhitelisted / addRowNumbers /
//       renderRateStatsGrid / cardViewToggle / getCsrfToken / getCardOptions /
//       createFilterHeaderRow / buildIpFilterCell / setupCardFilter /
//       autoInitCardFromDataset / initBulkBan / loginHistoryRowToggleAttrs /
//       saveCurrentViewFilter / getViewFilter / restoreFilterState /
//       formatCount / formatDisplayDateTime、
//       layout.html の BANNED_IPS / KNOWN_IPS、card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderNginxRateStats(rate) {
		return renderRateStatsGrid(rate, { spikeMinRecent: 50 });
	}

	function monitorIpFilterOpts(cardId, fallback) {
		var opts = (typeof getCardOptions === 'function') ? getCardOptions(cardId) : null;
		if (opts && opts.ip_filter && typeof opts.ip_filter === 'object') return opts.ip_filter;
		return fallback || {};
	}

	function renderNginxLogSummary(content) {
		saveCurrentViewFilter(content);
		var state = content && content.__nginxLogState ? content.__nginxLogState : null;
		var logs = state && state.logs ? state.logs : [];
		var flags = state && state.flags ? state.flags : {};
		var rate = state ? state.rate : null;
		if (!logs.length) { content.innerHTML = '<p class="empty">アクセスログがありません</p>'; return; }

		// IP別に集計
		var grouped = {};
		for (var i = 0; i < logs.length; i++) {
			var nr = logs[i];
			var ip = nr.ip;
			if (!ip) continue;
			if (!grouped[ip]) {
				grouped[ip] = { ip: ip, flag: flags[ip] || '', total: 0, statuses: {}, status_codes: {}, ports: {}, first_time: nr.time, last_time: '' };
			}
			var g = grouped[ip];
			g.total++;
			g.statuses[nr.status] = (g.statuses[nr.status] || 0) + 1;
			g.status_codes[nr.status] = 1;
			if (nr.port) g.ports[nr.port] = (g.ports[nr.port] || 0) + 1;
			g.last_time = nr.time;
		}
		var summaryRows = Object.keys(grouped).map(function(k) { return grouped[k]; });
		summaryRows.sort(function(a, b) { return b.total - a.total; });

		var countrySet = {};
		var statusCodeSet = {};
		var portSet = {};
		for (var sr = 0; sr < summaryRows.length; sr++) {
			var summaryCountry = (summaryRows[sr].flag || '').replace(/<[^>]*>/g, '').trim();
			if (summaryCountry) countrySet[summaryCountry] = 1;
			var summaryStatusCodes = Object.keys(summaryRows[sr].status_codes || {});
			for (var ss = 0; ss < summaryStatusCodes.length; ss++) {
				statusCodeSet[summaryStatusCodes[ss]] = 1;
			}
			var summaryPorts = Object.keys(summaryRows[sr].ports || {});
			for (var sp = 0; sp < summaryPorts.length; sp++) {
				portSet[summaryPorts[sp]] = 1;
			}
		}
		var countryList = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
		var statusCodeList = Object.keys(statusCodeSet).sort(function(a, b) { return Number(b) - Number(a); });
		var portList = Object.keys(portSet).sort(function(a, b) { return Number(a) - Number(b); });
		var countryOptions = '<option value="">国</option>';
		for (var co = 0; co < countryList.length; co++) {
			countryOptions += '<option value="' + escHtml(countryList[co]) + '">' + escHtml(countryList[co]) + '</option>';
		}
		var statusOptions = '<option value="">ステータス内訳</option>';
		for (var sto = 0; sto < statusCodeList.length; sto++) {
			statusOptions += '<option value="' + escHtml(statusCodeList[sto]) + '">' + escHtml(statusCodeList[sto]) + '</option>';
		}

		var csrfToken = getCsrfToken();
		var html = renderNginxRateStats(rate);
		html += cardViewToggle(
			'summary',
			'renderNginxLogSummary(this.closest(\'.async-content\'))',
			'renderNginxLogDetail(this.closest(\'.async-content\'), null)'
		);
		html += '<div class="nc-summary-meta">直近 ' + formatCount(logs.length) + ' 件 &nbsp;/&nbsp; ' + formatCount(summaryRows.length) + ' IP</div>';
		html += '<form method="post" data-bulk-ban="nginx" data-bulk-ban-url="?api=bulk_ban"><input type="hidden" name="csrf_token" value="' + escHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="nginx"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="nginx"> 全選択</label><span class="bulk-ban-count" data-count="nginx">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nginx" disabled>選択したIPをBAN</button></div>';
		html += '<div class="table-scroll"><table class="nginx-log-summary-table log-table"><col style="width:28px"><thead>';
		html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th class="col-count">件数</th><th class="col-port">ポート</th><th class="col-status-summary">ステータス内訳</th><th class="col-first">初回</th><th class="col-last">最終</th><th class="col-action"></th></tr>';
		html += '</thead><tbody>';

		for (var r = 0; r < summaryRows.length; r++) {
			var row = summaryRows[r];
			var wl = isWhitelisted(row.ip);
			var banned = BANNED_IPS[row.ip] || '';
			var disableCb = wl || !!banned;
			var ipEsc = escHtml(row.ip);
			var statusEntries = Object.keys(row.statuses).map(function(sc) { return { sc: sc, count: row.statuses[sc] }; });
			statusEntries.sort(function(a, b) { return b.count - a.count; });
			var breakdownHtml = '<span class="nginx-status-breakdown">';
			for (var si = 0; si < Math.min(statusEntries.length, 4); si++) {
				var se = statusEntries[si];
				if (si > 0) breakdownHtml += ' ';
				breakdownHtml += '<span class="sc sc-' + se.sc.charAt(0) + '">' + escHtml(se.sc) + '</span>×' + se.count;
			}
			if (statusEntries.length > 4) breakdownHtml += ' …';
			breakdownHtml += '</span>';
			var statusAttr = statusEntries.map(function(se) { return se.sc; }).join(' ');
			var portEntries = Object.keys(row.ports || {}).sort(function(a, b) { return Number(a) - Number(b); });
			var portAttr = portEntries.join(' ');
			var portHtml = portEntries.map(function(p) {
				return '<span class="port-badge port-' + escHtml(p) + '">' + escHtml(p) + '</span>';
			}).join(' ');
			var actionCell = wl ? '<td class="col-action"></td>' : (banned ? '<td class="col-action"><span class="jail-tag jail-tag-banned">BAN済</span></td>' : '<td class="col-action"><button class="btn-ban btn-sm" onclick="event.stopPropagation(); this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>');
			html += '<tr data-ip="' + ipEsc + '" data-country="' + escHtml((row.flag || '').replace(/<[^>]*>/g, '').trim()) + '" data-status-summary="' + escHtml(statusAttr) + '" data-port="' + escHtml(portAttr) + '" data-wl="' + (wl ? '1' : '0') + '" data-banned="' + (banned ? '1' : '0') + '"' + (KNOWN_IPS && KNOWN_IPS[row.ip] ? ' data-known="1"' : '')
				+ loginHistoryRowToggleAttrs('detail', 'renderNginxLogDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')')
				+ '>';
			html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="nginx"' + (disableCb ? ' disabled' : '') + '></td>';
			html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(row.ip) + '</td>';
			html += '<td class="col-country nowrap">' + escHtml(row.flag) + '</td>';
			html += '<td class="col-count">' + row.total.toLocaleString() + '</td>';
			html += '<td class="col-port nowrap">' + portHtml + '</td>';
			html += '<td class="col-status-summary">' + breakdownHtml + '</td>';
			html += '<td class="col-first nowrap">' + escHtml(formatDisplayDateTime(row.first_time, '')) + '</td>';
			html += '<td class="col-last nowrap">' + escHtml(formatDisplayDateTime(row.last_time, '')) + '</td>';
			html += actionCell + '</tr>';
		}

		html += '</tbody></table></div></form>';
		content.innerHTML = html;
		var thead = content.querySelector('thead');
		if (thead) {
			var countryOptions = countryList.map(function(c) { return { value: c, label: c }; });
			var statusCodeOptions = statusCodeList.map(function(sc) { return { value: sc, label: sc }; });
			var portOptions = portList.map(function(p) { return { value: p, label: p }; });
			var filterRow = createFilterHeaderRow([
				{ type: 'checkbox', colClass: 'cb-col' },
				{ type: 'custom', colClass: 'col-ip', content: buildIpFilterCell(monitorIpFilterOpts('sec-nginx-log', {wl:false,wlm:false,wla:false,ban:true,known:true})) },
				{ type: 'select', colClass: 'col-country', dataFilter: 'country', options: [{ value: '', label: '国' }].concat(countryOptions) },
				{ type: 'empty', colClass: 'col-count' },
				{ type: 'select', colClass: 'col-port', dataFilter: 'port', dataFilterPartial: '1', options: [{ value: '', label: 'ポート' }].concat(portOptions) },
				{ type: 'select', colClass: 'col-status-summary', dataFilter: 'status-summary', dataFilterPartial: '1', options: [{ value: '', label: 'ステータス内訳' }].concat(statusCodeOptions) },
				{ type: 'empty', colClass: 'col-first' },
				{ type: 'empty', colClass: 'col-last' },
				{ type: 'count', colClass: 'col-action' }
			]);
			thead.insertBefore(filterRow, thead.querySelector('tr'));
		}
		initBulkBan('nginx', content);
		autoInitCardFromDataset(content.closest('section.card'), { total: summaryRows.length });
		setupCardFilter(content.querySelector('.thead-filter-row'), content);
		restoreFilterState(content, getViewFilter(content, 'summary'));
		addRowNumbers(content);
	}

	function renderNginxLogDetail(content, filterIp) {
		saveCurrentViewFilter(content);
		var state = content && content.__nginxLogState ? content.__nginxLogState : null;
		var allLogs = state && state.logs ? state.logs : [];
		var flags = state && state.flags ? state.flags : {};
		var rate = state ? state.rate : null;
		if (!allLogs.length) { content.innerHTML = '<p class="empty">アクセスログがありません</p>'; return; }

		var logs = filterIp ? allLogs.filter(function(nr) { return nr.ip === filterIp; }) : allLogs;

		var countrySet = {};
		var countrySource = filterIp ? logs : allLogs;
		for (var ci = 0; ci < countrySource.length; ci++) {
			var c = flags[countrySource[ci].ip];
			if (c) countrySet[c] = true;
		}
		var countryList = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
		var countryOptions = countryList.map(function(c) { return { value: c, label: c }; });

		var portSet = {};
		for (var pi = 0; pi < logs.length; pi++) {
			var p = logs[pi].port;
			if (p) portSet[p] = true;
		}
		var portList = Object.keys(portSet).sort(function(a, b) { return Number(a) - Number(b); });
		var portOptions = portList.map(function(p) { return { value: p, label: p }; });

		var csrfToken = getCsrfToken();
		var html = renderNginxRateStats(rate);
		html += cardViewToggle(
			'detail',
			'renderNginxLogSummary(this.closest(\'.async-content\'))',
			'renderNginxLogDetail(this.closest(\'.async-content\'), null)'
		);
		if (filterIp) {
			html += '<div class="nc-filter-bar"><span class="nc-filter-badge">IP: ' + escHtml(filterIp) + '</span><button class="btn-secondary btn-sm" onclick="renderNginxLogDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button></div>';
		}
		html += '<form method="post" data-bulk-ban="nginx" data-bulk-ban-url="?api=bulk_ban"><input type="hidden" name="csrf_token" value="' + escHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="nginx"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="nginx"> 全選択</label><span class="bulk-ban-count" data-count="nginx">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nginx" disabled>選択したIPをBAN</button></div>';
		html += '<div class="table-scroll"><table class="nginx-log-table log-table"><col style="width:28px"><thead>';
		html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th class="col-time">日時</th><th class="col-port">ポート</th><th class="col-request">リクエスト</th><th class="col-status">ステータス</th><th class="col-size">サイズ</th><th class="col-action"></th></tr>';
		html += '</thead><tbody>';

		for (var i = 0; i < logs.length; i++) {
			var nr = logs[i];
			var wl = isWhitelisted(nr.ip);
			var flag = flags[nr.ip] || '';
			var ipEsc = escHtml(nr.ip);
			html += '<tr data-ip="' + ipEsc + '" data-country="' + escHtml(flag) + '" data-status="' + (nr.status ? nr.status.charAt(0) : '') + '" data-port="' + escHtml(nr.port || '') + '" data-wl="' + (wl ? '1' : '0') + '" data-banned="' + (BANNED_IPS[nr.ip] ? '1' : '0') + '"' + (KNOWN_IPS && KNOWN_IPS[nr.ip] ? ' data-known="1"' : '')
				+ loginHistoryRowToggleAttrs('summary', 'renderNginxLogSummary(this.closest(\'.async-content\'))')
				+ '>';
			html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="nginx"' + (wl ? ' disabled' : '') + '></td>';
			html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(nr.ip) + '</td>';
			html += '<td class="col-country nowrap">' + escHtml(flag) + '</td>';
			html += '<td class="col-time nowrap">' + escHtml(formatDisplayDateTime(nr.time, '')) + '</td>';
			html += '<td class="col-port nowrap">' + (nr.port ? '<span class="port-badge port-' + escHtml(nr.port) + '">' + escHtml(nr.port) + '</span>' : '') + '</td>';
			html += '<td class="col-request"><code class="nginx-request-code" title="' + escHtml(nr.request) + '" data-full-request="' + escHtml(nr.request) + '">' + escHtml(nr.request) + '</code></td>';
			html += '<td class="col-status"><span class="sc sc-' + (nr.status ? nr.status.charAt(0) : '') + '">' + escHtml(nr.status) + '</span></td>';
			html += '<td class="col-size nowrap">' + Number(nr.size).toLocaleString() + ' B</td>';
			html += (wl ? '<td class="col-action"></td>' : (BANNED_IPS[nr.ip] ? '<td class="col-action"><span class="jail-tag jail-tag-banned">BAN済</span></td>' : '<td class="col-action"><button class="btn-ban btn-sm" onclick="event.stopPropagation(); this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>'));
			html += '</tr>';
		}
		html += '</tbody></table></div></form>';
		content.innerHTML = html;
		var thead = content.querySelector('thead');
		if (thead) {
			var filterRow = createFilterHeaderRow([
				{ type: 'checkbox', colClass: 'cb-col' },
				{ type: 'custom', colClass: 'col-ip', content: buildIpFilterCell(monitorIpFilterOpts('sec-nginx-log', {wl:false,wlm:false,wla:false,ban:true,known:true})) },
				{ type: 'select', colClass: 'col-country', dataFilter: 'country', options: [{ value: '', label: '国絞り込み' }].concat(countryOptions) },
				{ type: 'empty', colClass: 'col-time' },
				{ type: 'select', colClass: 'col-port', dataFilter: 'port', options: [{ value: '', label: 'ポート' }].concat(portOptions) },
				{ type: 'empty', colClass: 'col-request' },
				{ type: 'select', colClass: 'col-status', dataFilter: 'status', options: [{ value: '', label: '全ステータス' }, { value: '2', label: '2xx' }, { value: '3', label: '3xx' }, { value: '4', label: '4xx' }, { value: '5', label: '5xx' }] },
				{ type: 'empty', colClass: 'col-size' },
				{ type: 'count', colClass: 'col-action' }
			]);
			thead.insertBefore(filterRow, thead.querySelector('tr'));
		}
		initBulkBan('nginx', content);
		autoInitCardFromDataset(content.closest('section.card'), { total: logs.length });
		setupCardFilter(content.querySelector('.thead-filter-row'), content);
		restoreFilterState(content, getViewFilter(content, 'detail'));
		addRowNumbers(content);
	}

	function renderNginxLog(content, data) {
		content.__nginxLogState = { logs: data.logs || [], flags: data.flags || {}, rate: data.rate || null };
		renderNginxLogSummary(content);
	}

	window.renderNginxLog = renderNginxLog;
	window.renderNginxLogSummary = renderNginxLogSummary;
	window.renderNginxLogDetail = renderNginxLogDetail;
	window.renderNginxRateStats = renderNginxRateStats;
	window.monitorIpFilterOpts = monitorIpFilterOpts;

	CardRegistry.register('NginxLog', {
		cardKey: 'NGINX_LOG',
		fallbackId: 'sec-nginx-log',
		apiFallback: 'nginx_log',
		render: function(el, d) { renderNginxLog(el, d); }
	});
})();
