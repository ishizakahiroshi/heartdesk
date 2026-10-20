// heartdesk カード: 脅威スコア (sec-threat-score)
// Phase 2b (C3): monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / isWhitelisted / ipBadges / openIpModal /
//       getCsrfToken / createFilterHeaderRow / buildIpFilterCell /
//       setupCardFilter / initBulkBan / autoInitCardFromDataset /
//       addRowNumbers / formatDisplayDateTime / threatWeightLabel、
//       card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function drawThreatScoreChart(entries, config) {
		if (!entries || entries.length < 2) {
			return '<p class="empty threat-chart-empty">グラフを表示するにはデータが2件以上必要です（次回の5分cron実行後から蓄積が始まります）</p>';
		}
		var thresholds = (config && config.thresholds) ? config.thresholds : { warning: 30, danger: 70 };
		var scores = entries.map(function(e) { return e.score; });
		var maxScore = Math.max.apply(null, scores) || 1;
		var W = 700, H = 130;
		var PAD = { top: 14, right: 16, bottom: 30, left: 44 };
		var chartW = W - PAD.left - PAD.right;
		var chartH = H - PAD.top - PAD.bottom;
		var yMax = maxScore * 1.15;
		function xPos(i) { return PAD.left + (entries.length > 1 ? i / (entries.length - 1) : 0.5) * chartW; }
		function yPos(v) { return PAD.top + chartH - (v / yMax) * chartH; }
		var svg = '<svg width="100%" viewBox="0 0 ' + W + ' ' + H + '" class="threat-score-chart">';
		svg += '<rect x="' + PAD.left + '" y="' + PAD.top + '" width="' + chartW + '" height="' + chartH + '" fill="rgba(255,255,255,0.03)" rx="2"/>';
		var warnY = yPos(thresholds.warning);
		var dangerY = yPos(thresholds.danger);
		if (thresholds.warning <= yMax) {
			svg += '<line x1="' + PAD.left + '" y1="' + warnY + '" x2="' + (W - PAD.right) + '" y2="' + warnY + '" stroke="#e67e22" stroke-width="1" stroke-dasharray="4,3" opacity="0.7"/>';
			svg += '<text x="' + (PAD.left + 3) + '" y="' + (warnY - 3) + '" fill="#e67e22" font-size="8" opacity="0.8">警告 ' + thresholds.warning + '</text>';
		}
		if (thresholds.danger <= yMax) {
			svg += '<line x1="' + PAD.left + '" y1="' + dangerY + '" x2="' + (W - PAD.right) + '" y2="' + dangerY + '" stroke="#e74c3c" stroke-width="1" stroke-dasharray="4,3" opacity="0.7"/>';
			svg += '<text x="' + (PAD.left + 3) + '" y="' + (dangerY - 3) + '" fill="#e74c3c" font-size="8" opacity="0.8">危険 ' + thresholds.danger + '</text>';
		}
		var points = entries.map(function(e, i) { return xPos(i) + ',' + yPos(e.score); }).join(' ');
		svg += '<polyline points="' + points + '" fill="none" stroke="#3498db" stroke-width="2" stroke-linejoin="round"/>';
		entries.forEach(function(e, i) {
			var cx = xPos(i), cy = yPos(e.score);
			var color = e.score >= thresholds.danger ? '#e74c3c' : (e.score >= thresholds.warning ? '#e67e22' : '#27ae60');
			svg += '<circle cx="' + cx + '" cy="' + cy + '" r="3" fill="' + color + '" stroke="#1a1a2e" stroke-width="1"/>';
		});
		var labelStep = Math.max(1, Math.floor(entries.length / 6));
		entries.forEach(function(e, i) {
			if (i === 0 || i === entries.length - 1 || i % labelStep === 0) {
				var lx = xPos(i);
				var anchor = (i === 0) ? 'start' : (i === entries.length - 1 ? 'end' : 'middle');
				var label = e.ts ? e.ts.substring(5, 16).replace('T', ' ') : '';
				svg += '<text x="' + lx + '" y="' + (H - 4) + '" fill="#888" font-size="8" text-anchor="' + anchor + '">' + escHtml(label) + '</text>';
			}
		});
		svg += '<text x="' + (PAD.left - 5) + '" y="' + (PAD.top + 5) + '" fill="#888" font-size="9" text-anchor="end">' + Math.round(yMax) + '</text>';
		svg += '<text x="' + (PAD.left - 5) + '" y="' + (PAD.top + chartH) + '" fill="#888" font-size="9" text-anchor="end">0</text>';
		var last = entries[entries.length - 1];
		var lx = xPos(entries.length - 1), ly = yPos(last.score);
		var scoreColor = last.score >= thresholds.danger ? '#e74c3c' : (last.score >= thresholds.warning ? '#e67e22' : '#27ae60');
		svg += '<text x="' + (lx - 4) + '" y="' + (ly - 6) + '" fill="' + scoreColor + '" font-size="10" font-weight="bold" text-anchor="end">' + last.score + '</text>';
		svg += '</svg>';
		return svg;
	}

	function renderThreatScore(el, d) {
		if (!d || !d.scores) { el.innerHTML = '<p>データなし</p>'; return; }
		el.__threatState = d;
		renderThreatSummary(el);
	}

	function renderThreatSummary(el) {
		var d = el.__threatState;
		if (!d || !d.scores) { el.innerHTML = '<p>データなし</p>'; return; }
		var flags = d.flags || {};
		var config = d.config || {};
		var weights = config.weights || {};
		var warn   = config.thresholds ? config.thresholds.warning : 50;
		var danger = config.thresholds ? config.thresholds.danger  : 100;
		if (d.scores.length === 0) { el.innerHTML = '<p class="empty">脅威スコアデータがありません</p>'; return; }

		var maxScore = Math.max.apply(null, d.scores.map(function(s) { return s.score; })) || 1;

		var countrySet = {}, countryList = [];
		d.scores.forEach(function(s) {
			var cname = (flags[s.ip] || '').replace(/<[^>]*>/g, '').trim();
			if (cname && !countrySet[cname]) { countrySet[cname] = 1; countryList.push(cname); }
		});
		countryList.sort();

		var csrfToken = (typeof getCsrfToken === 'function') ? getCsrfToken() : '';
		var html = '<form method="post" data-bulk-ban="threat" data-bulk-ban-url="?api=bulk_ban">';
		html += '<input type="hidden" name="csrf_token" value="' + escHtml(csrfToken) + '">';
		html += '<input type="hidden" name="ban_section" value="threat">';
		html += '<div class="bulk-ban-bar">';
		html += '<label class="bulk-select-all"><input type="checkbox" data-select-all="threat"> 全選択</label>';
		html += '<span class="bulk-ban-count" data-count="threat">0件選択中</span>';
		html += '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="threat" disabled>選択したIPをBAN</button>';
		html += '</div>';

		html += '<table class="log-table"><thead>';
		html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th>';
		html += '<th>スコア</th>';
		html += '<th class="score-detail">' + threatWeightLabel('スキャン', 'scan_hit', weights, 'ハニーポットへのアクセス（全トリガー）') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('高危険', 'scan_critical', weights, '高危険スキャン（backdoor / query_string）') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('認証', 'auth_fail', weights, 'Basic認証失敗（Nginxアクセスログ）') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('NC', 'nc_fail', weights, 'Nextcloudログイン失敗') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('4XX', 'nc_4xx', weights, 'Nextcloud 4xxエラー') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('BAN', 'already_banned', weights, '既BANのIPによるアクセス（recidive対象）') + '</th>';
		html += '<th class="score-detail">' + threatWeightLabel('海外', 'foreign_ip', weights, '海外IP（ipset japan_ips 非登録）') + '</th>';
		html += '<th class="score-detail">更新</th><th></th></tr>';
		html += '</thead><tbody>';

		d.scores.forEach(function(s) {
			var wl = (typeof isWhitelisted === 'function') ? isWhitelisted(s.ip) : false;
			var bannedJail = (typeof BANNED_IPS !== 'undefined' && BANNED_IPS) ? (BANNED_IPS[s.ip] || '') : '';
			var isBanned = s.is_banned || !!bannedJail;
			var disableCb = wl || isBanned;
			var ipEsc = escHtml(s.ip);
			var pct = Math.round(s.score / maxScore * 100);
			var colorClass = s.score >= danger ? 'score-danger' : (s.score >= warn ? 'score-warning' : 'score-ok');
			var countryText = (flags[s.ip] || '').replace(/<[^>]*>/g, '').trim();
			var isKnown = (typeof KNOWN_IPS !== 'undefined' && KNOWN_IPS) ? !!KNOWN_IPS[s.ip] : false;
			var scanCrit = s.scan_criticals !== undefined ? s.scan_criticals : 0;
			var isHighRisk = !wl && !isBanned && scanCrit === 0 && s.score >= danger;

			html += '<tr class="ts-row' + (isHighRisk ? ' ts-row-high-risk' : '') + '" style="cursor:pointer" title="クリックして推移グラフを表示"'
				+ ' data-ip="' + ipEsc + '"'
				+ ' data-country="' + escHtml(countryText) + '"'
				+ ' data-foreign="' + (s.is_foreign ? '海外' : '国内') + '"'
				+ ' data-wl="' + (wl ? '1' : '0') + '"'
				+ (isBanned ? ' data-banned="1"' : '')
				+ (isKnown ? ' data-known="1"' : '') + '>';
			html += '<td class="cb-col" onclick="event.stopPropagation();">'
				+ '<input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="threat"' + (disableCb ? ' disabled' : '') + '></td>';
			html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">'
				+ ipEsc + '</code>' + (typeof ipBadges === 'function' ? ipBadges(s.ip) : '') + '</td>';
			html += '<td class="col-country">' + escHtml(flags[s.ip] || '-') + '</td>';
			html += '<td><div class="score-bar-outer"><div class="score-bar-bg">'
				+ '<div class="score-bar-fill ' + colorClass + '" style="width:' + pct + '%"></div>'
				+ '</div><span class="score-value">' + s.score + '</span></div></td>';
			html += '<td class="score-detail">' + escHtml(s.scan_hits) + '</td>';
			html += '<td class="score-detail">'
				+ (scanCrit > 0 ? '<span style="color:#e74c3c;font-weight:600">' + scanCrit + '</span>' : '0') + '</td>';
			html += '<td class="score-detail">' + escHtml(s.auth_fails) + '</td>';
			html += '<td class="score-detail">' + escHtml(s.nc_fails) + '</td>';
			html += '<td class="score-detail">' + escHtml(s.nc_4xx || 0) + '</td>';
			html += '<td class="score-detail">' + (isBanned ? '<span class="ban-badge">BAN</span>' : '-') + '</td>';
			html += '<td class="score-detail">' + (s.is_foreign ? '<span class="foreign-badge">海外</span>' : '-') + '</td>';
			var ts = s.timestamp || '';
			html += '<td class="score-detail nowrap" style="font-size:0.78rem">'
				+ (typeof formatDisplayDateTime === 'function' ? formatDisplayDateTime(ts, '-') : escHtml(ts || '-')) + '</td>';
			if (wl) {
				html += '<td></td>';
			} else if (isBanned) {
				html += '<td onclick="event.stopPropagation();"><span class="jail-tag jail-tag-banned">BAN済</span></td>';
			} else {
				html += '<td onclick="event.stopPropagation();">';
				if (isHighRisk) {
					html += '<button class="btn-warning btn-sm ts-dismiss-btn" data-ip="' + ipEsc + '" title="24時間このIPを要確認ハイライトから除外">24h無視</button> ';
				}
				html += '<button class="btn-ban btn-sm ts-ban-btn" data-ip="' + ipEsc + '">BAN追加</button></td>';
			}
			html += '</tr>';
		});

		html += '</tbody></table></form>';
		el.innerHTML = html;
		var thead = el.querySelector('thead');
		if (thead && typeof setupCardFilter === 'function') {
			var countryOptions = countryList.map(function(c) { return { value: c, label: c }; });
			var filterRow = createFilterHeaderRow([
				{ type: 'checkbox', colClass: 'cb-col' },
				{ type: 'custom', colClass: 'col-ip', content: buildIpFilterCell(monitorIpFilterOpts('sec-threat-score', {wl:false,wlm:false,wla:false,ban:false,known:false})) },
				{ type: 'select', colClass: 'col-country', dataFilter: 'country', options: [{ value: '', label: '全て' }].concat(countryOptions) },
				{ type: 'empty', colSpan: 1 },
				{ type: 'empty', colSpan: 6 },
				{ type: 'select', colClass: 'score-detail', dataFilter: 'foreign', options: [{ value: '', label: '全て' }, { value: '海外', label: '海外' }, { value: '国内', label: '国内' }] },
				{ type: 'empty', colClass: 'score-detail' },
				{ type: 'count' }
			]);
			thead.appendChild(filterRow);
		}
		if (typeof initBulkBan === 'function') initBulkBan('threat', el);
		autoInitCardFromDataset(el.closest('section.card'), { total: d.scores.length });
		if (typeof setupCardFilter === 'function') setupCardFilter(el.querySelector('.thead-filter-row'), el);
		addRowNumbers(el);

		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';

		// td の stopPropagation が委譲をブロックするため各ボタンに直接バインド
		el.querySelectorAll('.ts-dismiss-btn').forEach(function(dismissBtn) {
			dismissBtn.addEventListener('click', function(ev) {
				ev.stopPropagation();
				var dIp = dismissBtn.getAttribute('data-ip');
				if (!dIp) return;
				dismissBtn.disabled = true;
				var dismissURL = (typeof monitorApiURL === 'function') ? monitorApiURL('highscore_dismiss') : (appBase + '/?api=highscore_dismiss');
				fetch(dismissURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: 'ip=' + encodeURIComponent(dIp)
				}).then(function(r) { return r.json(); })
				.then(function(res) {
					if (res.ok) {
						var tr = dismissBtn.closest('tr');
						if (tr) {
							tr.classList.remove('ts-row-high-risk');
							dismissBtn.parentNode.removeChild(dismissBtn);
						}
					} else {
						alert('エラー: ' + (res.message || '不明'));
						dismissBtn.disabled = false;
					}
				}).catch(function() {
					alert('エラーが発生しました');
					dismissBtn.disabled = false;
				});
			});
		});

		el.querySelectorAll('.ts-ban-btn').forEach(function(banBtn) {
			banBtn.addEventListener('click', function(ev) {
				ev.stopPropagation();
				var ip = banBtn.getAttribute('data-ip');
				if (!ip) return;
				if (typeof isWhitelisted === 'function' && isWhitelisted(ip)) {
					alert('ホワイトリストIPのためBANできません');
					return;
				}
				if (!confirm(ip + ' をBANしますか？')) return;
				banBtn.disabled = true;
				var banURL = (typeof monitorApiURL === 'function') ? monitorApiURL('fail2ban_ban') : (appBase + '/?api=fail2ban_ban');
				fetch(banURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: 'ip=' + encodeURIComponent(ip)
				}).then(function(r) { return r.json(); })
				.then(function(res) {
					if (res.ok) {
						var tr = banBtn.closest('tr');
						if (tr) {
							banBtn.parentNode.innerHTML = '<span class="jail-tag jail-tag-banned">BAN済</span>';
							tr.setAttribute('data-banned', '1');
							if (typeof BANNED_IPS !== 'undefined') BANNED_IPS[ip] = 'recidive';
						}
					} else {
						alert('エラー: ' + (res.message || '不明'));
						banBtn.disabled = false;
					}
				}).catch(function() {
					alert('エラーが発生しました');
					banBtn.disabled = false;
				});
			});
		});

		el.addEventListener('click', function handler(ev) {
			var row = ev.target.closest('.ts-row');
			if (!row) return;
			var ip = row.getAttribute('data-ip');
			if (!ip) return;
			el.removeEventListener('click', handler);
			renderThreatDetail(el, ip);
		});
	}

	function renderThreatDetail(el, filterIp) {
		var d = el.__threatState;
		if (!d) return;
		if (!filterIp) { renderThreatSummary(el); return; }
		var config = d.config || { thresholds: { warning: 50, danger: 100 } };
		var flags = d.flags || {};
		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
		var ipEsc = escHtml(filterIp);
		var wl = (typeof isWhitelisted === 'function') ? isWhitelisted(filterIp) : false;
		var bannedJail = (typeof BANNED_IPS !== 'undefined' && BANNED_IPS) ? (BANNED_IPS[filterIp] || '') : '';
		var banDisabled = wl || !!bannedJail;

		var headerHtml = '<div class="nc-view-toggle"><button class="btn-secondary btn-sm ts-back-btn">集計</button></div>';
		headerHtml += '<div class="nc-filter-bar">';
		headerHtml += '<code class="ip-clickable" onclick="openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>';
		headerHtml += (typeof ipBadges === 'function' ? ipBadges(filterIp) : '');
		var detailFlag = flags[filterIp] || '';
		if (detailFlag) headerHtml += '<span class="threat-detail-country">' + detailFlag + '</span>';
		headerHtml += '<button type="button" class="btn-danger btn-sm ts-detail-ban-btn"' + (banDisabled ? ' disabled' : '') + '>BAN追加</button>';
		headerHtml += '<button type="button" class="btn-warning btn-sm ts-detail-unban-btn"' + (wl ? ' disabled' : '') + '>BAN解除</button>';
		headerHtml += '<span class="ts-detail-msg ban-list-msg"></span>';
		headerHtml += '<button class="btn-secondary btn-sm ts-back-btn">× 閉じる</button>';
		headerHtml += '</div>';

		el.innerHTML = headerHtml + '<p class="section-loading">推移データを読み込み中...</p>';
		setupThreatDetailBanEvents(el, filterIp);

		fetch(appBase + '/?api=threat_score_history&ip=' + encodeURIComponent(filterIp))
			.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
			.then(function(data) {
				var entries = data.entries || [];
				var html = headerHtml;
				html += drawThreatScoreChart(entries, config);
				html += '<section class="threat-req-section"><p class="section-loading">イベント履歴を読み込み中...</p></section>';
				el.innerHTML = html;
				setupThreatDetailBanEvents(el, filterIp);
				var reqSection = el.querySelector('.threat-req-section');
				fetch(appBase + '/?api=threat_event_history&ip=' + encodeURIComponent(filterIp))
					.then(function(r2) { if (!r2.ok) throw new Error('HTTP ' + r2.status); return r2.json(); })
					.then(function(d2) {
						var events = d2.events || [];
						if (!reqSection) return;
						if (events.length === 0) { reqSection.innerHTML = '<p class="no-data">スコア加算イベントなし</p>'; return; }
						var catClass = { 'SSH': 'type-ssh', 'スキャン': 'type-honeypot', '高危険': 'type-critical', '認証': 'type-auth', 'NC': 'type-nc', '4XX': 'type-nc4xx' };
						var rHtml = '<div class="threat-history-meta">イベント履歴（' + events.length + ' 件）</div>';
						rHtml += '<table class="log-table threat-event-table"><thead><tr>';
						rHtml += '<th class="score-detail nowrap">時刻</th>';
						rHtml += '<th class="score-detail">カテゴリ</th>';
						rHtml += '<th class="score-detail col-count">+スコア</th>';
						rHtml += '<th class="score-detail col-count">累計</th>';
						rHtml += '<th>詳細</th>';
						rHtml += '</tr></thead><tbody>';
						events.forEach(function(ev) {
							var cls = catClass[ev.category] || 'type-honeypot';
							rHtml += '<tr>';
							rHtml += '<td class="score-detail datetime-cell nowrap">' + escHtml(ev.ts) + '</td>';
							rHtml += '<td class="score-detail"><span class="req-type-badge ' + cls + '">' + escHtml(ev.category) + '</span></td>';
							rHtml += '<td class="score-detail col-count">+' + ev.score_delta + '</td>';
							rHtml += '<td class="score-detail col-count">' + ev.cumulative + '</td>';
							var uaBadge = ev.ua_label ? '<span class="device-badge device-' + escHtml(ev.ua_device || 'unknown') + '">' + escHtml(ev.ua_label) + '</span> ' : '';
							rHtml += '<td class="req-detail-cell">' + uaBadge + '<code>' + escHtml(ev.detail) + '</code></td>';
							rHtml += '</tr>';
						});
						rHtml += '</tbody></table>';
						reqSection.innerHTML = rHtml;
						addRowNumbers(reqSection);
					})
					.catch(function() { if (reqSection) reqSection.innerHTML = '<p class="section-error">イベント履歴の読み込みに失敗しました</p>'; });
			})
			.catch(function(err) {
				el.innerHTML = headerHtml + '<p class="section-error">推移データの読み込みに失敗しました: ' + escHtml(err.message) + '</p>';
				setupThreatDetailBanEvents(el, filterIp);
			});
	}

	function setupThreatDetailBanEvents(el, ip) {
		var appBase = (typeof HD_APP_BASE !== 'undefined') ? HD_APP_BASE : '/monitor';
		var banBtn = el.querySelector('.ts-detail-ban-btn');
		var unbanBtn = el.querySelector('.ts-detail-unban-btn');
		var msg = el.querySelector('.ts-detail-msg');

		el.querySelectorAll('.ts-back-btn').forEach(function(btn) {
			btn.addEventListener('click', function() { renderThreatSummary(el); });
		});

		if (banBtn) {
			banBtn.addEventListener('click', function() {
				if (typeof isWhitelisted === 'function' && isWhitelisted(ip)) {
					alert('ホワイトリストIPのためBANできません');
					return;
				}
				if (!confirm(ip + ' をBANしますか？')) return;
				banBtn.disabled = true;
				if (msg) { msg.textContent = '処理中...'; msg.className = 'ts-detail-msg ban-list-msg'; }
				var banURL = (typeof monitorApiURL === 'function') ? monitorApiURL('fail2ban_ban') : (appBase + '/?api=fail2ban_ban');
				fetch(banURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: 'ip=' + encodeURIComponent(ip)
				}).then(function(r) { return r.json(); })
				.then(function(res) {
					var m = el.querySelector('.ts-detail-msg') || msg;
					var bb = el.querySelector('.ts-detail-ban-btn') || banBtn;
					if (res.ok) {
						if (m) { m.textContent = 'BAN完了'; m.className = 'ts-detail-msg ban-list-msg success'; }
						bb.disabled = true;
						if (typeof BANNED_IPS !== 'undefined') BANNED_IPS[ip] = 'recidive';
					} else {
						if (m) { m.textContent = 'エラー: ' + (res.message || '不明'); m.className = 'ts-detail-msg ban-list-msg error'; }
						bb.disabled = false;
					}
				}).catch(function() {
					var m = el.querySelector('.ts-detail-msg') || msg;
					var bb = el.querySelector('.ts-detail-ban-btn') || banBtn;
					if (m) { m.textContent = 'エラーが発生しました'; m.className = 'ts-detail-msg ban-list-msg error'; }
					bb.disabled = false;
				});
			});
		}

		if (unbanBtn) {
			unbanBtn.addEventListener('click', function() {
				if (!confirm(ip + ' を全jailから解除しますか？')) return;
				unbanBtn.disabled = true;
				if (msg) { msg.textContent = '処理中...'; msg.className = 'ts-detail-msg ban-list-msg'; }
				var unbanURL = (typeof monitorApiURL === 'function') ? monitorApiURL('fail2ban_unban') : (appBase + '/?api=fail2ban_unban');
				fetch(unbanURL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: 'ip=' + encodeURIComponent(ip)
				}).then(function(r) { return r.json(); })
				.then(function(res) {
					var m = el.querySelector('.ts-detail-msg') || msg;
					var ub = el.querySelector('.ts-detail-unban-btn') || unbanBtn;
					if (res.ok) {
						if (m) { m.textContent = '解除完了'; m.className = 'ts-detail-msg ban-list-msg success'; }
						if (typeof BANNED_IPS !== 'undefined') delete BANNED_IPS[ip];
					} else {
						if (m) { m.textContent = 'エラー: ' + (res.message || '不明'); m.className = 'ts-detail-msg ban-list-msg error'; }
					}
					ub.disabled = false;
				}).catch(function() {
					var m = el.querySelector('.ts-detail-msg') || msg;
					var ub = el.querySelector('.ts-detail-unban-btn') || unbanBtn;
					if (m) { m.textContent = 'エラーが発生しました'; m.className = 'ts-detail-msg ban-list-msg error'; }
					ub.disabled = false;
				});
			});
		}
	}

	window.drawThreatScoreChart = drawThreatScoreChart;
	window.renderThreatScore = renderThreatScore;
	window.renderThreatSummary = renderThreatSummary;
	window.renderThreatDetail = renderThreatDetail;
	window.setupThreatDetailBanEvents = setupThreatDetailBanEvents;

	CardRegistry.register('ThreatScore', {
		cardKey: 'THREAT_SCORE',
		fallbackId: 'sec-threat-score',
		apiFallback: 'threat_score',
		render: function(el, d) { renderThreatScore(el, d); }
	});
})();
