// =============================================================================
// shared.js — 共通UI/ユーティリティ
// =============================================================================

// --- Display constants ---
var ROW_LIMIT_DEFAULT = 20; // テーブル折りたたみ表示件数（initRowLimit のデフォルト）

// --- Cross-app globals (safe defaults) ---
if (typeof window.BANNED_IPS === 'undefined') {
	window.BANNED_IPS = {};
}
if (typeof window.WHITELIST_IPS_PHP === 'undefined') {
	window.WHITELIST_IPS_PHP = [];
}
if (typeof window.SSH_ALLOWED_IPS === 'undefined') {
	window.SSH_ALLOWED_IPS = [];
}
if (typeof window.KNOWN_IPS === 'undefined') {
	window.KNOWN_IPS = {};
}
if (typeof window.IP_TYPE_LABELS === 'undefined') {
	window.IP_TYPE_LABELS = {
		wl: { short: 'WL', full: 'WL（サーバー）' },
		wlm: { short: 'WLM', full: 'WLM（フルアクセス）' },
		wla: { short: 'WLA', full: 'WLA（Adminのみ）' },
		known: { short: '既知', full: '既知' }
	};
}
if (typeof window.ipTypeShortLabel !== 'function') {
	window.ipTypeShortLabel = function(type) {
		var labels = window.IP_TYPE_LABELS || {};
		var entry = labels[type] || {};
		return entry.short || entry.Short || type || '';
	};
}
if (typeof window.ipTypeFullLabel !== 'function') {
	window.ipTypeFullLabel = function(type) {
		var labels = window.IP_TYPE_LABELS || {};
		var entry = labels[type] || {};
		return entry.full || entry.Full || entry.short || entry.Short || type || '';
	};
}
if (typeof window.isWhitelisted !== 'function') {
	window.isWhitelisted = function(ip) {
		if (!ip) return false;
		var wl = (typeof window.WHITELIST_IPS_PHP !== 'undefined' && window.WHITELIST_IPS_PHP) ? window.WHITELIST_IPS_PHP : [];
		if (wl.indexOf(ip) !== -1) return true;
		var serverIps = (typeof window.SERVER_IPS !== 'undefined' && window.SERVER_IPS) ? window.SERVER_IPS : [];
		if (serverIps.indexOf(ip) !== -1) return true;
		var ssh = (typeof window.SSH_ALLOWED_IPS !== 'undefined' && window.SSH_ALLOWED_IPS) ? window.SSH_ALLOWED_IPS : [];
		return ssh.indexOf(ip) !== -1;
	};
}
if (typeof window.ipBadgeLabel !== 'function') {
	window.ipBadgeLabel = function(ip) {
		if (!ip) return '';
		if (typeof window.SERVER_IPS !== 'undefined' && Array.isArray(window.SERVER_IPS) && window.SERVER_IPS.indexOf(ip) !== -1) {
			return 'サーバー';
		}
		if (typeof window.SSH_ALLOWED_NAMES !== 'undefined' && window.SSH_ALLOWED_NAMES && window.SSH_ALLOWED_NAMES[ip]) {
			var name = window.SSH_ALLOWED_NAMES[ip];
			if (name === 'BAN除外') return 'サーバー';
			return name;
		}
		return '';
	};
}
if (typeof window.__heartdeskIsValidIP !== 'function') {
	window.__heartdeskIsValidIP = function(ip) {
		ip = (ip || '').trim();
		if (!ip) return false;
		if (ip.indexOf(':') !== -1) {
			try {
				return new URL('http://[' + ip + ']/').hostname === '[' + ip + ']';
			} catch (_e) {
				return false;
			}
		}
		var parts = ip.split('.');
		if (parts.length !== 4) return false;
		for (var i = 0; i < parts.length; i++) {
			if (!/^\d{1,3}$/.test(parts[i])) return false;
			var n = parseInt(parts[i], 10);
			if (n < 0 || n > 255) return false;
		}
		return true;
	};
}
if (typeof window.__heartdeskNormalizeIP !== 'function') {
	window.__heartdeskNormalizeIP = function(ip) {
		return (ip || '').trim().toLowerCase();
	};
}
if (typeof window.ipBadges !== 'function') {
	window.ipBadges = function(ip) {
		var html = '';
		var ipType = (window.SSH_ALLOWED_TYPES && window.SSH_ALLOWED_TYPES[ip]) || null;
		if (ipType === 'wlm') {
			var label = window.ipBadgeLabel ? window.ipBadgeLabel(ip) : '';
			html += ' <span class="wlm-badge">' + escapeHtml(window.ipTypeShortLabel('wlm')) + (label ? ' ' + escapeHtml(label) : '') + '</span>';
		} else if (ipType === 'wla') {
			var label = window.ipBadgeLabel ? window.ipBadgeLabel(ip) : '';
			html += ' <span class="wla-badge">' + escapeHtml(window.ipTypeShortLabel('wla')) + (label ? ' ' + escapeHtml(label) : '') + '</span>';
		} else if (ipType === 'known') {
			var label = window.ipBadgeLabel ? window.ipBadgeLabel(ip) : '';
			html += ' <span class="known-badge">' + escapeHtml(label || ip) + '</span>';
		} else if (window.isWhitelisted && window.isWhitelisted(ip)) {
			// WHITELIST_IPS（サーバーIP等）用のフォールバック
			var label = window.ipBadgeLabel ? window.ipBadgeLabel(ip) : '';
			html += ' <span class="wl-badge">' + escapeHtml(window.ipTypeShortLabel('wl')) + (label ? ' ' + escapeHtml(label) : '') + '</span>';
		} else if (window.KNOWN_IPS && window.KNOWN_IPS[ip]) {
			html += ' <span class="known-badge">' + escapeHtml(window.KNOWN_IPS[ip]) + '</span>';
		}
		if (window.BANNED_IPS && window.BANNED_IPS[ip]) html += ' <span class="ban-badge">BAN</span>';
		return html;
	};
}

function fadeOut(id, delay) {
	setTimeout(function() {
		var el = document.getElementById(id);
		if (el) {
			el.style.transition = 'opacity 0.5s';
			el.style.opacity = '0';
			setTimeout(function() { el.remove(); }, 500);
		}
	}, delay);
}

function normalizeCountText(text) {
	if (!text || text.indexOf('件') === -1) return text;
	var out = text.replace(/(\d[\d,]*)\s*\/\s*(\d[\d,]*)\s*件/g, function(_m, a, b) {
		return formatCount(a) + ' / ' + formatCount(b) + '件';
	});
	out = out.replace(/(\d[\d,]*)(?=\s*件(?:選択中|表示|中)?)/g, function(_m, n) {
		return formatCount(n);
	});
	return out;
}

function applyCountFormatting(root) {
	if (!root) return;
	var isElement = root.nodeType === 1;
	var isText = root.nodeType === 3;
	if (isText) {
		var parentTag = root.parentNode && root.parentNode.nodeName ? root.parentNode.nodeName.toLowerCase() : '';
		if (parentTag === 'script' || parentTag === 'style') return;
		var nextVal = normalizeCountText(root.nodeValue);
		if (nextVal !== root.nodeValue) root.nodeValue = nextVal;
		return;
	}
	if (!isElement) return;
	var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
	var node;
	while ((node = walker.nextNode())) {
		var tag = node.parentNode && node.parentNode.nodeName ? node.parentNode.nodeName.toLowerCase() : '';
		if (tag === 'script' || tag === 'style') continue;
		var val = normalizeCountText(node.nodeValue);
		if (val !== node.nodeValue) node.nodeValue = val;
	}
}

if (typeof window !== 'undefined') {
	window.applyCountFormatting = applyCountFormatting;
}

(function initCountFormattingObserver() {
	if (typeof window === 'undefined' || typeof MutationObserver === 'undefined') return;
	if (window.__countFormatterInitialized) return;
	window.__countFormatterInitialized = true;
	var busy = false;
	function run(root) {
		if (busy) return;
		busy = true;
		try {
			applyCountFormatting(root);
		} finally {
			busy = false;
		}
	}
	function boot() {
		if (!document.body) return;
		run(document.body);
		var observer = new MutationObserver(function(mutations) {
			mutations.forEach(function(mutation) {
				if (mutation.type === 'characterData') {
					run(mutation.target);
					return;
				}
				mutation.addedNodes.forEach(function(node) {
					run(node);
				});
			});
		});
		observer.observe(document.body, {
			childList: true,
			subtree: true,
			characterData: true
		});
	}
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', boot);
	} else {
		boot();
	}
})();

function getBarThresholds() {
	var t = (typeof BAR_THRESHOLDS !== 'undefined' && BAR_THRESHOLDS) ? BAR_THRESHOLDS : {};
	var warning = (typeof t.warning === 'number') ? t.warning : 50;
	var danger = (typeof t.danger === 'number') ? t.danger : 80;
	return { warning: warning, danger: danger };
}

function barColorClass(pct) {
	var val = parseFloat(pct);
	if (isNaN(val)) val = 0;
	var t = getBarThresholds();
	if (val >= t.danger) return 'danger';
	if (val >= t.warning) return 'warning';
	return 'ok';
}

function touchLastUpdated() {
	var el = document.getElementById('last-updated');
	if (!el) return;
	var now = formatDateTime(new Date());
	el.textContent = now;
	el.setAttribute('data-updated-at', now);
}

function isSameOriginRequest(input) {
	try {
		var rawUrl = '';
		if (typeof input === 'string') {
			rawUrl = input;
		} else if (input && typeof input.url === 'string') {
			rawUrl = input.url;
		}
		if (!rawUrl) return true;
		var u = new URL(rawUrl, window.location.origin);
		return u.origin === window.location.origin;
	} catch (e) {
		return true;
	}
}

(function initCsrfFetchWrapper() {
	if (typeof window === 'undefined' || typeof window.fetch !== 'function') return;
	if (window.__heartdeskFetchWrapped) return;
	window.__heartdeskFetchWrapped = true;
	var originalFetch = window.fetch.bind(window);

	window.fetch = function(input, init) {
		var opts = init ? Object.assign({}, init) : {};
		var method = String((opts.method || (input && input.method) || 'GET')).toUpperCase();
		if (method === 'POST' && isSameOriginRequest(input)) {
			var headers = new Headers(opts.headers || (input && input.headers ? input.headers : undefined));
			var csrfToken = getCsrfToken();
			if (csrfToken && !headers.has('X-CSRF-Token')) {
				headers.set('X-CSRF-Token', csrfToken);
			}
			if (!headers.has('X-Requested-With')) {
				headers.set('X-Requested-With', 'XMLHttpRequest');
			}
			opts.headers = headers;
		}
		return originalFetch(input, opts);
	};
})();

// ヒートマップ用の曜日ラベル（BAN / Honeypot 共通）
var HM_DAYS = ['月','火','水','木','金','土','日'];
if (typeof window !== 'undefined') {
	window.HM_DAYS = HM_DAYS;
}

// buildHeatmapTable — BAN/HP兼用ヒートマップHTMLビルダー
// jail   : BAN用jail名（非nullでBAN用セル、data-jail属性付与）
// trigger: HP用トリガー名（非nullでHP用セル、data-trigger属性付与、heatmap-cell-hp クラス追加）
// jail/trigger どちらも null の場合はクリック不可（表示のみ）
function buildHeatmapTable(hm, max, title, count, jail, color, unit, trigger) {
	var rgb = color || '231,76,60';
	var tipUnit = unit || 'BAN';
	var isHp = trigger != null;
	var countBadge = count != null ? ' <span class="heatmap-total">(' + escapeHtml(String(count)) + ' BAN)</span>' : '';
	var html = '<div class="heatmap-block">';
	html += '<div class="hm-title">' + escapeHtml(title) + countBadge + '</div>';
	html += '<div class="heatmap-scroll"><div class="heatmap-grid">';
	html += '<div class="heatmap-corner"></div>';
	for (var h = 0; h < 24; h++) {
		html += '<div class="heatmap-hhead">' + (h % 3 === 0 ? h : '') + '</div>';
	}
	HM_DAYS.forEach(function(day, d) {
		html += '<div class="heatmap-dhead">' + day + '</div>';
		for (var h = 0; h < 24; h++) {
			var v = (hm[d] && hm[d][h]) ? hm[d][h] : 0;
			var intensity = max > 0 ? (v / max) : 0;
			var bg = v > 0 ? 'rgba(' + rgb + ',' + (0.15 + intensity * 0.85).toFixed(2) + ')' : 'transparent';
			var isClickable = v > 0 && (jail != null || isHp);
			var tip = day + '曜 ' + h + ':00 - ' + v + ' ' + tipUnit + (isClickable ? '\nクリックで詳細表示' : '');
			var cls = 'heatmap-cell';
			if (isClickable) cls += isHp ? ' heatmap-cell-active heatmap-cell-hp' : ' heatmap-cell-active';
			var attrs = ' data-dow="' + d + '" data-hour="' + h + '"';
			if (isHp) {
				attrs += ' data-trigger="' + escapeHtml(trigger) + '"';
			} else {
				attrs += ' data-jail="' + escapeHtml(jail != null ? jail : 'all') + '"';
			}
			html += '<div class="' + cls + '"'
				+ ' style="background:' + bg + '"'
				+ ' title="' + escapeHtml(tip) + '"'
				+ attrs
				+ '>' + (v > 0 ? v : '') + '</div>';
		}
	});
	html += '</div></div></div>';
	return html;
}

// flagEmoji — "🇯🇵 JP" のような国旗+コード文字列から国旗絵文字のみ取り出す
function flagEmoji(flagStr) {
	if (!flagStr) return '';
	return String(flagStr).split(' ')[0];
}

function copyText(text, el) {
	navigator.clipboard.writeText(text).then(function() {
		if (!el) return;
		var orig = el.style.background;
		el.style.background = '#2d5a2d';
		setTimeout(function() { el.style.background = orig; }, 600);
	});
}

function getAppBase() {
	if (typeof HD_APP_BASE !== 'undefined' && HD_APP_BASE) return HD_APP_BASE;
	return '/monitor';
}

function getCardOptions(cardId) {
	if (typeof HD_CARD_OPTIONS === 'undefined' || !HD_CARD_OPTIONS) return {};
	var opts = HD_CARD_OPTIONS[cardId];
	return opts && typeof opts === 'object' ? opts : {};
}

function getMonitorCardId(key, fallbackId) {
	if (typeof HD_CARD_IDS !== 'undefined' && HD_CARD_IDS && HD_CARD_IDS[key]) {
		return HD_CARD_IDS[key];
	}
	return fallbackId;
}

function getMonitorCardAPI(cardId, fallbackAPI) {
	if (typeof HD_CARD_APIS !== 'undefined' && HD_CARD_APIS && HD_CARD_APIS[cardId]) {
		return HD_CARD_APIS[cardId];
	}
	return fallbackAPI;
}

function monitorApiURL(apiName, includeAgent) {
	var url = getAppBase() + '/?api=' + encodeURIComponent(apiName);
	var withAgent = includeAgent !== false;
	if (withAgent && typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) {
		url += '&agent=' + encodeURIComponent(HD_AGENT_ID);
	}
	return url;
}
window.monitorApiURL = monitorApiURL;

// ========================================
// Async section loader
// apiName   : ?api= に渡す値
// sectionId : ルート要素の id
// renderFn  : function(content, data) — DOM 書き換えを担当
// ========================================
function loadSection(apiName, sectionId, renderFn) {
	var section = document.getElementById(sectionId);
	if (!section) return;
	var content = section.classList.contains('async-content') ? section : section.querySelector('.async-content');
	if (!content) return;
	// 親カードに更新設定を保存（card_refresh.js の refreshCard() から参照）
	// async-ssl 等のサブカード loadSection がメインカードの _refreshConfig を上書きしないよう、
	// 既に別セクション向けの設定がある場合はスキップする。
	var card = section.closest('section.card[id]');
	if (card) {
		if (!card._refreshConfig || card._refreshConfig.sectionId === sectionId) {
			card._refreshConfig = { apiName: apiName, sectionId: sectionId, renderFn: renderFn };
		}
	}
	content.innerHTML = '<p class="section-loading">読み込み中...</p>';
	var url = monitorApiURL(apiName);
	fetch(url)
		.then(function(r) {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		})
		.then(function(data) {
			if (data && data.unavailable) {
				content.innerHTML = '<p class="unavailable-msg">このサーバーでは取得できません</p>';
				return;
			}
			renderFn(content, data);
			addRowNumbers(content);
			if (typeof touchLastUpdated === 'function') touchLastUpdated();
		})
		.catch(function(err) {
			content.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escapeHtml(err.message) + '</p>';
		});
}

// ========================================
// loadJsonCard — JSON を直接返す API 用の薄い fetch ラッパー。
// vendor_*/ssl/resource_graph が各自で再発明していたローカル doFetch を一本化する。
//   el       : 描画先要素（loadSection の section とは異なり content 要素を直接渡す）
//   apiName  : ?api= に渡す値
//   renderFn : function(el, data) — DOM 書き換えを担当
//   opts     : { agentID, includeAgent } 任意
// loading 表示と section-error によるエラー表示を共通化する（旧 doFetch の class="error" は section-error へ統一）。
// ========================================
function loadJsonCard(el, apiName, renderFn, opts) {
	if (!el) return;
	opts = opts || {};
	el.innerHTML = '<p class="section-loading">読み込み中...</p>';
	var url = getAppBase() + '/?api=' + encodeURIComponent(apiName);
	var agentID = opts.agentID;
	if (!agentID && opts.includeAgent !== false && typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) {
		agentID = HD_AGENT_ID;
	}
	if (agentID) url += '&agent=' + encodeURIComponent(agentID);
	fetch(url, { credentials: 'same-origin' })
		.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
		.then(function(data) { renderFn(el, data); })
		.catch(function(err) {
			el.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escapeHtml(err.message) + '</p>';
		});
}
window.loadJsonCard = loadJsonCard;


// MB数値文字列（"28.2" または "28.2 MB"）を "28.2 MB" / "1.4 GB" 形式に整形する共通ヘルパー
function fmtMB(s) {
	if (s === undefined || s === null || s === '' || s === '?') return '?';
	var n = parseFloat(s);
	if (isNaN(n)) return s;
	if (n >= 1024) return (n / 1024).toFixed(1) + ' GB';
	return n + ' MB';
}

// ========================================
// リソースカードの res-async-* サブカードを disk API データで更新
// resources.php の res-async-disk-detail / res-async-db / res-async-nginx を埋める。
// Monitor では renderDisk() からも呼ばれる。Admin では loadDiskResources() から直接呼ばれる。
// ========================================
function renderDiskResources(data) {
	function fmtDu(s) {
		if (!s || s === '?') return '?';
		var m = String(s).match(/^([\d.]+)\s*([KMGT]?)B?$/i);
		if (!m) return s;
		var unit = m[2].toUpperCase();
		return m[1] + ' ' + (unit ? unit + 'B' : 'B');
	}
	var resDiskEl = document.getElementById('res-async-disk-detail');
	if (resDiskEl) {
		resDiskEl.classList.remove('section-loading');
		resDiskEl.innerHTML =
			'<div class="stat-value typo-meta" style="line-height:1.7;">' +
				'<div>NCデータ：' + escapeHtml(fmtDu(data.nc_data_size)) + '</div>' +
				'<div>NCアプリ：' + escapeHtml(fmtDu(data.nc_app_size)) + '</div>' +
				'<div>/var/log：' + escapeHtml(fmtDu(data.log_size)) + '</div>' +
			'</div>' +
			'<span class="stat-sub" style="margin-top:6px;">' +
				'nextcloud.log：' + escapeHtml(fmtDu(data.nc_log_size)) +
				((data.nc_log_files && data.nc_log_files.length > 0) ? '（最終: ' + escapeHtml(data.nc_log_files[0].date) + '）' : '') +
			'</span>';
	}
	var resDbEl = document.getElementById('res-async-db');
	if (resDbEl) {
		resDbEl.classList.remove('section-loading');
		var dbLines = '<span class="stat-value">' + escapeHtml(fmtMB(data.db_size)) + '</span>';
		if (data.db_list && data.db_list.length > 0) {
			dbLines += '<div class="stat-sub" style="margin-top:6px;line-height:1.7;">';
			data.db_list.forEach(function(db) {
				dbLines += '<div>' + escapeHtml(db.name.toUpperCase()) + '：' + escapeHtml(fmtMB(db.size)) + '</div>';
			});
			dbLines += '</div>';
		}
		resDbEl.innerHTML = dbLines;
	}
	var resNginxEl = document.getElementById('res-async-nginx');
	if (resNginxEl) {
		resNginxEl.classList.remove('section-loading');
		var ccRes = data.country_counts || {};
		var ccResKeys = Object.keys(ccRes);
		var reqLineRes = '<span class="stat-value">' + Number(data.access_today || 0).toLocaleString() + '</span>';
		if (ccResKeys.length > 0) {
			var allTitleRes = ccResKeys.map(function(k) { return k + ': ' + Number(ccRes[k]).toLocaleString(); }).join('\n');
			var topHtmlRes = ccResKeys.slice(0, 3).map(function(k) {
				return escapeHtml(k) + ': <span class="typo-faint">' + Number(ccRes[k]).toLocaleString() + '</span>';
			}).join(' / ');
			reqLineRes += '<span class="stat-sub" title="' + escapeHtml(allTitleRes) + '" style="cursor:help;">' + topHtmlRes + '</span>';
		}
		var scLineRes = '<span class="stat-sub" style="margin-top:6px;">';
		if (data.status_codes && Object.keys(data.status_codes).length > 0) {
			var scCats = {};
			Object.keys(data.status_codes).forEach(function(code) {
				var cat = code.charAt(0) + 'xx';
				if (!scCats[cat]) scCats[cat] = { total: 0, codes: {} };
				scCats[cat].total += data.status_codes[code];
				scCats[cat].codes[code] = data.status_codes[code];
			});
			// _scCategoryData は dashboard.js 側のグローバルで openStatusCodeCategoryModal が参照する
			if (typeof _scCategoryData !== 'undefined') _scCategoryData = scCats;
			Object.keys(scCats).sort().forEach(function(cat) {
				if (typeof openStatusCodeCategoryModal === 'function') {
					scLineRes += '<span class="sc sc-' + cat.charAt(0) + '" style="cursor:pointer;margin-right:6px;" onclick="openStatusCodeCategoryModal(\'' + escapeJsString(cat) + '\')">' +
						escapeHtml(cat) + ': ' + Number(scCats[cat].total).toLocaleString() + '</span>';
				} else {
					scLineRes += '<span class="sc sc-' + cat.charAt(0) + '" style="margin-right:6px;">' +
						escapeHtml(cat) + ': ' + Number(scCats[cat].total).toLocaleString() + '</span>';
				}
			});
		}
		scLineRes += '</span>';
		resNginxEl.innerHTML = reqLineRes + scLineRes;
	}
}

// ========================================
// Row number helper — .log-table に #列を挿入し、可視行を1から採番する
// ========================================
function addRowNumbers(container) {
	var tables = container.querySelectorAll('table.log-table');
	tables.forEach(function(table) {
		// notification-rules-table など行番号不要なテーブルはスキップ
		if (table.classList.contains('no-row-num')) return;

		var thead = table.querySelector('thead');
		var tbody = table.querySelector('tbody');
		if (!thead || !tbody) return;

		// #列が未挿入なら挿入する
		if (!table.classList.contains('row-num-init')) {
			table.classList.add('row-num-init');
			// ヘッダー行（フィルター行以外）の先頭に <th class="col-row-num">#</th> を挿入
			thead.querySelectorAll('tr').forEach(function(tr) {
				var th = document.createElement('th');
				if (tr.classList.contains('thead-filter-row')) {
					th.className = 'col-row-num';
				} else {
					th.className = 'col-row-num';
					th.textContent = '#';
				}
				tr.insertBefore(th, tr.firstChild);
			});
			// tbody の各行の先頭に <td class="col-row-num"> を挿入
			tbody.querySelectorAll('tr').forEach(function(tr) {
				var td = document.createElement('td');
				td.className = 'col-row-num';
				tr.insertBefore(td, tr.firstChild);
			});
		}

		// 可視行を順番に採番する
		var num = 0;
		tbody.querySelectorAll('tr').forEach(function(tr) {
			var td = tr.querySelector('td.col-row-num');
			if (!td) return;
			if (tr.style.display === 'none' || tr.getAttribute('data-filter-hidden') === '1') {
				td.textContent = '';
			} else {
				td.textContent = ++num;
			}
		});
	});
}

// ========================================
// Row limit helper (default 20 rows, toggle to show all)
// NOTE:
// データ取得上限（例: 1000件）に対して初期表示件数（例: 20件）を見せる用途を想定。
// 初期表示の filter-count は total > defaultLimit のときだけ表示し、
// total <= defaultLimit（20/20件のような情報価値が低い表示）は出さない。
// ========================================
function initRowLimit(container, defaultLimit, slotId) {
	defaultLimit = defaultLimit || 20;
	var tbodies = container.querySelectorAll('tbody');
	var totalRows = 0;
	tbodies.forEach(function(tbody) {
		totalRows += tbody.querySelectorAll('tr').length;
	});
	if (totalRows === 0) return;
	container.setAttribute('data-row-limit-default', String(defaultLimit));
	container.setAttribute('data-row-limit-total', String(totalRows));
	container.setAttribute('data-row-limit-slot', slotId || '');
	// initCardHeaderActions が事前にスロットを作成済みの場合はそれを使う。
	// スロットが存在しない場合は後方互換として container.appendChild にフォールバック。
	var slot = slotId ? document.getElementById(slotId) : null;
	if (slot) {
		slot.querySelectorAll('.expand-btn').forEach(function(el) {
			el.remove();
		});
	}
	if (totalRows <= defaultLimit) {
		container.setAttribute('data-row-limit-collapsed', '0');
		var compactCounts = container.querySelectorAll('.filter-count');
		compactCounts.forEach(function(el) {
			el.textContent = '';
		});
		// 件数が少なくても右上に件数を静的表示する
		var slot = slotId ? document.getElementById(slotId) : null;
		if (slot) {
			slot.querySelectorAll('.expand-btn').forEach(function(el) { el.remove(); });
			var countSpan = document.createElement('span');
			countSpan.className = 'expand-btn expand-btn-static';
			countSpan.textContent = formatCount(totalRows) + '件';
			slot.appendChild(countSpan);
		}
		updateHeaderBadge(container);
		return;
	}
	function updateFilterCount(visibleRows) {
		var countEls = container.querySelectorAll('.filter-count');
		countEls.forEach(function(el) {
			el.textContent = formatCount(visibleRows) + '/' + formatCount(totalRows) + '件';
		});
		var isCollapsed = container.getAttribute('data-row-limit-collapsed') === '1';
		if (btn && isCollapsed) {
			btn.textContent = formatCount(visibleRows) + '件表示';
		}
		updateHeaderBadge(container);
	}
	function isFilterHidden(row) {
		return row.getAttribute('data-filter-hidden') === '1';
	}
	var allRows = [];
	tbodies.forEach(function(tbody) {
		var rows = tbody.querySelectorAll('tr');
		for (var i = 0; i < rows.length; i++) allRows.push(rows[i]);
	});
	function applyRowLimitVisibility(isCollapsed) {
		var visibleTotal = 0;
		for (var ci = 0; ci < allRows.length; ci++) {
			if (!isFilterHidden(allRows[ci])) visibleTotal++;
		}
		var shown = 0;
		for (var ri = 0; ri < allRows.length; ri++) {
			var row = allRows[ri];
			if (isFilterHidden(row)) {
				row.style.display = 'none';
				continue;
			}
			if (!isCollapsed || shown < defaultLimit) {
				row.style.display = '';
				shown++;
			} else {
				row.style.display = 'none';
			}
		}
		updateFilterCount(visibleTotal);
		addRowNumbers(container);
	}
	container.setAttribute('data-row-limit-collapsed', '1');
	var btn = document.createElement('button');
	btn.className = 'expand-btn';
	btn.addEventListener('click', function() {
		var isCollapsed = container.getAttribute('data-row-limit-collapsed') !== '0';
		if (isCollapsed) {
			btn.textContent = '折りたたむ';
			container.setAttribute('data-row-limit-collapsed', '0');
			applyRowLimitVisibility(false);
		} else {
			container.setAttribute('data-row-limit-collapsed', '1');
			applyRowLimitVisibility(true);
		}
	});
	applyRowLimitVisibility(true);
	container.addEventListener('row-filter-apply', function() {
		var isCollapsed = container.getAttribute('data-row-limit-collapsed') !== '0';
		applyRowLimitVisibility(isCollapsed);
	});
	if (slot) {
		slot.appendChild(btn);
	} else {
		container.appendChild(btn);
	}
	updateHeaderBadge(container);
}

function resetToInitialRowLimit(container) {
	if (!container) return;
	var defaultLimit = parseInt(container.getAttribute('data-row-limit-default') || '0', 10);
	if (!defaultLimit) return;
	var allRows = container.querySelectorAll('tbody tr');
	if (allRows.length <= defaultLimit) return;
	for (var i = 0; i < allRows.length; i++) {
		allRows[i].style.display = (i < defaultLimit) ? '' : 'none';
	}
	container.setAttribute('data-row-limit-collapsed', '1');
	updateHeaderBadge(container);
}

// ========================================
// Bulk BAN initializer (for dynamically loaded sections)
// ========================================
function initBulkBan(section, container) {
	var form = container.querySelector ? container.querySelector('[data-bulk-ban="' + section + '"]') : container;
	if (!form) return;
	var selectAll = form.querySelector('[data-select-all="' + section + '"]');
	var countSpan = form.querySelector('[data-count="' + section + '"]');
	var banBtn = form.querySelector('[data-ban-btn="' + section + '"]');
	var checkboxes = form.querySelectorAll('input[name="ban_ips[]"]:not(:disabled)');
	var bar = form.querySelector('.bulk-ban-bar');
	if (bar) bar.style.display = 'none';
	function updateState() {
		var checked = form.querySelectorAll('input[name="ban_ips[]"]:checked');
		var count = checked.length;
		if (countSpan) countSpan.textContent = formatCount(count) + '件選択中';
		if (banBtn) banBtn.disabled = count === 0;
		if (bar) {
			bar.style.display = count > 0 ? '' : 'none';
			bar.classList.toggle('sticky-active', count > 0);
		}
		if (checkboxes.length > 0 && selectAll) {
			selectAll.checked = (count === checkboxes.length);
			selectAll.indeterminate = (count > 0 && count < checkboxes.length);
		}
	}
	if (selectAll) {
		selectAll.addEventListener('change', function() {
			checkboxes.forEach(function(cb) { cb.checked = selectAll.checked; });
			updateState();
		});
	}
	checkboxes.forEach(function(cb) { cb.addEventListener('change', updateState); });
	form.addEventListener('submit', function(e) {
		e.preventDefault();
		var checked = form.querySelectorAll('input[name="ban_ips[]"]:checked');
		if (checked.length === 0) return;
		var bulkBanConfirmMsg = '選択した ' + formatCount(checked.length) + ' 件のIPをBANします。よろしいですか？';

		var formData = new FormData(form);
		var bulkBanUrl = form.getAttribute('data-bulk-ban-url');
		var postUrl = bulkBanUrl ? getAppBase() + '/' + bulkBanUrl : location.pathname;
		// headers は明示せず共通 CSRF ラッパー（initCsrfFetchWrapper）に委譲する。
		// ラッパーが同一オリジン POST に X-CSRF-Token / X-Requested-With を付与する。
		fetch(postUrl, {
			method: 'POST',
			body: formData
		})
		.then(function(res) { return res.json(); })
		.then(function(data) {
			var existing = form.parentNode.querySelector('.ajax-result');
			if (existing) existing.remove();
			var div = document.createElement('div');
			div.className = 'ajax-result card action-result ' + (data.type || 'ban');
			div.style.transition = 'opacity 0.5s';
			div.innerHTML = '<p>' + escapeHtml(data.message || '') + '</p>';
			form.parentNode.insertBefore(div, form);
			setTimeout(function() { div.style.opacity = '0'; setTimeout(function() { div.remove(); }, 500); }, 5000);
			checked.forEach(function(cb) {
				var ip = cb.value;
				cb.checked = false; cb.disabled = true;
				var tr = cb.closest('tr');
				if (tr) {
					tr.setAttribute('data-banned', '1');
					if (ip && window.BANNED_IPS) window.BANNED_IPS[ip] = 'recidive';
					var oneBtn = tr.querySelector('.btn-ban:not(.btn-bulk-ban)');
					if (oneBtn) {
						oneBtn.parentNode.innerHTML = '<span class="jail-tag jail-tag-banned">BAN済</span>';
					}
				}
			});
			checkboxes = form.querySelectorAll('input[name="ban_ips[]"]:not(:disabled)');
			updateState();
		})
		.catch(function(err) {
			alert('BAN処理に失敗しました: ' + err.message);
		});
	});
}

// ========================================
// Card Filter helper (client-side row filtering)
// ========================================
var SHARED_FILTER_DROPDOWN_OPEN = null;

function closeSharedFilterDropdowns(exceptEl) {
	document.querySelectorAll('.filter-multi.open').forEach(function(el) {
		if (exceptEl && el === exceptEl) return;
		el.classList.remove('open');
	});
	SHARED_FILTER_DROPDOWN_OPEN = exceptEl || null;
}

if (!window.__sharedFilterDropdownDocBound) {
	window.__sharedFilterDropdownDocBound = true;
	document.addEventListener('click', function(ev) {
		if (ev.target.closest('.filter-multi')) return;
		closeSharedFilterDropdowns(null);
	});
}

function parseFilterOptionsFromSource(source) {
	var opts = [];
	if (source.tagName === 'SELECT') {
		var options = source.querySelectorAll('option');
		for (var i = 0; i < options.length; i++) {
			var v = (options[i].value || '').trim();
			var l = (options[i].textContent || '').trim();
			if (!v) continue;
			opts.push({ value: v, label: l || v });
		}
		return opts;
	}
	if (source.tagName === 'INPUT') {
		var listId = source.getAttribute('list');
		if (!listId) return opts;
		var dl = document.getElementById(listId);
		if (!dl) return opts;
		var dlOpts = dl.querySelectorAll('option');
		for (var j = 0; j < dlOpts.length; j++) {
			var dv = (dlOpts[j].value || '').trim();
			if (!dv) continue;
			var dlLabel = (dlOpts[j].getAttribute('data-label') || dlOpts[j].getAttribute('label') || dv).trim();
			opts.push({ value: dv, label: dlLabel || dv });
		}
	}
	return opts;
}

function getSourceMultiValues(source) {
	try {
		var raw = source.getAttribute('data-multi-values') || '[]';
		var arr = JSON.parse(raw);
		if (!Array.isArray(arr)) return [];
		var normalized = [];
		var seen = {};
		for (var i = 0; i < arr.length; i++) {
			var v = String(arr[i] == null ? '' : arr[i]).trim();
			if (!v || seen[v]) continue;
			seen[v] = true;
			normalized.push(v);
		}
		return normalized;
	} catch (e) {
		return [];
	}
}

function setSourceMultiValues(source, values) {
	var normalized = [];
	var seen = {};
	for (var i = 0; i < values.length; i++) {
		var v = String(values[i] == null ? '' : values[i]).trim();
		if (!v || seen[v]) continue;
		seen[v] = true;
		normalized.push(v);
	}
	source.setAttribute('data-multi-values', JSON.stringify(normalized));
}

function formatMultiButtonLabel(values, map, defaultLabel) {
	if (!values || values.length === 0) return defaultLabel;
	if (values.length === Object.keys(map).length) return defaultLabel;
	if (values.length === 1) return map[values[0]] || values[0];
	if (values.length === 2) return (map[values[0]] || values[0]) + ', ' + (map[values[1]] || values[1]);
	return (map[values[0]] || values[0]) + ' ほか' + formatCount(values.length - 1) + '件';
}

function enhanceToSharedMultiSelect(source) {
	if (!source || source.getAttribute('data-multi-init') === '1') return;
	var options = parseFilterOptionsFromSource(source);
	if (!options || options.length === 0) return;

	var sourceClass = source.classList.contains('filter-select') ? 'filter-select' : 'filter-input';
	var defaultLabel = source.tagName === 'SELECT'
		? ((source.querySelector('option[value=""]') || {}).textContent || '全て').trim()
		: ((source.getAttribute('placeholder') || '全て').trim());

	source.setAttribute('data-multi-init', '1');
	source.setAttribute('data-filter-mode', 'multi');
	source.setAttribute('data-multi-total', String(options.length));
	source.classList.add('filter-source-hidden');
	if (source.tagName === 'INPUT') source.removeAttribute('list');
	setSourceMultiValues(source, []);

	var labelMap = {};
	options.forEach(function(o) { labelMap[o.value] = o.label; });

	var root = document.createElement('div');
	root.className = 'filter-multi';
	root.setAttribute('data-filter-key', source.getAttribute('data-filter') || '');

	var btn = document.createElement('button');
	btn.type = 'button';
	btn.className = sourceClass + ' filter-multi-btn';
	btn.textContent = defaultLabel;
	root.appendChild(btn);

	var menu = document.createElement('div');
	menu.className = 'filter-multi-menu';
	var menuInner = document.createElement('div');
	menuInner.className = 'filter-multi-menu-inner';

	var allRow = document.createElement('label');
	allRow.className = 'filter-multi-opt filter-multi-opt-all';
	var allCb = document.createElement('input');
	allCb.type = 'checkbox';
	allRow.appendChild(allCb);
	allRow.appendChild(document.createTextNode(' 全て'));
	menuInner.appendChild(allRow);

	var optionCbs = [];
	options.forEach(function(o) {
		var row = document.createElement('label');
		row.className = 'filter-multi-opt';
		var cb = document.createElement('input');
		cb.type = 'checkbox';
		cb.value = o.value;
		row.appendChild(cb);
		row.appendChild(document.createTextNode(' ' + o.label));
		menuInner.appendChild(row);
		optionCbs.push(cb);
	});

	menu.appendChild(menuInner);
	root.appendChild(menu);
	source.parentNode.insertBefore(root, source.nextSibling);

	function syncAllCheckboxState(selectedValues) {
		if (selectedValues.length === 0) {
			allCb.checked = false;
			allCb.indeterminate = false;
			return;
		}
		if (selectedValues.length >= options.length) {
			allCb.checked = true;
			allCb.indeterminate = false;
			return;
		}
		allCb.checked = false;
		allCb.indeterminate = true;
	}

	function syncState(triggerChange) {
		var selected = [];
		optionCbs.forEach(function(cb) {
			if (cb.checked) selected.push(cb.value);
		});
		syncAllCheckboxState(selected);
		setSourceMultiValues(source, selected);
		btn.textContent = formatMultiButtonLabel(selected, labelMap, defaultLabel);
		root.classList.toggle('has-value', selected.length > 0);
		if (triggerChange) {
			source.dispatchEvent(new Event('multi-change', { bubbles: true }));
		}
	}

	btn.addEventListener('click', function(ev) {
		ev.preventDefault();
		if (root.classList.contains('open')) {
			root.classList.remove('open');
			SHARED_FILTER_DROPDOWN_OPEN = null;
			return;
		}
		closeSharedFilterDropdowns(root);
		root.classList.add('open');
		SHARED_FILTER_DROPDOWN_OPEN = root;
	});

	allCb.addEventListener('change', function() {
		var checked = allCb.checked;
		optionCbs.forEach(function(cb) { cb.checked = checked; });
		syncState(true);
	});

	optionCbs.forEach(function(cb) {
		cb.addEventListener('change', function() { syncState(true); });
	});

	syncState(false);
}

function normalizeFilterInputs(filterBar) {
	if (!filterBar) return;
	var allInputs = filterBar.querySelectorAll('.filter-input, .filter-select');
	allInputs.forEach(function(inp) {
		if (inp.classList.contains('filter-input')) {
			applyNoPasswordManagerAttrs(inp);
			if (!inp.__filterEscBound) {
				inp.__filterEscBound = true;
				inp.addEventListener('keydown', function(ev) {
					if (ev.key !== 'Escape') return;
					if (!inp.value) return;
					inp.value = '';
					inp.dispatchEvent(new Event('input', { bubbles: true }));
				});
			}
		}
		if (inp.classList.contains('filter-select') || (inp.classList.contains('filter-input') && inp.hasAttribute('list'))) {
			enhanceToSharedMultiSelect(inp);
		}
	});
}

function shouldSuppressPasswordManagerForInput(input) {
	if (!input || !input.tagName || input.tagName !== 'INPUT') return false;
	var type = String(input.getAttribute('type') || 'text').toLowerCase();
	if (type === 'hidden' || type === 'file' || type === 'checkbox' || type === 'radio' || type === 'submit' || type === 'button' || type === 'reset') {
		return false;
	}
	if (type === 'password') {
		var autocomplete = String(input.getAttribute('autocomplete') || '').toLowerCase();
		if (autocomplete === 'current-password' || autocomplete === 'new-password') {
			return false;
		}
	}
	if (input.hasAttribute('data-allow-password-manager')) {
		return false;
	}
	return true;
}

function applyNoPasswordManagerAttrs(root) {
	if (!root) return;
	var nodes = [];
	if (root.matches && (root.matches('input') || root.matches('textarea') || root.matches('select'))) {
		nodes.push(root);
	}
	if (root.querySelectorAll) {
		nodes = nodes.concat(Array.prototype.slice.call(root.querySelectorAll('input, textarea, select')));
	}
	nodes.forEach(function(node) {
		if (node.tagName === 'INPUT') {
			var type = String(node.getAttribute('type') || 'text').toLowerCase();
			if (!shouldSuppressPasswordManagerForInput(node)) {
				if (type !== 'hidden') {
					node.setAttribute('autocapitalize', 'off');
					node.setAttribute('spellcheck', 'false');
				}
				return;
			}
		}
		if (node.tagName === 'TEXTAREA' || node.tagName === 'SELECT' || shouldSuppressPasswordManagerForInput(node)) {
			if (node.tagName !== 'SELECT' || !node.hasAttribute('multiple')) {
				node.setAttribute('autocomplete', 'off');
			}
			node.setAttribute('autocapitalize', 'off');
			node.setAttribute('spellcheck', 'false');
			node.setAttribute('data-form-type', 'other');
			node.setAttribute('data-lpignore', 'true');
			node.setAttribute('data-1p-ignore', 'true');
		}
	});
}

window.applyNoPasswordManagerAttrs = applyNoPasswordManagerAttrs;

document.addEventListener('DOMContentLoaded', function() {
	applyNoPasswordManagerAttrs(document.body);
});

function ensureFilterCountRow(filterBar) {
	if (!filterBar) return null;
	// filterBar 内にすでに .filter-count があればそれを使い、カウント行を挿入しない
	var inlineCount = filterBar.querySelector('.filter-count');
	if (inlineCount) return inlineCount;
	var thead = filterBar.parentElement;
	if (!thead || thead.tagName !== 'THEAD') return null;

	var filterThCount = filterBar.querySelectorAll('th').length || 1;
	var countRow = thead.querySelector('.thead-count-row');
	if (!countRow) {
		countRow = document.createElement('tr');
		countRow.className = 'thead-count-row';
		var cell = document.createElement('th');
		cell.colSpan = filterThCount;
		var countEl = document.createElement('span');
		countEl.className = 'filter-count';
		cell.appendChild(countEl);
		countRow.appendChild(cell);
		thead.insertBefore(countRow, filterBar);
	}

	var countCell = countRow.querySelector('th, td');
	if (countCell) {
		countCell.colSpan = filterThCount;
	}

	var rowCountEl = countRow.querySelector('.filter-count');
	if (!rowCountEl) {
		rowCountEl = document.createElement('span');
		rowCountEl.className = 'filter-count';
		if (countCell) countCell.appendChild(rowCountEl);
	}

	var oldCountEls = filterBar.querySelectorAll('.filter-count');
	oldCountEls.forEach(function(el) {
		if (el === rowCountEl) return;
		el.parentNode.removeChild(el);
	});

	return rowCountEl;
}

// IP絞り込みセル（テキスト入力 + WL/BAN/既知ドロップダウンフィルター）を生成する共通ヘルパー
// opts: { wl, wlm, wla, ban, known }
//   true  = 項目を表示しデフォルトON（含む）
//   false = 項目を表示しデフォルトOFF（除外）
//   省略/null = その項目を表示しない
// ※ wl は後方互換用の一括WLフィルター。wlm/wla を使うと種別ごとに個別制御できる
function buildIpFilterCell(opts) {
	var o = opts || {};
	var hasFilter = (o.wl !== undefined && o.wl !== null) ||
	                (o.wlm !== undefined && o.wlm !== null) ||
	                (o.wla !== undefined && o.wla !== null) ||
	                (o.ban !== undefined && o.ban !== null) ||
	                (o.known !== undefined && o.known !== null);
	var html = '<div class="ip-filter-cell">';
	html += '<input type="text" class="filter-input" data-filter="ip" placeholder="IP絞り込み">';
	if (hasFilter) {
		// ドロップダウンボタン（ラベルでON/OFF状態を表示）
		html += '<div class="ifd-wrap">';
		html += '<button type="button" class="ifd-btn">';
		if (o.wl !== undefined && o.wl !== null) {
			html += '<span class="ifd-label' + (o.wl ? '' : ' ifd-off') + '" data-key="wl">' + escapeHtml(window.ipTypeShortLabel('wl')) + '</span>';
		}
		if (o.wlm !== undefined && o.wlm !== null) {
			html += '<span class="ifd-label' + (o.wlm ? '' : ' ifd-off') + '" data-key="wlm">' + escapeHtml(window.ipTypeShortLabel('wlm')) + '</span>';
		}
		if (o.wla !== undefined && o.wla !== null) {
			html += '<span class="ifd-label' + (o.wla ? '' : ' ifd-off') + '" data-key="wla">' + escapeHtml(window.ipTypeShortLabel('wla')) + '</span>';
		}
		if (o.ban !== undefined && o.ban !== null) {
			html += '<span class="ifd-label' + (o.ban ? '' : ' ifd-off') + '" data-key="ban">BAN</span>';
		}
		if (o.known !== undefined && o.known !== null) {
			html += '<span class="ifd-label' + (o.known ? '' : ' ifd-off') + '" data-key="known">' + escapeHtml(window.ipTypeShortLabel('known')) + '</span>';
		}
		html += '<span class="ifd-arrow">▾</span>';
		html += '</button>';
		// ドロップダウンパネル
		html += '<div class="ifd-panel">';
		if (o.wl !== undefined && o.wl !== null) {
			html += '<label class="ifd-item"><input type="checkbox" class="wl-include-cb"' + (o.wl ? ' checked' : '') + '> ' + escapeHtml(window.ipTypeShortLabel('wl')) + 'を含む</label>';
		}
		if (o.wlm !== undefined && o.wlm !== null) {
			html += '<label class="ifd-item"><input type="checkbox" class="wlm-include-cb"' + (o.wlm ? ' checked' : '') + '> ' + escapeHtml(window.ipTypeShortLabel('wlm')) + 'を含む</label>';
		}
		if (o.wla !== undefined && o.wla !== null) {
			html += '<label class="ifd-item"><input type="checkbox" class="wla-include-cb"' + (o.wla ? ' checked' : '') + '> ' + escapeHtml(window.ipTypeShortLabel('wla')) + 'を含む</label>';
		}
		if (o.ban !== undefined && o.ban !== null) {
			html += '<label class="ifd-item"><input type="checkbox" class="ban-include-cb"' + (o.ban ? ' checked' : '') + '> BANを含む</label>';
		}
		if (o.known !== undefined && o.known !== null) {
			html += '<label class="ifd-item"><input type="checkbox" class="known-include-cb"' + (o.known ? ' checked' : '') + '> ' + escapeHtml(window.ipTypeShortLabel('known')) + 'を含む</label>';
		}
		html += '</div>';
		html += '</div>';
	}
	html += '</div>';
	return html;
}

// 脅威スコアカラムヘッダー（重みバッジ付き）生成ヘルパー
// PHP版 dashboard.js の _threatWeightLabel に相当する共通関数
function threatWeightLabel(label, key, weights, tip) {
	var w = weights && weights[key];
	var text = (typeof w === 'number') ? (label + ' (' + w + ')') : label;
	if (tip) {
		return '<span title="' + escapeHtml(tip) + '">' + escapeHtml(text) + '</span>';
	}
	return escapeHtml(text);
}

function setupCardFilter(filterBar, container) {
	if (!filterBar) return;
	normalizeFilterInputs(filterBar);
	var inputs = filterBar.querySelectorAll('.filter-input, .filter-select');
	var countMode = String(filterBar.getAttribute('data-filter-count') || '').toLowerCase();
	var showCount = !(countMode === 'off' || countMode === 'none' || countMode === 'hidden');
	var countEl = showCount ? (ensureFilterCountRow(filterBar) || filterBar.querySelector('.filter-count')) : null;
	if (!showCount) {
		var thead = filterBar.parentElement;
		if (thead && thead.tagName === 'THEAD') {
			var countRow = thead.querySelector('.thead-count-row');
			if (countRow) countRow.parentNode.removeChild(countRow);
		}
		filterBar.querySelectorAll('.filter-count').forEach(function(el) {
			el.textContent = '';
			el.style.display = 'none';
		});
	}
	var wlCb    = filterBar.querySelector('.wl-include-cb');
	var wlmCb   = filterBar.querySelector('.wlm-include-cb');
	var wlaCb   = filterBar.querySelector('.wla-include-cb');
	var banCb   = filterBar.querySelector('.ban-include-cb');
	var knownCb = filterBar.querySelector('.known-include-cb');
	var showWl    = wlCb    ? wlCb.checked    : true;
	var showWlm   = wlmCb   ? wlmCb.checked   : true;
	var showWla   = wlaCb   ? wlaCb.checked   : true;
	var showBan   = banCb   ? banCb.checked   : true;
	var showKnown = knownCb ? knownCb.checked : true;

	function applyFilter() {
		var filters = [];
		inputs.forEach(function(inp) {
			var mode = inp.getAttribute('data-filter-mode') || '';
			if (mode === 'multi') {
				var mvals = getSourceMultiValues(inp);
				var multiTotal = parseInt(inp.getAttribute('data-multi-total') || '0', 10);
				if (multiTotal > 0 && mvals.length >= multiTotal) {
					return;
				}
				if (mvals.length > 0) {
					var allowPartialMulti = inp.getAttribute('data-filter-partial') === '1' || inp.tagName !== 'SELECT';
					filters.push({
						key: inp.getAttribute('data-filter'),
						values: mvals.map(function(v) { return (v || '').toLowerCase(); }),
						partial: allowPartialMulti,
						multi: true
					});
				}
				return;
			}
			var val = inp.value.trim();
			if (val) {
				var allowPartialSelect = inp.getAttribute('data-filter-partial') === '1';
				filters.push({
					key: inp.getAttribute('data-filter'),
					value: val.toLowerCase(),
					partial: inp.tagName !== 'SELECT' || allowPartialSelect
				});
			}
		});

		var allRows = container.querySelectorAll('tbody tr');
		var rowLimitDefault = parseInt(container.getAttribute('data-row-limit-default') || '0', 10);
		var rowLimitTotal = parseInt(container.getAttribute('data-row-limit-total') || '0', 10);
		// 行数が default 以下のときは initRowLimit が row-filter-apply を発火しないため、
		// setupCardFilter 側で直接 display を切り替える必要がある。
		var hasRowLimit = rowLimitDefault > 0 && rowLimitTotal > rowLimitDefault;
		var visible = 0;
		allRows.forEach(function(row) {
			var show = true;
			for (var i = 0; i < filters.length; i++) {
				var f = filters[i];
				var cellVal = (row.getAttribute('data-' + f.key) || '').toLowerCase();
				if (f.multi) {
					var matched = false;
					for (var mi = 0; mi < f.values.length; mi++) {
						if (f.partial) {
							if (cellVal.indexOf(f.values[mi]) !== -1) { matched = true; break; }
						} else {
							if (cellVal === f.values[mi]) { matched = true; break; }
						}
					}
					if (!matched) { show = false; break; }
					continue;
				}
				if (f.partial) {
					if (cellVal.indexOf(f.value) === -1) { show = false; break; }
				} else {
					if (cellVal !== f.value) { show = false; break; }
				}
			}
			if (show && row.getAttribute('data-wl') === '1') {
				var rowIp = row.getAttribute('data-ip') || '';
				var rowIpType = (window.SSH_ALLOWED_TYPES && rowIp) ? (window.SSH_ALLOWED_TYPES[rowIp] || '') : '';
				if (rowIpType === 'wlm') {
					if (!showWlm) show = false;
				} else if (rowIpType === 'wla') {
					if (!showWla) show = false;
				} else {
					if (!showWl) show = false;
				}
			}
			if (show && !showBan   && row.getAttribute('data-banned') === '1') show = false;
			if (show && !showKnown && row.getAttribute('data-known')  === '1') show = false;
			row.setAttribute('data-filter-hidden', show ? '0' : '1');
			if (!hasRowLimit) row.style.display = show ? '' : 'none';
			if (show) visible++;
		});

		if (hasRowLimit) {
			container.dispatchEvent(new CustomEvent('row-filter-apply'));
		}
		if (countEl) {
			countEl.textContent = formatCount(visible) + '/' + formatCount(allRows.length) + '件';
		}
		// initRowLimit が生成した expand-btn のテキストをフィルター後件数で更新
		var slotId = container.getAttribute('data-row-limit-slot') || '';
		var expandSlot = slotId ? document.getElementById(slotId) : null;
		var expandBtn = expandSlot ? expandSlot.querySelector('.expand-btn') : null;
		if (expandBtn && container.getAttribute('data-row-limit-collapsed') === '1') {
			expandBtn.textContent = formatCount(visible) + '件表示';
		}
		updateHeaderBadge(container);
		addRowNumbers(container);
	}

	inputs.forEach(function(inp) {
		var mode = inp.getAttribute('data-filter-mode') || '';
		if (mode === 'multi') {
			inp.addEventListener('multi-change', applyFilter);
		} else {
			inp.addEventListener(inp.tagName === 'SELECT' ? 'change' : 'input', applyFilter);
		}
	});
	// ドロップダウンの開閉制御
	var ifdWrap = filterBar.querySelector('.ifd-wrap');
	var ifdBtn  = filterBar.querySelector('.ifd-btn');
	var ifdPanel = filterBar.querySelector('.ifd-panel');
	function updateIfdBtn() {
		if (!ifdBtn) return;
		ifdBtn.querySelectorAll('.ifd-label').forEach(function(lbl) {
			var key = lbl.getAttribute('data-key');
			var on = key === 'wl' ? showWl : key === 'wlm' ? showWlm : key === 'wla' ? showWla : key === 'ban' ? showBan : showKnown;
			lbl.classList.toggle('ifd-off', !on);
		});
	}
	if (ifdBtn && ifdPanel) {
		ifdBtn.addEventListener('click', function(e) {
			e.stopPropagation();
			ifdPanel.classList.toggle('ifd-open');
		});
		document.addEventListener('click', function(e) {
			if (ifdWrap && !ifdWrap.contains(e.target)) {
				ifdPanel.classList.remove('ifd-open');
			}
		});
	}
	if (wlCb)    wlCb.addEventListener('change',    function() { showWl    = wlCb.checked;    updateIfdBtn(); applyFilter(); });
	if (wlmCb)   wlmCb.addEventListener('change',   function() { showWlm   = wlmCb.checked;   updateIfdBtn(); applyFilter(); });
	if (wlaCb)   wlaCb.addEventListener('change',   function() { showWla   = wlaCb.checked;   updateIfdBtn(); applyFilter(); });
	if (banCb)   banCb.addEventListener('change',   function() { showBan   = banCb.checked;   updateIfdBtn(); applyFilter(); });
	if (knownCb) knownCb.addEventListener('change', function() { showKnown = knownCb.checked; updateIfdBtn(); applyFilter(); });
	if (countEl) {
		var totalRows = container.querySelectorAll('tbody tr').length;
		var defaultLimit = parseInt(container.getAttribute('data-row-limit-default') || '0', 10);
		if (defaultLimit <= 0 && typeof ROW_LIMIT_DEFAULT !== 'undefined') defaultLimit = parseInt(ROW_LIMIT_DEFAULT, 10) || 0;
		var initialVisible = (defaultLimit > 0) ? Math.min(defaultLimit, totalRows) : totalRows;
		countEl.textContent = (totalRows <= defaultLimit) ? '' : (formatCount(initialVisible) + '/' + formatCount(totalRows) + '件');
	}
	if (!showWl || !showWlm || !showWla || !showBan || !showKnown) applyFilter();
}

// ========================================
// ビュー切替フィルター保持ヘルパー
// 集計/一覧を切り替えても各ビューのフィルター条件を維持する
// ========================================

// 現在の container のフィルター状態をオブジェクトとして返す
function captureFilterState(container) {
	var state = {};
	if (!container) return state;
	// テキスト入力（非multi）
	container.querySelectorAll('.filter-input[data-filter]').forEach(function(el) {
		if (el.getAttribute('data-multi-init') === '1') return;
		var key = el.getAttribute('data-filter');
		if (key && el.value) state[key] = el.value;
	});
	// multi-select: data-multi-values を保存
	container.querySelectorAll('[data-filter][data-multi-init="1"]').forEach(function(el) {
		var key = el.getAttribute('data-filter');
		var raw = el.getAttribute('data-multi-values');
		if (!key || !raw) return;
		try {
			var arr = JSON.parse(raw);
			if (Array.isArray(arr) && arr.length > 0) state[key] = arr;
		} catch(e) {}
	});
	// WL/WLM/WLA/BAN/既知チェックボックス（falseのみ保存：デフォルトが true のため）
	var wlCb  = container.querySelector('.wl-include-cb');
	var wlmCb = container.querySelector('.wlm-include-cb');
	var wlaCb = container.querySelector('.wla-include-cb');
	var banCb = container.querySelector('.ban-include-cb');
	var knownCb = container.querySelector('.known-include-cb');
	if (wlCb  && !wlCb.checked)  state.__wl  = false;
	if (wlmCb && !wlmCb.checked) state.__wlm = false;
	if (wlaCb && !wlaCb.checked) state.__wla = false;
	if (banCb && !banCb.checked) state.__ban = false;
	if (knownCb && !knownCb.checked) state.__known = false;
	return state;
}

// 保存済みフィルター状態を container に復元し applyFilter を起動する
function restoreFilterState(container, savedState) {
	if (!container || !savedState || Object.keys(savedState).length === 0) return;
	var needApply = false;
	// テキスト入力（非multi）
	container.querySelectorAll('.filter-input[data-filter]').forEach(function(el) {
		if (el.getAttribute('data-multi-init') === '1') return;
		var key = el.getAttribute('data-filter');
		if (key && typeof savedState[key] === 'string') {
			el.value = savedState[key];
			needApply = true;
		}
	});
	// multi-select: option チェックボックスを操作して syncState 経由で applyFilter を起動
	container.querySelectorAll('.filter-multi[data-filter-key]').forEach(function(root) {
		var key = root.getAttribute('data-filter-key');
		var saved = savedState[key];
		if (!saved) return;
		var savedArr = Array.isArray(saved) ? saved : [saved];
		if (savedArr.length === 0) return;
		var optCbs = root.querySelectorAll('.filter-multi-menu-inner input[type=checkbox][value]');
		var anySet = false;
		optCbs.forEach(function(cb) {
			if (savedArr.indexOf(cb.value) !== -1) { cb.checked = true; anySet = true; }
		});
		if (anySet) {
			// 最初の1個だけ change を発火 → syncState(true) → multi-change → applyFilter
			var first = root.querySelector('.filter-multi-menu-inner input[type=checkbox][value]');
			if (first) first.dispatchEvent(new Event('change', { bubbles: true }));
			needApply = true;
		}
	});
	// WL/WLM/WLA/BAN/既知チェックボックス
	var wlCb  = container.querySelector('.wl-include-cb');
	var wlmCb = container.querySelector('.wlm-include-cb');
	var wlaCb = container.querySelector('.wla-include-cb');
	var banCb = container.querySelector('.ban-include-cb');
	var knownCb = container.querySelector('.known-include-cb');
	if (wlCb  && savedState.__wl  === false) { wlCb.checked  = false; wlCb.dispatchEvent(new Event('change', { bubbles: true })); }
	if (wlmCb && savedState.__wlm === false) { wlmCb.checked = false; wlmCb.dispatchEvent(new Event('change', { bubbles: true })); }
	if (wlaCb && savedState.__wla === false) { wlaCb.checked = false; wlaCb.dispatchEvent(new Event('change', { bubbles: true })); }
	if (banCb && savedState.__ban === false) { banCb.checked = false; banCb.dispatchEvent(new Event('change', { bubbles: true })); }
	if (knownCb && savedState.__known === false) { knownCb.checked = false; knownCb.dispatchEvent(new Event('change', { bubbles: true })); }
	// テキスト入力のフィルターを再適用（multi-change は既に applyFilter を起動済み）
	if (needApply) {
		var firstInput = container.querySelector('.filter-input[data-filter]:not(.filter-source-hidden)');
		if (firstInput) firstInput.dispatchEvent(new Event('input', { bubbles: true }));
	}
}

// ビュー切替前に現在のフィルター状態を container.__viewFilters に保存する
// nc-view-toggle がない（初回レンダリング）場合はスキップ
function saveCurrentViewFilter(content) {
	var toggle = content && content.querySelector('.nc-view-toggle');
	if (!toggle) return;
	var btns = toggle.querySelectorAll('.nc-view-btn');
	// 2番目のボタン（一覧）が active なら detail、それ以外は summary
	var currentKey = (btns[1] && btns[1].classList.contains('active')) ? 'detail' : 'summary';
	if (!content.__viewFilters) content.__viewFilters = {};
	content.__viewFilters[currentKey] = captureFilterState(content);
}

// 保存済みのビューフィルター状態を返す（未設定なら空オブジェクト）
function getViewFilter(content, viewKey) {
	return (content && content.__viewFilters && content.__viewFilters[viewKey]) || {};
}

// ========================================
// サイドナビ + 折りたたみ + localStorage
// ========================================
var COLLAPSE_KEY = (typeof HD_COLLAPSE_KEY !== 'undefined' && HD_COLLAPSE_KEY) ? HD_COLLAPSE_KEY : 'heartdesk.collapsed.v1';
var SIDENAV_SERVER_TREE_KEY = (typeof HD_SIDENAV_SERVER_TREE_KEY !== 'undefined' && HD_SIDENAV_SERVER_TREE_KEY) ? HD_SIDENAV_SERVER_TREE_KEY : 'heartdesk.sidenav.server_tree.v1';
var SIDENAV_ORDER_KEY = (typeof HD_SIDENAV_ORDER_KEY !== 'undefined' && HD_SIDENAV_ORDER_KEY) ? HD_SIDENAV_ORDER_KEY : 'heartdesk.sidenav.order.v1';

function loadCollapsedSet() {
	try {
		var raw = localStorage.getItem(COLLAPSE_KEY);
		if (!raw) return {};
		var arr = JSON.parse(raw);
		if (!Array.isArray(arr)) return {};
		var set = {};
		arr.forEach(function(id) { set[id] = true; });
		return set;
	} catch (e) { return {}; }
}

function saveCollapsedSet(set) {
	try {
		var arr = Object.keys(set).filter(function(k) { return set[k]; });
		localStorage.setItem(COLLAPSE_KEY, JSON.stringify(arr));
	} catch (e) {}
}

function loadSidenavServerTreeOpen() {
	try {
		var raw = localStorage.getItem(SIDENAV_SERVER_TREE_KEY);
		if (raw === '1') return true;
		if (raw === '0') return false;
		return null;
	} catch (e) {
		return null;
	}
}

function saveSidenavServerTreeOpen(open) {
	try {
		localStorage.setItem(SIDENAV_SERVER_TREE_KEY, open ? '1' : '0');
	} catch (e) {}
}

function applyCollapseState() {
	var set = loadCollapsedSet();
	document.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
		if (set[card.id]) {
			card.classList.add('collapsed');
		} else {
			card.classList.remove('collapsed');
		}
	});
}

(function() {
	var tip = null;
	var showTimer = null;
	var activeTitleEl = null;
	function ensureTip() {
		if (!tip) {
			tip = document.createElement('div');
			tip.className = 'cursor-tooltip';
			document.body.appendChild(tip);
		}
		return tip;
	}
	function getTipTarget(e) {
		var dataTipEl = e.target.closest('[data-tip]:not(.card-header):not(.section-toggle)');
		if (dataTipEl) return dataTipEl;
		dataTipEl = e.target.closest('[data-tip]');
		if (dataTipEl) return dataTipEl;
		var titleEl = e.target.closest('[title], [data-native-title]');
		if (!titleEl) return null;
		if (titleEl.getAttribute('title') || titleEl.getAttribute('data-native-title')) return titleEl;
		return null;
	}
	function getTipText(el) {
		return el.getAttribute('data-tip') || el.getAttribute('title') || el.getAttribute('data-native-title') || '';
	}
	function setTipPosition(e, el, t) {
		if (!t || !el) return;
		var pad = 8;
		var left = 0;
		var top = 0;
		var rootZoom = parseFloat(getComputedStyle(document.documentElement).zoom || '1');
		if (!Number.isFinite(rootZoom) || rootZoom <= 0) rootZoom = 1;
		var anchor = el.closest('.header-icons .header-link, .header-icons .theme-toggle, .header-icons .user-avatar');
		if (anchor) {
			var rect = anchor.getBoundingClientRect();
			left = rect.left + (rect.width / 2) - (t.offsetWidth / 2);
			top = rect.bottom + pad;
			// Header icon tooltips prioritize icon alignment over strict viewport clamping.
			// Limit horizontal correction so text does not drift far from the icon.
			var maxNudge = 40;
			var overflowLeft = pad - left;
			if (overflowLeft > 0) {
				left += Math.min(maxNudge, overflowLeft);
			}
			var overflowRight = (left + t.offsetWidth) - (window.innerWidth - pad);
			if (overflowRight > 0) {
				left -= Math.min(maxNudge, overflowRight);
			}
		} else {
			left = e.clientX + 14;
			top = e.clientY + 18;
			if (left < pad) left = pad;
			if ((left + t.offsetWidth) > (window.innerWidth - pad)) {
				left = window.innerWidth - t.offsetWidth - pad;
			}
		}
		if ((top + t.offsetHeight) > (window.innerHeight - pad)) {
			var altTop = (anchor ? anchor.getBoundingClientRect().top : e.clientY) - t.offsetHeight - pad;
			top = Math.max(pad, altTop);
		}
		// CSS zoom (html { zoom: ... }) を使っているため、fixed 座標は補正が必要。
		if (rootZoom !== 1) {
			left /= rootZoom;
			top /= rootZoom;
		}
		t.style.left = left + 'px';
		t.style.top = top + 'px';
	}
	function suppressNativeTitle(el) {
		var title = el.getAttribute('title');
		if (!title || el.getAttribute('data-tip')) return;
		el.setAttribute('data-native-title', title);
		el.removeAttribute('title');
		activeTitleEl = el;
	}
	function restoreNativeTitle(el) {
		if (!el) return;
		var saved = el.getAttribute('data-native-title');
		if (!saved) return;
		el.setAttribute('title', saved);
		el.removeAttribute('data-native-title');
		if (activeTitleEl === el) activeTitleEl = null;
	}
	function isSuppressed(e, el) {
		if (!el.getAttribute('data-tip')) return false;
		var inner = e.target.closest('.card-header-actions, button, a, input, select, textarea, label');
		if (inner && inner.closest('[data-tip]') === el) return false;
		return inner && inner !== el && el.contains(inner);
	}
	document.addEventListener('mouseover', function(e) {
		var el = getTipTarget(e);
		if (!el) return;
		if (isSuppressed(e, el)) { clearTimeout(showTimer); if (tip) tip.classList.remove('show'); return; }
		suppressNativeTitle(el);
		var t = ensureTip();
		t.textContent = getTipText(el);
		setTipPosition(e, el, t);
		clearTimeout(showTimer);
		showTimer = setTimeout(function() { t.classList.add('show'); }, 0);
	});
	document.addEventListener('mousemove', function(e) {
		if (!tip) return;
		var el = getTipTarget(e);
		if (!el) return;
		if (isSuppressed(e, el)) { tip.classList.remove('show'); return; }
		suppressNativeTitle(el);
		setTipPosition(e, el, tip);
	});
	document.addEventListener('mouseout', function(e) {
		var el = getTipTarget(e);
		if (!el) return;
		clearTimeout(showTimer);
		if (tip) tip.classList.remove('show');
		restoreNativeTitle(el);
	});
	document.addEventListener('mouseover', function(e) {
		if (!activeTitleEl) return;
		if (activeTitleEl.contains(e.target)) return;
		restoreNativeTitle(activeTitleEl);
	});
})();

function initCollapse() {
	document.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
		var header = card.querySelector(':scope > .card-header');
		var iconTarget = null;
		if (header) {
			iconTarget = header;
		} else {
			var h2 = card.querySelector(':scope > h2');
			if (h2) {
				h2.classList.add('section-toggle');
				iconTarget = h2;
			}
		}
		if (!iconTarget) return;

		if (!iconTarget.querySelector(':scope > .toggle-icon')) {
			var icon = document.createElement('span');
			icon.className = 'toggle-icon';
			icon.textContent = '\u25BC';
			iconTarget.insertBefore(icon, iconTarget.firstChild);
		}

		/* 折りたたみヒントを h2 の末尾に挿入（全カード共通） */
		var h2 = iconTarget.tagName === 'H2' ? iconTarget : iconTarget.querySelector('h2');
		if (h2 && !h2.querySelector('.collapse-hint')) {
			var hint = document.createElement('span');
			hint.className = 'collapse-hint';
			hint.textContent = '折りたたみ中です　展開するにはこちらをクリック';
			h2.appendChild(hint);
		}
		iconTarget.setAttribute('data-tip', 'クリックで折りたたみ/展開');

		if (iconTarget.dataset.collapseInit === '1') return;
		iconTarget.dataset.collapseInit = '1';

		iconTarget.addEventListener('click', function(e) {
			if (e.target.closest('.card-header-actions, button, a, input, select, textarea, label')) {
				return;
			}
			card.classList.toggle('collapsed');
			var set = loadCollapsedSet();
			if (card.classList.contains('collapsed')) {
				set[card.id] = true;
			} else {
				delete set[card.id];
			}
			saveCollapsedSet(set);
		});
	});

	document.querySelectorAll('.card-header-actions').forEach(function(el) {
		el.addEventListener('click', function(e) { e.stopPropagation(); });
	});

	var btnExpand = document.getElementById('sidenav-expand-all');
	var btnCollapse = document.getElementById('sidenav-collapse-all');
	if (btnExpand) {
		btnExpand.addEventListener('click', function() {
			document.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
				card.classList.remove('collapsed');
			});
			saveCollapsedSet({});
		});
	}
	if (btnCollapse) {
		btnCollapse.addEventListener('click', function() {
			var set = {};
			document.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
				card.classList.add('collapsed');
				set[card.id] = true;
			});
			saveCollapsedSet(set);
		});
	}
}

function initSidenav() {
	var nav = document.getElementById('sidenav');
	var fab = document.getElementById('sidenav-fab');
	if (!nav) return;
	var serverTreeToggle = document.getElementById('sidenav-server-tree-toggle');
	var serverTree = document.getElementById('sidenav-server-tree');
	function setServerTreeOpen(open) {
		if (!serverTreeToggle || !serverTree) return;
		serverTree.hidden = !open;
		serverTreeToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
		serverTreeToggle.classList.toggle('open', open);
	}
	if (serverTreeToggle && serverTree) {
		var hasAlertServer = !!serverTree.querySelector('.sidenav-server-badge.is-alert');
		var savedServerTreeOpen = loadSidenavServerTreeOpen();
		setServerTreeOpen(savedServerTreeOpen !== null ? savedServerTreeOpen : hasAlertServer);
		serverTreeToggle.addEventListener('click', function() {
			var nextOpen = serverTree.hidden;
			setServerTreeOpen(nextOpen);
			saveSidenavServerTreeOpen(nextOpen);
		});
	}
	function ensureSidenavLinkVisible(link) {
		if (!link) return;
		var linkRect = link.getBoundingClientRect();
		var navRect = nav.getBoundingClientRect();
		var padding = 12;
		if (linkRect.top < navRect.top + padding) {
			nav.scrollTop -= (navRect.top + padding - linkRect.top);
		} else if (linkRect.bottom > navRect.bottom - padding) {
			nav.scrollTop += (linkRect.bottom - (navRect.bottom - padding));
		}
	}
	nav.querySelectorAll('.sidenav-link').forEach(function(link) {
		link.addEventListener('click', function(e) {
			var id = link.getAttribute('data-target');
			var target = id && document.getElementById(id);
			if (!target) return;
			e.preventDefault();
			if (target.classList.contains('collapsed')) {
				target.classList.remove('collapsed');
				var set = loadCollapsedSet();
				delete set[id];
				saveCollapsedSet(set);
			}
			target.scrollIntoView({ behavior: 'smooth', block: 'start' });
			ensureSidenavLinkVisible(link);
			if (window.innerWidth < 1200) {
				nav.classList.remove('open');
			}
		});
	});
	initSidenavSearch(nav);
	initSidenavOrder(nav);
	var hoverZone = document.getElementById('sidenav-hover-zone');
	if (hoverZone) {
		hoverZone.addEventListener('click', function(e) {
			e.stopPropagation();
			nav.classList.toggle('open');
		});
	}
	if (fab) {
		fab.addEventListener('click', function(e) {
			e.stopPropagation();
			nav.classList.toggle('open');
		});
	}
	if (fab || hoverZone) {
		document.addEventListener('click', function(e) {
			if (window.innerWidth >= 1200) return;
			if (nav.contains(e.target)) return;
			if (fab && e.target === fab) return;
			if (hoverZone && (e.target === hoverZone || hoverZone.contains(e.target))) return;
			nav.classList.remove('open');
		});
	}
}

// 目次のカード検索。入力でカードのリンクを絞り込み、Enter で先頭の該当カードへ飛ぶ。
// 飛ぶ処理は各リンクの click ハンドラ（折りたたみ解除・スクロール）をそのまま使う。
function initSidenavSearch(nav) {
	var input = document.getElementById('sidenav-search-input');
	if (!input) return;
	var empty = document.getElementById('sidenav-search-empty');
	var list = nav.querySelector('.sidenav-list');
	if (!list) return;
	function normalize(s) {
		s = String(s || '');
		if (s.normalize) s = s.normalize('NFKC');
		return s.toLowerCase();
	}
	function firstMatch() {
		return list.querySelector('.sidenav-link[data-target]:not(.sidenav-filtered-out)');
	}
	function applyFilter() {
		var terms = normalize(input.value).split(/\s+/).filter(Boolean);
		var active = terms.length > 0;
		var matched = 0;
		var groupTitle = null;
		var groupHasMatch = false;
		function closeGroup() {
			if (groupTitle) groupTitle.classList.toggle('sidenav-filtered-out', active && !groupHasMatch);
		}
		Array.prototype.forEach.call(list.children, function(el) {
			if (el.classList.contains('sidenav-group-title')) {
				closeGroup();
				groupTitle = el;
				groupHasMatch = false;
				return;
			}
			if (!el.classList.contains('sidenav-link')) return;
			var hit = true;
			if (active) {
				// 別画面へのリンク（全サーバー概要など）は検索中は隠し、カードだけを対象にする。
				if (!el.hasAttribute('data-target')) {
					hit = false;
				} else {
					var text = normalize(el.textContent + ' ' + el.getAttribute('data-target'));
					hit = terms.every(function(t) { return text.indexOf(t) !== -1; });
				}
			}
			el.classList.toggle('sidenav-filtered-out', !hit);
			if (hit) {
				groupHasMatch = true;
				if (el.hasAttribute('data-target')) matched++;
			}
		});
		closeGroup();
		if (empty) empty.hidden = !active || matched > 0;
	}
	input.addEventListener('input', applyFilter);
	input.addEventListener('keydown', function(e) {
		if (e.isComposing) return;
		if (e.key === 'Enter') {
			e.preventDefault();
			var link = firstMatch();
			if (link) link.click();
		} else if (e.key === 'Escape') {
			if (input.value) {
				e.preventDefault();
				input.value = '';
				applyFilter();
			}
		}
	});
	// type="search" の × ボタンで消したときも一覧を戻す。
	input.addEventListener('search', applyFilter);
}

// 目次の並び順（利用者ごとに localStorage へ保存）。
// ☆ で先頭の「よく使う」へ集め、項目はドラッグで自由に並べ替える。本文のカードも目次と同じ順に並べ直す。
// 項目のキーはカードが "i:<カードID>"、別画面へのリンクが "h:<href>"、見出しが "g:<見出し>"（見出しより前の項目は ""）。
// 画面の並びは { pinned: [項目], groups: [{ key: 見出し, items: [項目] }] }、保存は groups を { 見出し: [項目] } にした形で持つ。
// 見出しごとに持つのは、グループをまたいで動かしたカードの所属を崩さないため。
// 画面やサーバーによって出るカードが違うため、保存するときは今の画面に無い項目も元の位置関係のまま残す。
var sidenavOrderDefault = null; // サーバーが出した既定の並び（元に戻すときと、☆を外したときの戻り先）

function loadSidenavOrder() {
	try {
		var raw = localStorage.getItem(SIDENAV_ORDER_KEY);
		if (!raw) return null;
		var st = JSON.parse(raw);
		if (!st || !Array.isArray(st.pinned) || !st.groups || typeof st.groups !== 'object') return null;
		function onlyKeys(arr) {
			return Array.isArray(arr) ? arr.filter(function(k) { return typeof k === 'string' && k !== ''; }) : [];
		}
		var groups = {};
		Object.keys(st.groups).forEach(function(g) { groups[g] = onlyKeys(st.groups[g]); });
		return { pinned: onlyKeys(st.pinned), groups: groups };
	} catch (e) { return null; }
}

function saveSidenavOrder(st) {
	try {
		localStorage.setItem(SIDENAV_ORDER_KEY, JSON.stringify({ pinned: st.pinned, groups: st.groups }));
	} catch (e) {}
}

function clearSidenavOrder() {
	try { localStorage.removeItem(SIDENAV_ORDER_KEY); } catch (e) {}
}

// primary の順を正とし、secondary にだけあるキーを、secondary 上で直前にあったキーの後ろへ差し込む。
// skip に含まれるキーは secondary から差し込まない（位置が別の列で決まっているキー）。
function mergeOrderTokens(primary, secondary, skip) {
	var out = [];
	primary.forEach(function(k) {
		if (out.indexOf(k) === -1) out.push(k);
	});
	var at = 0;
	(secondary || []).forEach(function(k) {
		var idx = out.indexOf(k);
		if (idx !== -1) { at = idx + 1; return; }
		if (skip && skip[k]) return;
		out.splice(at, 0, k);
		at++;
	});
	return out;
}

// 並べ替えの対象は検索欄より下（カードの目次）。上の「全サーバー概要」「サーバー一覧」などは動かさない。
function sidenavOrderParts(list) {
	var search = list && list.querySelector(':scope > .sidenav-search');
	if (!search) return null;
	var els = [];
	for (var el = search.nextElementSibling; el; el = el.nextElementSibling) els.push(el);
	return { search: search, els: els };
}

// 目次の要素へキーを振り、ドラッグの取っ手・☆・「よく使う」見出し・元に戻すボタンを足す。
function prepareSidenavOrder(nav, list) {
	var parts = sidenavOrderParts(list);
	if (!parts) return false;
	var used = {};
	function uniqueKey(k) {
		used[k] = (used[k] || 0) + 1;
		return used[k] > 1 ? k + '#' + used[k] : k;
	}
	parts.els.forEach(function(el) {
		if (el.classList.contains('sidenav-group-title')) {
			el.setAttribute('data-order-key', uniqueKey('g:' + el.textContent.trim()));
			return;
		}
		if (!el.classList.contains('sidenav-link')) return;
		var id = el.getAttribute('data-target');
		var href = el.getAttribute('href');
		if (!id && !href) return;
		el.setAttribute('data-order-key', uniqueKey(id ? 'i:' + id : 'h:' + href));
		el.setAttribute('draggable', 'true');
		// 取っ手と☆の記号は CSS で出す（textContent に混ぜると目次検索に引っかかるため）
		var grip = document.createElement('span');
		grip.className = 'sidenav-grip';
		grip.setAttribute('aria-hidden', 'true');
		grip.setAttribute('data-tip', 'ドラッグで並べ替え');
		el.insertBefore(grip, el.firstChild);
		var pin = document.createElement('span');
		pin.className = 'sidenav-pin';
		pin.setAttribute('role', 'button');
		el.appendChild(pin);
	});
	var head = document.createElement('div');
	head.className = 'sidenav-group-title sidenav-pin-group';
	head.textContent = '★ よく使う';
	var end = document.createElement('div');
	end.className = 'sidenav-pin-end';
	end.setAttribute('aria-hidden', 'true');
	list.insertBefore(end, parts.search.nextSibling);
	list.insertBefore(head, end);
	var footer = document.createElement('div');
	footer.className = 'sidenav-order-footer';
	footer.hidden = true;
	footer.innerHTML = '<button type="button" class="btn-secondary btn-sm sidenav-order-reset">並び順を元に戻す</button>';
	nav.appendChild(footer);
	return true;
}

// 今の目次の並びを読む。「よく使う」見出しから終端までが pinned、それ以降は見出しごとに groups へ入れる。
function readSidenavOrder(list) {
	var st = { pinned: [], groups: [] };
	var parts = sidenavOrderParts(list);
	if (!parts) return st;
	var inPin = false;
	var group = null;
	parts.els.forEach(function(el) {
		if (el.classList.contains('sidenav-pin-group')) { inPin = true; return; }
		if (el.classList.contains('sidenav-pin-end')) { inPin = false; return; }
		var k = el.getAttribute('data-order-key');
		if (!k) return;
		if (inPin) {
			st.pinned.push(k);
		} else if (el.classList.contains('sidenav-group-title')) {
			group = { key: k, items: [] };
			st.groups.push(group);
		} else {
			if (!group) {
				group = { key: '', items: [] };
				st.groups.push(group);
			}
			group.items.push(k);
		}
	});
	return st;
}

function findSidenavGroup(st, key) {
	for (var i = 0; i < st.groups.length; i++) {
		if (st.groups[i].key === key) return st.groups[i];
	}
	return null;
}

function renderSidenavOrder(list, st) {
	var parts = sidenavOrderParts(list);
	if (!parts) return;
	var byKey = {};
	var head = null;
	var end = null;
	parts.els.forEach(function(el) {
		if (el.classList.contains('sidenav-pin-group')) head = el;
		else if (el.classList.contains('sidenav-pin-end')) end = el;
		var k = el.getAttribute('data-order-key');
		if (k) byKey[k] = el;
	});
	var placed = [];
	var frag = document.createDocumentFragment();
	function place(el) {
		if (!el || placed.indexOf(el) !== -1) return;
		frag.appendChild(el);
		placed.push(el);
	}
	place(head);
	st.pinned.forEach(function(k) { place(byKey[k]); });
	place(end);
	st.groups.forEach(function(g) {
		if (g.key) place(byKey[g.key]);
		g.items.forEach(function(k) { place(byKey[k]); });
	});
	parts.els.forEach(place); // 並びに無い要素は元の順で末尾へ
	list.insertBefore(frag, parts.search.nextSibling);
	updateSidenavPinState(list);
}

function updateSidenavPinState(list) {
	var parts = sidenavOrderParts(list);
	if (!parts) return;
	var inPin = false;
	var head = null;
	var count = 0;
	parts.els.forEach(function(el) {
		if (el.classList.contains('sidenav-pin-group')) { inPin = true; head = el; return; }
		if (el.classList.contains('sidenav-pin-end')) { inPin = false; return; }
		if (!el.classList.contains('sidenav-link')) return;
		el.classList.toggle('is-pinned', inPin);
		var pin = el.querySelector(':scope > .sidenav-pin');
		if (pin) {
			var label = inPin ? 'よく使うから外す' : 'よく使うに追加';
			pin.setAttribute('aria-label', label);
			pin.setAttribute('data-tip', label);
		}
		if (inPin) count++;
	});
	if (head) {
		// 空のときは隠し、ドラッグ中だけ落とし先として出す
		head.classList.toggle('is-empty', count === 0);
		head.hidden = count === 0 && !list.classList.contains('is-sorting');
	}
}

// 保存された並びを今の画面に当てはめる。見出しの並びは既定のまま。
// 今の画面に無い項目は捨て、保存に無い項目（あとから増えたカード等）は既定のグループの既定の位置へ入れる。
function resolveSidenavOrder(saved, def) {
	var present = {};
	def.groups.forEach(function(g) {
		g.items.forEach(function(k) { present[k] = true; });
	});
	var placed = {};
	function take(k) {
		if (!present[k] || placed[k]) return false;
		placed[k] = true;
		return true;
	}
	var pinned = saved.pinned.filter(take);
	var groups = def.groups.map(function(g) {
		return { key: g.key, items: (saved.groups[g.key] || []).filter(take) };
	});
	def.groups.forEach(function(g, i) {
		groups[i].items = mergeOrderTokens(groups[i].items, g.items, placed);
	});
	return { pinned: pinned, groups: groups };
}

// 本文のカードを目次と同じ順に並べ直す。動かす単位は .container 直下の要素（カードを包む要素があればそれごと）。
// keepViewport のときは、画面の一番上に見えているカードの位置を保つ。
// ページ最上部にいるときは保たない（先頭へ来たカードをそのまま見せる。ブラウザのスクロール位置補正と同じ扱い）。
function reorderCardsBySidenav(list, keepViewport) {
	var container = document.querySelector('body > .container');
	if (!container) return;
	var blocks = [];
	list.querySelectorAll('.sidenav-link[data-target]').forEach(function(link) {
		var el = document.getElementById(link.getAttribute('data-target'));
		while (el && el.parentNode !== container) el = el.parentNode;
		if (el && blocks.indexOf(el) === -1) blocks.push(el);
	});
	var current = Array.prototype.filter.call(container.children, function(el) {
		return blocks.indexOf(el) !== -1;
	});
	if (current.length < 2 || current.every(function(el, i) { return el === blocks[i]; })) return;
	var anchor = null;
	var anchorTop = 0;
	if (keepViewport && window.scrollY > 0) {
		for (var i = 0; i < current.length; i++) {
			var rect = current[i].getBoundingClientRect();
			if (rect.bottom > 0) { anchor = current[i]; anchorTop = rect.top; break; }
		}
	}
	// 先頭カードの位置を基準に並べる。カード以外の要素（見出し・固定表示など）は動かさない。
	var marker = document.createComment('');
	container.insertBefore(marker, current[0]);
	blocks.forEach(function(el) { container.insertBefore(el, marker); });
	container.removeChild(marker);
	if (anchor) {
		window.scrollBy({ top: anchor.getBoundingClientRect().top - anchorTop, behavior: 'instant' });
	}
}

function updateSidenavOrderFooter(nav) {
	var footer = nav.querySelector('.sidenav-order-footer');
	if (footer) footer.hidden = !loadSidenavOrder();
}

// 並べ替えた後、検索中なら絞り込みをかけ直す（「よく使う」見出しの表示を合わせるため）。
function refreshSidenavSearch() {
	var input = document.getElementById('sidenav-search-input');
	if (input && input.value) input.dispatchEvent(new Event('input'));
}

// 保存済みの並びを目次と本文へ当てる。layout.html の本文直後で呼び、描画前に並べ替えてチラつきを防ぐ。
// initSidenavOrder からも呼ぶが、2 回目以降は何もしない。
function applySidenavOrder() {
	if (sidenavOrderDefault) return;
	var nav = document.getElementById('sidenav');
	var list = nav && nav.querySelector('.sidenav-list');
	if (!list || !prepareSidenavOrder(nav, list)) return;
	sidenavOrderDefault = readSidenavOrder(list);
	var saved = loadSidenavOrder();
	if (saved) {
		renderSidenavOrder(list, resolveSidenavOrder(saved, sidenavOrderDefault));
		reorderCardsBySidenav(list, false);
	} else {
		updateSidenavPinState(list);
	}
	updateSidenavOrderFooter(nav);
}

// 今の画面の並び cur を保存する形にする。今の画面に無い項目・見出しは前回の保存 old から引き継ぐ。
function buildSavedSidenavOrder(cur, old) {
	var present = {};
	cur.pinned.forEach(function(k) { present[k] = true; });
	cur.groups.forEach(function(g) {
		g.items.forEach(function(k) { present[k] = true; });
	});
	var groups = {};
	cur.groups.forEach(function(g) {
		groups[g.key] = mergeOrderTokens(g.items, old && old.groups[g.key], present);
	});
	if (old) {
		Object.keys(old.groups).forEach(function(key) {
			if (Object.prototype.hasOwnProperty.call(groups, key)) return;
			var items = old.groups[key].filter(function(k) { return !present[k]; });
			if (items.length) groups[key] = items;
		});
	}
	return { pinned: mergeOrderTokens(cur.pinned, old && old.pinned, present), groups: groups };
}

// ☆の切り替え。付けると「よく使う」の末尾へ移し、外すと既定のグループの既定の位置へ戻す。st を書き換える。
function toggleSidenavPin(st, key, def) {
	var idx = st.pinned.indexOf(key);
	if (idx === -1) {
		st.pinned.push(key);
		st.groups.forEach(function(g) {
			g.items = g.items.filter(function(k) { return k !== key; });
		});
		return st;
	}
	st.pinned.splice(idx, 1);
	var placed = {};
	st.pinned.forEach(function(k) { placed[k] = true; });
	st.groups.forEach(function(g) {
		g.items.forEach(function(k) { placed[k] = true; });
	});
	def.groups.forEach(function(dg) {
		if (dg.items.indexOf(key) === -1) return;
		var g = findSidenavGroup(st, dg.key);
		if (!g) {
			// 見出しより前の項目がいまは 1 件も無いときは、その場所を作り直す
			g = { key: dg.key, items: [] };
			st.groups.unshift(g);
		}
		g.items = mergeOrderTokens(g.items, dg.items, placed);
	});
	return st;
}

// ☆で並べ直すと、途中でブラウザが目次のスクロール位置を動かす。行をいったん全部外して入れ直すため、
// フォーカスを持つリンク（押した行や、前にクリックした行）を外した瞬間に、短くなった目次でレイアウトが計算される。
// 並べ直す前に目次に見えている先頭の行を覚え、並べ直した後に同じ位置へ戻す。
// 動かす行と、出たり消えたりする「よく使う」見出しは基準にしない。
function findSidenavScrollAnchor(nav, list, exclude) {
	var header = nav.querySelector('.sidenav-header');
	var top = nav.getBoundingClientRect().top + (header ? header.offsetHeight : 0);
	var els = list.querySelectorAll('.sidenav-link, .sidenav-group-title:not(.sidenav-pin-group)');
	for (var i = 0; i < els.length; i++) {
		var el = els[i];
		if (el === exclude || el.offsetParent === null) continue;
		var rect = el.getBoundingClientRect();
		if (rect.bottom > top) return { el: el, top: rect.top };
	}
	return null;
}

function restoreSidenavScrollAnchor(nav, anchor) {
	if (!anchor || anchor.el.offsetParent === null) return;
	var diff = anchor.el.getBoundingClientRect().top - anchor.top;
	if (diff) nav.scrollTop += diff;
}

// 今の目次の並びを保存し、本文のカードも並べ直す。
function commitSidenavOrder(nav, list) {
	saveSidenavOrder(buildSavedSidenavOrder(readSidenavOrder(list), loadSidenavOrder()));
	updateSidenavPinState(list);
	reorderCardsBySidenav(list, true);
	updateSidenavOrderFooter(nav);
	refreshSidenavSearch();
}

function initSidenavOrder(nav) {
	applySidenavOrder();
	var list = nav.querySelector('.sidenav-list');
	if (!list || !sidenavOrderDefault) return;

	// ☆: capture で拾い、リンク本体のクリック（カードへスクロール）より先に止める。
	list.addEventListener('click', function(e) {
		var pin = e.target.closest && e.target.closest('.sidenav-pin');
		var link = pin && pin.closest('.sidenav-link[data-order-key]');
		if (!link) return;
		e.preventDefault();
		e.stopPropagation();
		var anchor = findSidenavScrollAnchor(nav, list, link);
		var st = toggleSidenavPin(readSidenavOrder(list), link.getAttribute('data-order-key'), sidenavOrderDefault);
		renderSidenavOrder(list, st);
		commitSidenavOrder(nav, list);
		restoreSidenavScrollAnchor(nav, anchor);
	}, true);

	// ドラッグ: 項目の上半分なら前、下半分なら後ろへ入れる。見出しへ落としたらそのグループの先頭へ入れる。
	var dragEl = null;
	var drop = null;
	function clearDropMark() {
		list.querySelectorAll('.drop-before, .drop-after').forEach(function(el) {
			el.classList.remove('drop-before', 'drop-after');
		});
	}
	function findDrop(e) {
		var node = e.target && e.target.nodeType === 1 ? e.target : (e.target && e.target.parentElement);
		var t = node && node.closest('.sidenav-link[data-order-key], .sidenav-group-title[data-order-key], .sidenav-pin-group');
		if (t && list.contains(t)) {
			if (t === dragEl) return null;
			if (t.classList.contains('sidenav-group-title')) return { el: t, where: 'after' };
			var rect = t.getBoundingClientRect();
			return { el: t, where: e.clientY < rect.top + rect.height / 2 ? 'before' : 'after' };
		}
		// 一覧の最後より下で離したら最後尾へ
		var parts = sidenavOrderParts(list);
		for (var i = parts.els.length - 1; i >= 0; i--) {
			var last = parts.els[i];
			if (!last.hasAttribute('data-order-key') || last.offsetParent === null) continue;
			if (last !== dragEl && e.clientY > last.getBoundingClientRect().bottom) return { el: last, where: 'after' };
			break;
		}
		return null;
	}
	function autoScroll(e) {
		var rect = nav.getBoundingClientRect();
		var header = nav.querySelector('.sidenav-header');
		var top = rect.top + (header ? header.offsetHeight : 0);
		var edge = 40;
		if (e.clientY < top + edge) nav.scrollTop -= 12;
		else if (e.clientY > rect.bottom - edge) nav.scrollTop += 12;
	}
	function finishDrag() {
		clearDropMark();
		if (dragEl) dragEl.classList.remove('is-dragging');
		dragEl = null;
		drop = null;
		list.classList.remove('is-sorting');
		updateSidenavPinState(list);
	}
	nav.addEventListener('dragstart', function(e) {
		var link = e.target.closest && e.target.closest('.sidenav-link[data-order-key]');
		if (!link || !list.contains(link)) return;
		dragEl = link;
		e.dataTransfer.effectAllowed = 'move';
		try { e.dataTransfer.setData('text/plain', link.textContent.trim()); } catch (err) {}
		// dragstart の中で DOM を動かすとドラッグが中断されることがあるため、見た目の変更は次の tick で行う
		setTimeout(function() {
			if (dragEl !== link) return;
			link.classList.add('is-dragging');
			list.classList.add('is-sorting');
			updateSidenavPinState(list);
		}, 0);
	});
	nav.addEventListener('dragover', function(e) {
		if (!dragEl) return;
		e.preventDefault();
		autoScroll(e);
		clearDropMark();
		drop = findDrop(e);
		e.dataTransfer.dropEffect = drop ? 'move' : 'none';
		if (drop) drop.el.classList.add(drop.where === 'before' ? 'drop-before' : 'drop-after');
	});
	nav.addEventListener('drop', function(e) {
		if (!dragEl) return;
		e.preventDefault();
		var target = drop;
		var moved = dragEl;
		finishDrag();
		if (!target) return;
		list.insertBefore(moved, target.where === 'before' ? target.el : target.el.nextSibling);
		commitSidenavOrder(nav, list);
	});
	nav.addEventListener('dragend', finishDrag);

	var resetBtn = nav.querySelector('.sidenav-order-reset');
	if (resetBtn) {
		resetBtn.addEventListener('click', function() {
			var msg = '目次と本文カードの並び順を最初の状態に戻します。★ よく使う もすべて外れます。よろしいですか？';
			var ask = typeof window.confirmModal === 'function' ? window.confirmModal(msg) : Promise.resolve(window.confirm(msg));
			ask.then(function(ok) {
				if (!ok) return;
				clearSidenavOrder();
				renderSidenavOrder(list, sidenavOrderDefault);
				reorderCardsBySidenav(list, true);
				updateSidenavOrderFooter(nav);
				refreshSidenavSearch();
			});
		});
	}
}

function initScrollSpy() {
	var nav = document.getElementById('sidenav');
	var links = {};
	document.querySelectorAll('#sidenav .sidenav-link').forEach(function(link) {
		var id = link.getAttribute('data-target');
		if (id) links[id] = link;
	});
	var sections = document.querySelectorAll('section.card[id^="sec-"]');
	if (!sections.length || !('IntersectionObserver' in window)) return;

	var visible = {};
	var lastActiveId = null;
	var observer = new IntersectionObserver(function(entries) {
		entries.forEach(function(entry) {
			if (entry.isIntersecting) {
				visible[entry.target.id] = entry.intersectionRatio;
			} else {
				delete visible[entry.target.id];
			}
		});
		var topId = null;
		var topY = Infinity;
		Object.keys(visible).forEach(function(id) {
			var el = document.getElementById(id);
			if (!el) return;
			var y = el.getBoundingClientRect().top;
			if (y < topY) { topY = y; topId = id; }
		});
		Object.keys(links).forEach(function(id) {
			links[id].classList.toggle('active', id === topId);
		});
		if (nav && topId && topId !== lastActiveId && links[topId]) {
			var linkRect = links[topId].getBoundingClientRect();
			var navRect = nav.getBoundingClientRect();
			var padding = 12;
			if (linkRect.top < navRect.top + padding) {
				nav.scrollTop -= (navRect.top + padding - linkRect.top);
			} else if (linkRect.bottom > navRect.bottom - padding) {
				nav.scrollTop += (linkRect.bottom - (navRect.bottom - padding));
			}
			lastActiveId = topId;
		}
	}, { rootMargin: '-80px 0px -60% 0px', threshold: [0, 0.1, 0.5] });

	sections.forEach(function(s) { observer.observe(s); });
}

function initThemeToggle() {
	var toggle = document.getElementById('themeToggle');
	if (!toggle) return;
	var body = document.body;
	var storageKey = 'heartdesk_theme';
	var saved = localStorage.getItem(storageKey) || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
	body.setAttribute('data-theme', saved);
	toggle.textContent = saved === 'dark' ? '\u{1F319}' : '\u{2600}\u{FE0F}';
	toggle.addEventListener('click', function() {
		var current = body.getAttribute('data-theme');
		var next = current === 'dark' ? 'light' : 'dark';
		body.setAttribute('data-theme', next);
		toggle.textContent = next === 'dark' ? '\u{1F319}' : '\u{2600}\u{FE0F}';
		localStorage.setItem(storageKey, next);
	});
}

function initHeaderControls() {
	document.querySelectorAll('[data-page-reload]').forEach(function(el) {
		if (el.getAttribute('data-page-reload-bound') === '1') return;
		el.setAttribute('data-page-reload-bound', '1');
		el.addEventListener('click', function(e) {
			e.preventDefault();
			window.location.reload();
		});
	});

	var input = document.getElementById('header-ip-input');
	var button = document.getElementById('header-ip-search-btn');
	if (!input || !button) return;

	function runSearch() {
		var v = (input.value || '').trim();
		if (window.__heartdeskIsValidIP && window.__heartdeskIsValidIP(v) && typeof window.openIpModal === 'function') {
			input.removeAttribute('aria-invalid');
			window.openIpModal(v);
			return;
		}
		input.setAttribute('aria-invalid', 'true');
		input.focus();
	}
	button.addEventListener('click', runSearch);
	input.addEventListener('keydown', function(e) {
		if (e.key === 'Enter') {
			e.preventDefault();
			runSearch();
		}
	});
	input.addEventListener('input', function() {
		input.removeAttribute('aria-invalid');
	});
}

function initSharedUi() {
	applyCollapseState();
	applyCardGroupLabels();
	initCollapse();
	initSidenav();
	initScrollSpy();
	initThemeToggle();
	initHeaderControls();
}

function applyCardGroupLabels(root) {
	var target = root || document;
	var meta = (typeof HD_CARD_META !== 'undefined' && HD_CARD_META) ? HD_CARD_META : {};
	target.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
		var h2 = card.querySelector(':scope > .card-header h2')
			|| card.querySelector(':scope > h2');
		if (!h2) return;
		var cardMeta = meta[card.id] || null;
		var group = cardMeta && cardMeta.group ? String(cardMeta.group) : '';
		var label = h2.querySelector('.card-parent-group');
		if (!group) {
			if (label && label.parentNode) label.parentNode.removeChild(label);
			return;
		}
		if (!label) {
			label = document.createElement('span');
			label.className = 'card-parent-group';
			h2.insertBefore(label, h2.firstChild);
		}
		label.textContent = group;
	});
}
window.applyCardGroupLabels = applyCardGroupLabels;

// フィルター入力にブラウザのオートフィル（ユーザー名候補等）が差し込まれるのを抑止する
// Chrome は name="user"/"filter_*" 等の input を見て autocomplete="off" を無視することがあるため、
// .filter-input / .filter-select には name 属性を付与せず、複数属性で保険をかける。
// さらに Chrome は placeholder/周辺テキストから input を誤判定して強制フィルするため、
// readonly を初期付与 → ユーザー操作（focus/pointerdown/touchstart/keydown）で解除する二段構え。
function armReadonlyAutofillGuard(el) {
	// select や既に type=hidden などは除外
	if (el.tagName !== 'INPUT') return;
	if (el.readOnly) return;
	el.setAttribute('readonly', 'readonly');
	var release = function() {
		el.removeAttribute('readonly');
		el.removeEventListener('focus', release);
		el.removeEventListener('pointerdown', release);
		el.removeEventListener('touchstart', release);
		el.removeEventListener('keydown', release);
	};
	el.addEventListener('focus', release);
	el.addEventListener('pointerdown', release);
	el.addEventListener('touchstart', release);
	el.addEventListener('keydown', release);
}
function suppressFilterAutofill(root) {
	var target = root || document;
	target.querySelectorAll('.filter-input, .filter-select').forEach(function(el) {
		if (el.getAttribute('data-autofill-guarded') === '1') return;
		el.removeAttribute('name');
		el.setAttribute('autocomplete', 'off');
		el.setAttribute('autocorrect', 'off');
		el.setAttribute('autocapitalize', 'off');
		el.setAttribute('spellcheck', 'false');
		el.setAttribute('data-form-type', 'other');
		el.setAttribute('data-lpignore', 'true');
		el.setAttribute('data-1p-ignore', 'true');
		if (el.tagName === 'INPUT' && el.type === 'text') {
			el.type = 'search';
		}
		armReadonlyAutofillGuard(el);
		el.setAttribute('data-autofill-guarded', '1');
	});
}

// サーバーレンダリング済みカード（Cron等）のフィルターと行番号を初期化する
function initStaticCardFilters(root) {
	var target = root || document;
	suppressFilterAutofill(target);
	target.querySelectorAll('.thead-filter-row').forEach(function(filterBar) {
		// 既にフィルター初期化済みなら skip（filter-input に data-multi-init 等がつく）
		if (filterBar.getAttribute('data-filter-init') === '1') return;
		filterBar.setAttribute('data-filter-init', '1');
		var container = filterBar.closest('section') || filterBar.closest('[data-card]') || filterBar.parentElement;
		if (!container) return;
		setupCardFilter(filterBar, container);
		addRowNumbers(container);
	});
	// フィルターなしのログテーブルにも行番号を付与
	target.querySelectorAll('table.log-table').forEach(function(table) {
		if (table.classList.contains('row-num-init')) return;
		var container = table.closest('section') || table.parentElement;
		if (container) addRowNumbers(container);
	});
}

// JS で動的に挿入される .filter-input / .filter-select にもオートフィル抑止を効かせるため、
// body subtree を軽量監視し、追加要素だけスイープする
function observeFilterAutofill() {
	if (!document.body || typeof MutationObserver === 'undefined') return;
	var scheduled = false;
	var observer = new MutationObserver(function(mutations) {
		for (var i = 0; i < mutations.length; i++) {
			var m = mutations[i];
			if (m.type !== 'childList' || !m.addedNodes || !m.addedNodes.length) continue;
			for (var j = 0; j < m.addedNodes.length; j++) {
				var node = m.addedNodes[j];
				if (node.nodeType !== 1) continue;
				if (node.matches && (node.matches('.filter-input') || node.matches('.filter-select'))) {
					scheduled = true;
					break;
				}
				if (node.querySelector && node.querySelector('.filter-input, .filter-select')) {
					scheduled = true;
					break;
				}
			}
			if (scheduled) break;
		}
		if (scheduled) {
			scheduled = false;
			suppressFilterAutofill(document);
		}
	});
	observer.observe(document.body, { childList: true, subtree: true });
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', initSharedUi);
	document.addEventListener('DOMContentLoaded', function() { initStaticCardFilters(); });
	document.addEventListener('DOMContentLoaded', initUserAvatar);
	document.addEventListener('DOMContentLoaded', observeFilterAutofill);
} else {
	initSharedUi();
	initStaticCardFilters();
	initUserAvatar();
	observeFilterAutofill();
}

function initUserAvatar() {
	var btn = document.getElementById('userAvatarBtn');
	var dropdown = document.getElementById('userDropdown');
	if (!btn || !dropdown) return;
	btn.addEventListener('click', function(e) {
		e.stopPropagation();
		var open = dropdown.classList.contains('open');
		dropdown.classList.toggle('open', !open);
		btn.setAttribute('aria-expanded', String(!open));
	});
	document.addEventListener('click', function(e) {
		var wrap = document.getElementById('userAvatarWrap');
		if (wrap && !wrap.contains(e.target)) {
			dropdown.classList.remove('open');
			btn.setAttribute('aria-expanded', 'false');
		}
	});
	document.addEventListener('keydown', function(e) {
		if (e.key === 'Escape') {
			dropdown.classList.remove('open');
			btn.setAttribute('aria-expanded', 'false');
		}
	});
}

// カード更新後にも再初期化
document.addEventListener('card:refreshed', function(ev) {
	var cardId = ev && ev.detail && ev.detail.cardId;
	var card = cardId ? document.getElementById(cardId) : null;
	if (card) initStaticCardFilters(card);
});

// =============================================================================
// Shared card renderers (services/resources/r2/nc_storage/login_history/etc.)
// =============================================================================

// --- R2 Metrics ---
function renderR2Metrics(data, fetchedAt) {
	var content = document.getElementById('r2-content');
	if (!content) return;
	content.textContent = '';

	var bytes = parseInt(data.storage?.payloadSize || 0);
	var objects = parseInt(data.storage?.objectCount || 0);
	var limitBytes = 9 * 1024 * 1024 * 1024;
	var pct = Math.min((bytes / limitBytes * 100), 100).toFixed(1);
	var sizeStr = formatBytes(bytes);
	var colorClass = barColorClass(pct);

	var grid = document.createElement('div');
	grid.className = 'stats-grid';

	var storageBox = document.createElement('div');
	storageBox.className = 'stat-box';
	var storageLabel = document.createElement('span');
	storageLabel.className = 'stat-label';
	storageLabel.textContent = 'ストレージ使用量';
	var storageVal = document.createElement('span');
	storageVal.className = 'stat-value ' + colorClass;
	storageVal.textContent = sizeStr + ' / 9.0 GB (' + pct + '%)';
	var barOuter = document.createElement('div');
	barOuter.className = 'bar';
	var barInner = document.createElement('div');
	barInner.className = 'bar-fill ' + colorClass;
	barInner.style.width = pct + '%';
	barOuter.appendChild(barInner);
	storageBox.appendChild(storageLabel);
	storageBox.appendChild(storageVal);
	storageBox.appendChild(barOuter);
	grid.appendChild(storageBox);

	var objBox = document.createElement('div');
	objBox.className = 'stat-box';
	var objLabel = document.createElement('span');
	objLabel.className = 'stat-label';
	objLabel.textContent = 'オブジェクト数';
	var objVal = document.createElement('span');
	objVal.className = 'stat-value';
	objVal.textContent = objects.toLocaleString();
	objBox.appendChild(objLabel);
	objBox.appendChild(objVal);
	grid.appendChild(objBox);

	var timeBox = document.createElement('div');
	timeBox.className = 'stat-box';
	var timeLabel = document.createElement('span');
	timeLabel.className = 'stat-label';
	timeLabel.textContent = '取得時刻';
	var timeVal = document.createElement('span');
	timeVal.className = 'stat-value';
	timeVal.textContent = fetchedAt;
	timeBox.appendChild(timeLabel);
	timeBox.appendChild(timeVal);
	grid.appendChild(timeBox);

	content.appendChild(grid);

	var subCards = document.createElement('div');
	subCards.className = 'r2-sub-cards';

	if (data.storage && data.storage.buckets) {
		var buckets = data.storage.buckets;
		var bucketCard = document.createElement('div');
		bucketCard.className = 'r2-sub-card';

		var bh3 = document.createElement('h3');
		bh3.textContent = 'バケット別内訳';
		bucketCard.appendChild(bh3);

		var bTable = document.createElement('table');
		var bThead = document.createElement('thead');
		var bHeadRow = document.createElement('tr');
		['バケット', 'オブジェクト', 'サイズ'].forEach(function(text) {
			var th = document.createElement('th');
			th.textContent = text;
			bHeadRow.appendChild(th);
		});
		bThead.appendChild(bHeadRow);
		bTable.appendChild(bThead);

		var bTbody = document.createElement('tbody');
		Object.keys(buckets).forEach(function(name) {
			var b = buckets[name];
			var tr = document.createElement('tr');
			var tdName = document.createElement('td');
			tdName.textContent = name;
			var tdObj = document.createElement('td');
			tdObj.textContent = parseInt(b.objectCount || 0).toLocaleString();
			var tdSize = document.createElement('td');
			tdSize.textContent = formatBytes(parseInt(b.payloadSize || 0));
			tr.appendChild(tdName);
			tr.appendChild(tdObj);
			tr.appendChild(tdSize);
			bTbody.appendChild(tr);
		});
		bTable.appendChild(bTbody);
		bucketCard.appendChild(bTable);
		subCards.appendChild(bucketCard);
	}

	if (data.operations) {
		var ops = data.operations;
		var opsCard = document.createElement('div');
		opsCard.className = 'r2-sub-card';

		var h3 = document.createElement('h3');
		h3.textContent = '当月操作回数（' + ops.month + '）';
		opsCard.appendChild(h3);

		var table = document.createElement('table');
		var thead = document.createElement('thead');
		var headRow = document.createElement('tr');
		['種別', '回数', '無料枠', '使用率'].forEach(function(text) {
			var th = document.createElement('th');
			th.textContent = text;
			headRow.appendChild(th);
		});
		thead.appendChild(headRow);
		table.appendChild(thead);

		var tbody = document.createElement('tbody');
		var aPct = (ops.class_a / 1000000 * 100).toFixed(2);
		var bPct = (ops.class_b / 10000000 * 100).toFixed(2);
		[
			['クラスA（書込）', ops.class_a.toLocaleString(), '1,000,000', aPct + '%'],
			['クラスB（読取）', ops.class_b.toLocaleString(), '10,000,000', bPct + '%']
		].forEach(function(row) {
			var tr = document.createElement('tr');
			row.forEach(function(cell) {
				var td = document.createElement('td');
				td.textContent = cell;
				tr.appendChild(td);
			});
			tbody.appendChild(tr);
		});
		table.appendChild(tbody);
		opsCard.appendChild(table);

		var note = document.createElement('p');
		note.className = 'r2-note';
		note.textContent = '無料枠: ストレージ 10GB/月、クラスA 100万回/月、クラスB 1,000万回/月、エグレス無料';
		opsCard.appendChild(note);
		subCards.appendChild(opsCard);
	}

	content.appendChild(subCards);
}

var r2MetricsPromise = null;
function r2MetricsCacheKey() {
	var agent = (typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) ? String(HD_AGENT_ID) : '';
	return agent ? ('r2_metrics:' + agent) : 'r2_metrics';
}
function getR2Metrics(forceFetch) {
	var cacheKey = r2MetricsCacheKey();
	if (!forceFetch) {
		var cached = localStorage.getItem(cacheKey);
		if (cached) {
			try {
				var parsed = JSON.parse(cached);
				if (parsed && parsed.data) {
					return Promise.resolve({ data: parsed.data, fetchedAt: parsed.fetchedAt, fromCache: true });
				}
			} catch (e) {}
		}
		if (r2MetricsPromise) return r2MetricsPromise;
	}
	var url = getAppBase() + '/?r2_metrics=1';
	if (typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) {
		url += '&agent=' + encodeURIComponent(HD_AGENT_ID);
	}
	r2MetricsPromise = fetch(url)
		.then(function(r) {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		})
		.then(function(data) {
			var fetchedAt = formatDateTime(new Date());
			localStorage.setItem(cacheKey, JSON.stringify({data: data, fetchedAt: fetchedAt}));
			return { data: data, fetchedAt: fetchedAt, fromCache: false };
		})
		.catch(function(err) {
			return { error: err.message };
		})
		.then(function(res) {
			r2MetricsPromise = null;
			return res;
		});
	return r2MetricsPromise;
}

// --- Nextcloud Storage ---
function loadNcStorageCard() {
	var container = document.getElementById('async-nc-storage');
	if (!container) return;
	container.innerHTML = '<div class="section-loading">読み込み中...</div>';

	var ncReq = fetch(getAppBase() + '/?api=nc_storage')
		.then(function(r) {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		});
	ncReq
		.then(function(data) {
			renderNcStorageCard(container, data, null);
			touchLastUpdated();
		})
		.catch(function(err) {
			container.innerHTML = '<div class="section-error">読み込みに失敗しました: ' + escapeHtml(err.message) + '</div>';
		});
}

function renderNcStorageCard(container, data, r2Data) {
	container.textContent = '';
	if (!data || data.error) {
		container.innerHTML = '<div class="section-error">Nextcloudストレージの取得に失敗しました</div>';
		return;
	}

	var errors = data.errors || {};
	if (errors.users || errors.groupfolders) {
		var errLine = [];
		if (errors.users) errLine.push('ユーザー取得: ' + errors.users);
		if (errors.groupfolders) errLine.push('グループフォルダー取得: ' + errors.groupfolders);
		var errBox = document.createElement('div');
		errBox.className = 'section-error';
		errBox.textContent = errLine.join(' / ');
		container.appendChild(errBox);
	}

	var grid = document.createElement('div');
	grid.className = 'stats-grid stats-grid-child';

	var userBox = buildQuotaStatBox(
		'ユーザー合計',
		data.users ? data.users.used : 0,
		data.users ? data.users.quota : 0,
		data.users ? data.users.unlimited : 0,
		data.users ? data.users.users : 0
	);
	grid.appendChild(userBox);

	var gfBox = buildQuotaStatBox(
		'グループフォルダー合計',
		data.groupfolders_totals ? data.groupfolders_totals.size : 0,
		data.groupfolders_totals ? data.groupfolders_totals.quota : 0,
		data.groupfolders_totals ? data.groupfolders_totals.unlimited : 0,
		data.groupfolders ? data.groupfolders.length : 0
	);
	grid.appendChild(gfBox);

	var r2Box = document.createElement('div');
	r2Box.className = 'stat-box';
	r2Box.id = 'nc-storage-r2-box';
	if (r2Data && r2Data.storage) {
		renderR2StatBox(r2Box, r2Data);
	} else {
		renderR2StatBoxPlaceholder(r2Box);
	}
	grid.appendChild(r2Box);
	container.appendChild(grid);

	if (data.groupfolders && data.groupfolders.length > 0) {
		var list = data.groupfolders.slice().sort(function(a, b) {
			return (b.size || 0) - (a.size || 0);
		});
		var h3 = document.createElement('h3');
		h3.style.marginTop = '1rem';
		h3.style.fontSize = '0.95rem';
		h3.style.color = '#aaa';
		h3.textContent = 'グループフォルダー内訳';
		container.appendChild(h3);

		var gfGrid = document.createElement('div');
		gfGrid.className = 'stats-grid stats-grid-child';
		list.forEach(function(f) {
			var name = f.mount_point || '(未設定)';
			var box = buildQuotaStatBox(
				name,
				parseInt(f.size || 0),
				f.quota ? parseInt(f.quota) : 0,
				0,
				0
			);
			gfGrid.appendChild(box);
		});
		container.appendChild(gfGrid);
	}

	if (r2Data && r2Data.error) {
		var r2Err = document.createElement('div');
		r2Err.className = 'section-error';
		r2Err.textContent = '外部ストレージ (R2) 取得に失敗しました: ' + r2Data.error;
		container.appendChild(r2Err);
	}
}

function renderR2StatBox(box, r2Data) {
	box.textContent = '';
	box.classList.add('stat-box-refreshable');
	var r2Total = parseInt(r2Data.storage.payloadSize || 0);
	var r2Obj = parseInt(r2Data.storage.objectCount || 0);
	var r2Label = document.createElement('span');
	r2Label.className = 'stat-label';
	r2Label.textContent = '外部ストレージ (R2)';
	var r2Val = document.createElement('span');
	r2Val.className = 'stat-value';
	r2Val.textContent = formatBytes(r2Total) + ' / ' + r2Obj.toLocaleString() + ' オブジェクト';
	box.appendChild(r2Label);
	box.appendChild(r2Val);
	// 再取得用の更新ボタンを維持
	var btn = document.createElement('button');
	btn.className = 'btn-card-refresh';
	btn.textContent = '更新';
	btn.addEventListener('click', function() {
		btn.disabled = true;
		btn.classList.add('spinning');
		btn.textContent = '更新中…';
		getR2Metrics(true)
			.then(function(res) {
				if (res && res.data && res.data.storage) {
					renderR2StatBox(box, res.data);
				} else {
					btn.disabled = false;
					btn.classList.remove('spinning');
					btn.classList.add('error');
					btn.textContent = '失敗';
					setTimeout(function() { btn.classList.remove('error'); btn.textContent = '更新'; }, 2000);
				}
			})
			.catch(function() {
				btn.disabled = false;
				btn.classList.remove('spinning');
				btn.textContent = '更新';
			});
	});
	box.appendChild(btn);
}

function renderR2StatBoxPlaceholder(box) {
	box.textContent = '';
	box.classList.add('stat-box-refreshable');
	var r2Label = document.createElement('span');
	r2Label.className = 'stat-label';
	r2Label.textContent = '外部ストレージ (R2)';
	var r2Val = document.createElement('span');
	r2Val.className = 'stat-value';
	r2Val.style.color = 'var(--text-secondary)';
	r2Val.textContent = '—';
	var btn = document.createElement('button');
	btn.className = 'btn-card-refresh';
	btn.textContent = '更新';
	btn.addEventListener('click', function() {
		btn.disabled = true;
		btn.classList.add('spinning');
		btn.textContent = '更新中…';
		getR2Metrics(true)
			.then(function(res) {
				if (res && res.data && res.data.storage) {
					renderR2StatBox(box, res.data);
				} else {
					btn.disabled = false;
					btn.classList.remove('spinning');
					btn.classList.add('error');
					btn.textContent = '失敗';
					setTimeout(function() {
						btn.classList.remove('error');
						btn.textContent = '更新';
					}, 2000);
				}
			})
			.catch(function() {
				btn.disabled = false;
				btn.classList.remove('spinning');
				btn.textContent = '更新';
			});
	});
	box.appendChild(r2Label);
	box.appendChild(r2Val);
	box.appendChild(btn);
}

function buildQuotaStatBox(title, used, quota, unlimited, count) {
	var box = document.createElement('div');
	box.className = 'stat-box';
	var label = document.createElement('span');
	label.className = 'stat-label';
	label.textContent = title;
	var val = document.createElement('span');
	val.className = 'stat-value';

	var usedStr = formatBytes(parseInt(used || 0));
	var quotaStr = quota > 0 ? formatBytes(parseInt(quota)) : '無制限';
	if (unlimited > 0) {
		quotaStr += ' (無制限' + formatCount(unlimited) + '件)';
	}
	var suffix = count ? ' / ' + formatCount(count) + '件' : '';
	if (quota > 0) {
		var pct = Math.min((used / quota * 100), 100).toFixed(1);
		val.textContent = usedStr + ' / ' + quotaStr + ' (' + pct + '%)' + suffix;
		var colorClass = barColorClass(pct);
		var barOuter = document.createElement('div');
		barOuter.className = 'bar';
		var barInner = document.createElement('div');
		barInner.className = 'bar-fill ' + colorClass;
		barInner.style.width = pct + '%';
		barOuter.appendChild(barInner);
		box.appendChild(label);
		box.appendChild(val);
		box.appendChild(barOuter);
		return box;
	}
	val.textContent = usedStr + ' / ' + quotaStr + suffix;
	box.appendChild(label);
	box.appendChild(val);
	return box;
}

function fetchR2Metrics() {
	var btn = document.getElementById('r2-fetch-btn');
	var origLabel = btn ? btn.textContent : '';
	if (btn) {
		btn.disabled = true;
		btn.textContent = '取得中...';
	}
	// 折りたたまれていたら展開（データが見えないのを防ぐ）
	var secR2 = getMonitorCardId('R2', 'sec-r2');
	var r2Card = document.getElementById(secR2);
	if (r2Card && r2Card.classList.contains('collapsed')) {
		r2Card.classList.remove('collapsed');
		var set = loadCollapsedSet();
		delete set[secR2];
		saveCollapsedSet(set);
	}
	var loadingEl = document.getElementById('r2-content');
	loadingEl.textContent = '';
	var loadingP = document.createElement('p');
	loadingP.style.color = '#aaa';
	loadingP.textContent = 'Cloudflare APIからデータを更新中...';
	loadingEl.appendChild(loadingP);

	getR2Metrics(true)
		.then(function(res) {
			if (res && res.data) {
				renderR2Metrics(res.data, res.fetchedAt);
				touchLastUpdated();
				return;
			}
			throw new Error(res && res.error ? res.error : 'unknown error');
		})
		.catch(function(err) {
			var errEl = document.getElementById('r2-content');
			errEl.textContent = '';
			var errP = document.createElement('p');
			errP.style.color = '#ff5252';
			errP.textContent = '取得に失敗しました: ' + err.message;
			errEl.appendChild(errP);
		})
		.then(function() {
			if (btn) {
				btn.disabled = false;
				btn.textContent = origLabel;
			}
		});
}

// R2 cache display on page load
(function() {
	var cached = localStorage.getItem(r2MetricsCacheKey());
	if (cached) {
		try {
			var parsed = JSON.parse(cached);
			renderR2Metrics(parsed.data, parsed.fetchedAt);
		} catch(e) {}
	}
})();

// ========================================
// SSL (resources card)
// ========================================
function renderSsl(container, data) {
	container.innerHTML = '';
	container.classList.remove('section-loading');
	var box1 = document.createElement('div');
	var daysClass = data.ssl_days < 14 ? 'danger' : (data.ssl_days < 30 ? 'warning' : 'ok');
	var sslDomain = (typeof SERVER_DOMAIN !== 'undefined' && SERVER_DOMAIN) ? SERVER_DOMAIN : 'localhost';
	var btnHtml = '';
	var opts = getCardOptions('resources');
	var showRenew = opts.show_ssl_renew !== false && data.renew_allowed !== false;
	if (showRenew && data.ssl_days <= 30) {
		btnHtml = '<button id="ssl-renew-btn" class="btn-primary btn-sm">手動更新</button>';
	}
	box1.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">' +
		'<div><span class="stat-value ' + daysClass + '">残り ' + data.ssl_days + ' 日 (' + escapeHtml(data.ssl_expiry || '') + ')</span>' +
		'<span class="le-detail">' + escapeHtml(sslDomain) + '</span>' +
		(data.ssl_renewal_date ? '<span class="le-detail">次回更新予定: ' + escapeHtml(data.ssl_renewal_date) + '</span>' : '') +
		'</div>' +
		btnHtml +
		'</div>';
	container.appendChild(box1);

	// Bind renewal button
	var renewBtn = document.getElementById('ssl-renew-btn');
	if (renewBtn) {
		// ssl-renew-btn に状態クラス基盤（.ssl-renew-btn.is-*）を適用。inline hex を撤去。
		renewBtn.classList.add('ssl-renew-btn', 'is-idle');
		function sslBtnState(cls) {
			renewBtn.classList.remove('is-idle', 'is-busy', 'is-ok', 'is-err');
			renewBtn.classList.add(cls);
		}
		renewBtn.onclick = function() {
			// 破壊的操作（SSL 手動更新）の確認は共通 confirmModal 経由。確認後に doRenew() を発火。
			var sslRenewMsg = 'SSL証明書を手動で更新します。よろしいですか？\n（処理に1〜2分かかる場合があります）';
			if (typeof window.confirmModal === 'function') {
				window.confirmModal(sslRenewMsg).then(function(ok) { if (ok) doRenew(); });
			} else if (confirm(sslRenewMsg)) {
				doRenew();
			}
		};
		function doRenew() {
			renewBtn.disabled = true;
			renewBtn.textContent = '更新中...';
			sslBtnState('is-busy');
			var csrfToken = getCsrfToken();
			var formData = new FormData();
			formData.append('action', 'ssl_renew');
			formData.append('csrf_token', csrfToken);
			fetch('?', {
				method: 'POST',
				body: formData
			})
			.then(function(r) { return r.json(); })
			.then(function(result) {
				if (result.success) {
					renewBtn.textContent = '更新成功';
					sslBtnState('is-ok');
					var rc = document.getElementById('async-ssl-renew');
					if (rc) rc.innerHTML = '<p class="section-loading">読み込み中...</p>';
					loadSection('ssl', 'async-ssl', renderSsl);
				} else {
					renewBtn.textContent = '更新失敗';
					sslBtnState('is-err');
					alert('SSL証明書の更新に失敗しました:\n\n' + (result.output || '').substring(0, 500));
				}
				setTimeout(function() {
					renewBtn.disabled = false;
					renewBtn.textContent = '手動更新';
					sslBtnState('is-idle');
				}, 5000);
			})
			.catch(function() {
				renewBtn.textContent = '通信エラー';
				sslBtnState('is-err');
				setTimeout(function() {
					renewBtn.disabled = false;
					renewBtn.textContent = '手動更新';
					sslBtnState('is-idle');
				}, 3000);
			});
		}
	}

	var box2 = document.createElement('div');
	box2.innerHTML = '<span class="stat-value ' + escapeHtml(data.le_status_class || '') + '">' + escapeHtml(data.le_status || '') + '</span>';
	if (data.le_last_date) box2.innerHTML += '<span class="le-detail">' + escapeHtml(data.le_last_date) + '</span>';
	var renewContainer = document.getElementById('async-ssl-renew');
	if (renewContainer) {
		renewContainer.innerHTML = '';
		renewContainer.classList.remove('section-loading');
		renewContainer.appendChild(box2);
	} else {
		container.appendChild(box2);
	}
}

// ========================================
// Backups
// ========================================
function renderBackups(container, data) {
	var backupExpandSlot = document.getElementById('backup-expand-btn');
	if (backupExpandSlot) backupExpandSlot.innerHTML = '';
	// R2 保存先ラベルを表示（R2 データがある場合のみ）
	var r2PathEl = document.getElementById('db-r2-path-display');
	if (r2PathEl && data.r2_backup_files && data.r2_backup_files.length > 0) {
		r2PathEl.style.display = '';
	}
	// バックアップ対象DB一覧をカードヘッダーに表示（PHPのrenderResourcesと同等）
	var dbListEl = document.getElementById('db-list-display');
	if (dbListEl) {
		if (data.db_list && data.db_list.length > 0) {
			var dbHtml = '<span class="db-info-label">バックアップ対象DB:</span>';
			data.db_list.forEach(function(db) {
				dbHtml += ' <code>' + escapeHtml(db.name) + '</code><span class="db-info-label"> (' + fmtMB(db.size) + ')</span>';
			});
			dbListEl.innerHTML = dbHtml;
		} else if (data.db_size && data.db_size !== '?') {
			dbListEl.innerHTML = '<span class="db-info-label">バックアップ対象DB:</span> <code>' + escapeHtml(fmtMB(data.db_size)) + '</code>';
		}
	}
	var hasLocalBackup = data.backup_files && data.backup_files.length > 0;
	var hasNcBackup = data.nc_backup_files && data.nc_backup_files.length > 0;
	if (!hasLocalBackup && !hasNcBackup) {
		container.innerHTML = '<p class="empty">バックアップはありません</p>';
		return;
	}
	container.innerHTML = '';
	var colStyle = '<colgroup><col style="width:auto"><col style="width:120px"><col style="width:180px"></colgroup>';
	var tbody = null;
	if (hasLocalBackup) {
		var table = document.createElement('table');
		table.className = 'compact-table has-top-margin';
		table.setAttribute('data-backup-group', 'local');
		table.innerHTML = colStyle + '<thead><tr><th>VPS（7日間）</th><th>サイズ</th><th>日時</th></tr></thead>';
		tbody = document.createElement('tbody');
		data.backup_files.slice(0, 1).forEach(function(bf) {
			var tr = document.createElement('tr');
			tr.innerHTML = '<td>' + escapeHtml(bf.name) + '</td><td class="nowrap">' + (parseInt(bf.size) / 1024 / 1024).toFixed(1) + ' MB</td><td class="nowrap">' + escapeHtml(bf.date || '') + '</td>';
			tbody.appendChild(tr);
		});
		table.appendChild(tbody);
		container.appendChild(table);
	}
	if (data.r2_backup_files && data.r2_backup_files.length > 0) {
		var h3 = document.createElement('h3');
		h3.className = 'backup-subheading';
		h3.textContent = 'R2バックアップ（30日間）';
		container.appendChild(h3);
		var r2Table = document.createElement('table');
		r2Table.className = 'compact-table';
		r2Table.innerHTML = colStyle + '<thead><tr><th>ファイル名</th><th>サイズ</th><th>日時</th></tr></thead>';
		var r2Tbody = document.createElement('tbody');
		data.r2_backup_files.slice(0, 1).forEach(function(rf) {
			var tr = document.createElement('tr');
			tr.innerHTML = '<td>' + escapeHtml(rf.name) + '</td><td class="nowrap">' + escapeHtml(rf.size) + '</td><td class="nowrap">' + escapeHtml(rf.date || '') + '</td>';
			r2Tbody.appendChild(tr);
		});
		r2Table.appendChild(r2Tbody);
		container.appendChild(r2Table);
	}
	if (data.r2_config_files && data.r2_config_files.length > 0) {
		var h3c = document.createElement('h3');
		h3c.className = 'backup-subheading';
		h3c.textContent = 'R2 Config バックアップ（30日間）';
		container.appendChild(h3c);
		var r2cTable = document.createElement('table');
		r2cTable.className = 'compact-table';
		r2cTable.setAttribute('data-backup-group', 'r2config');
		r2cTable.innerHTML = colStyle + '<thead><tr><th>ファイル名</th><th>サイズ</th><th>日時</th></tr></thead>';
		var r2cTbody = document.createElement('tbody');
		data.r2_config_files.slice(0, 1).forEach(function(rf) {
			var tr = document.createElement('tr');
			tr.innerHTML = '<td>' + escapeHtml(rf.name) + '</td><td class="nowrap">' + escapeHtml(rf.size) + '</td><td class="nowrap">' + escapeHtml(rf.date || '') + '</td>';
			r2cTbody.appendChild(tr);
		});
		r2cTable.appendChild(r2cTbody);
		container.appendChild(r2cTable);
	}
	if (data.nc_backup_files && data.nc_backup_files.length > 0) {
		var h3nc = document.createElement('h3');
		h3nc.className = 'backup-subheading';
		h3nc.textContent = 'Nextcloud DBバックアップ（日次30世代）';
		container.appendChild(h3nc);
		var ncTable = document.createElement('table');
		ncTable.className = 'compact-table';
		ncTable.setAttribute('data-backup-group', 'nc');
		ncTable.innerHTML = colStyle + '<thead><tr><th>ファイル名</th><th>サイズ</th><th>日時</th></tr></thead>';
		var ncTbody = document.createElement('tbody');
		data.nc_backup_files.slice(0, 1).forEach(function(nf) {
			var tr = document.createElement('tr');
			tr.innerHTML = '<td>' + escapeHtml(nf.name) + '</td><td class="nowrap">' + (parseInt(nf.size) / 1024 / 1024).toFixed(1) + ' MB</td><td class="nowrap">' + escapeHtml(nf.date || '') + '</td>';
			ncTbody.appendChild(tr);
		});
		ncTable.appendChild(ncTbody);
		container.appendChild(ncTable);
	}
	// 統合「全て展開」ボタン
	var hasMultiBackup = hasLocalBackup && data.backup_files.length > 1;
	var hasMultiR2 = data.r2_backup_files && data.r2_backup_files.length > 1;
	var hasMultiR2c = data.r2_config_files && data.r2_config_files.length > 1;
	var hasMultiNc = data.nc_backup_files && data.nc_backup_files.length > 1;
	if (hasMultiBackup || hasMultiR2 || hasMultiR2c || hasMultiNc) {
		var unifiedBtn = document.createElement('button');
		unifiedBtn.type = 'button';
		unifiedBtn.textContent = '全て展開';
		unifiedBtn.className = 'btn-secondary btn-sm';
		var allExpanded = false;
		unifiedBtn.onclick = function() {
			if (!allExpanded) {
				if (hasMultiBackup) {
					data.backup_files.slice(1).forEach(function(bf) {
						var tr = document.createElement('tr');
						tr.classList.add('backup-extra-row');
						tr.innerHTML = '<td>' + escapeHtml(bf.name) + '</td><td class="nowrap">' + (parseInt(bf.size) / 1024 / 1024).toFixed(1) + ' MB</td><td class="nowrap">' + escapeHtml(bf.date || '') + '</td>';
						tbody.appendChild(tr);
					});
				}
				if (hasMultiR2) {
					data.r2_backup_files.slice(1).forEach(function(rf) {
						var tr = document.createElement('tr');
						tr.classList.add('backup-extra-row');
						tr.innerHTML = '<td>' + escapeHtml(rf.name) + '</td><td class="nowrap">' + escapeHtml(rf.size) + '</td><td class="nowrap">' + escapeHtml(rf.date || '') + '</td>';
						var table = container.querySelector('table.compact-table:not(.has-top-margin)');
						if (table) table.querySelector('tbody').appendChild(tr);
					});
				}
				if (hasMultiR2c) {
					var r2cTbodyEl = container.querySelector('table[data-backup-group="r2config"] tbody');
					data.r2_config_files.slice(1).forEach(function(rf) {
						var tr = document.createElement('tr');
						tr.classList.add('backup-extra-row');
						tr.innerHTML = '<td>' + escapeHtml(rf.name) + '</td><td class="nowrap">' + escapeHtml(rf.size) + '</td><td class="nowrap">' + escapeHtml(rf.date || '') + '</td>';
						if (r2cTbodyEl) r2cTbodyEl.appendChild(tr);
					});
				}
				if (hasMultiNc) {
					var ncTbodyEl = container.querySelector('table[data-backup-group="nc"] tbody');
					data.nc_backup_files.slice(1).forEach(function(nf) {
						var tr = document.createElement('tr');
						tr.classList.add('backup-extra-row');
						tr.innerHTML = '<td>' + escapeHtml(nf.name) + '</td><td class="nowrap">' + (parseInt(nf.size) / 1024 / 1024).toFixed(1) + ' MB</td><td class="nowrap">' + escapeHtml(nf.date || '') + '</td>';
						if (ncTbodyEl) ncTbodyEl.appendChild(tr);
					});
				}
				unifiedBtn.textContent = '折りたたむ';
				allExpanded = true;
			} else {
				container.querySelectorAll('.backup-extra-row').forEach(function(row) { row.remove(); });
				unifiedBtn.textContent = '全て展開';
				allExpanded = false;
			}
		};
		if (backupExpandSlot) backupExpandSlot.appendChild(unifiedBtn);
	}
}

// ========================================
// Nextcloud Login History (admin_audit)
// ========================================
function ncLoginViewToggle(content, activeView) {
	var html = '<div class="nc-view-toggle">';
	html += '<button class="btn-secondary btn-sm nc-view-btn' + (activeView === 'summary' ? ' active' : '') + '" onclick="renderNcLoginSummary(this.closest(\'.async-content\'))">集計</button>';
	html += '<button class="btn-secondary btn-sm nc-view-btn' + (activeView === 'detail' ? ' active' : '') + '" onclick="renderNcLoginDetail(this.closest(\'.async-content\'), null)">一覧</button>';
	html += '</div>';
	return html;
}

function ncLoginGetUaInfo(uaType) {
	var map = {
		win: ['ua-win', 'Win同期'],
		ios: ['ua-ios', 'iOS'],
		android: ['ua-android', 'Android'],
		browser: ['ua-browser', 'ブラウザ'],
		internal: ['ua-internal', '内部']
	};
	return map[uaType] || map.browser;
}

function ncLoginFailureKind(login) {
	if (!login || login.result !== 'fail') return '';
	if (login.failure_kind === 'request') return 'request';
	if (login.failure_kind === 'auth') return 'auth';
	var url = String(login.url || '').toLowerCase();
	return (url.indexOf('index.phpar=') !== -1) ? 'request' : 'auth';
}

var ncLoginPointerDown = null;

function ncLoginRememberPointerDown(ev) {
	if (!ev) return;
	ncLoginPointerDown = { x: Number(ev.clientX) || 0, y: Number(ev.clientY) || 0 };
}

function ncLoginCanToggleRowClick(ev) {
	if (ev && ev.defaultPrevented) return false;
	if (ev && ncLoginPointerDown) {
		var dx = Math.abs((Number(ev.clientX) || 0) - ncLoginPointerDown.x);
		var dy = Math.abs((Number(ev.clientY) || 0) - ncLoginPointerDown.y);
		ncLoginPointerDown = null;
		if (dx > 4 || dy > 4) return false;
	}
	if (window.getSelection) {
		var selObj = window.getSelection();
		var hasSelection = selObj && !selObj.isCollapsed && String(selObj).trim().length > 0;
		if (hasSelection) {
			var row = ev && ev.currentTarget ? ev.currentTarget : null;
			if (!row) return false;
			var inRowSelection = row.contains(selObj.anchorNode) || row.contains(selObj.focusNode);
			if (inRowSelection) return false;
		}
	}
	return true;
}

function renderNcLoginSummary(content) {
	saveCurrentViewFilter(content);
	var state = content && content.__ncLoginState ? content.__ncLoginState : null;
	var logins = state && state.logins ? state.logins : [];
	var rate = state ? state.rate : null;
	var flags = state && state.flags ? state.flags : {};
	if (!logins.length) {
		content.innerHTML = '<p class="empty">ログイン履歴はありません</p>';
		ncLoginResetExpandSlot();
		return;
	}

	var grouped = {};
	for (var i = 0; i < logins.length; i++) {
		var l = logins[i];
		var ip = String(l.ip || '').trim();
		if (!ip) continue;
		if (!grouped[ip]) {
			grouped[ip] = {
				ip: ip,
				total: 0,
				fail: 0,
				success: 0,
				auth_fail: 0,
				request_fail: 0,
				first_ts: null,
				first_time: '',
				last_ts: null,
				last_time: '',
				users: {},
				reasons: {},
				ua_counts: {}
			};
		}
		var g = grouped[ip];
		g.total++;
		var isFail = (l.result === 'fail');
		if (isFail) {
			g.fail++;
			var fk = ncLoginFailureKind(l);
			if (fk === 'request') g.request_fail++;
			else g.auth_fail++;
			var reason = String(l.reason || '').trim();
			if (reason) g.reasons[reason] = true;
		} else {
			g.success++;
		}
		var user = String(l.user || '').trim();
		if (user && user !== '--') g.users[user] = true;
		var uaType = String(l.ua_type || 'browser');
		g.ua_counts[uaType] = (g.ua_counts[uaType] || 0) + 1;
		var ts = Date.parse(String(l.time || ''));
		if (!isNaN(ts)) {
			if (g.first_ts === null || ts < g.first_ts) {
				g.first_ts = ts;
				g.first_time = String(l.time || '');
			}
			if (g.last_ts === null || ts > g.last_ts) {
				g.last_ts = ts;
				g.last_time = String(l.time || '');
			}
		}
	}

	var rows = Object.keys(grouped).map(function(ip) { return grouped[ip]; });
	rows.sort(function(a, b) {
		if (b.fail !== a.fail) return b.fail - a.fail;
		if (b.total !== a.total) return b.total - a.total;
		return (b.last_ts || 0) - (a.last_ts || 0);
	});

	var countryOpts = buildCountrySelectOptions(flags, rows);
	var html = renderLoginRateStats(rate);
	html += cardViewToggle('summary', 'renderNcLoginSummary(this.closest(\'.async-content\'))', 'renderNcLoginDetail(this.closest(\'.async-content\'), null)');
	html += '<div class="nc-summary-meta">直近 ' + formatCount(logins.length) + ' 件 &nbsp;/&nbsp; ' + formatCount(rows.length) + ' IP</div>';
	var csrfToken = getCsrfToken();
	html += '<form method="post" data-bulk-ban="nclogin">';
	html += '<input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '">';
	html += '<input type="hidden" name="ban_section" value="nclogin">';
	html += '<div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="nclogin"> 全選択</label><span class="bulk-ban-count" data-count="nclogin">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nclogin" disabled>選択したIPをBAN</button></div>';
	html += '<table class="log-table"><thead>';
	html += '<tr class="thead-filter-row"><th class="cb-col"></th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th class="th-filter-fail-kind"><select class="filter-select" data-filter="fail-kind" data-filter-partial="1"><option value="">全て</option><option value="auth">認証失敗あり</option><option value="request">リクエスト失敗あり</option><option value="none">失敗なし</option></select></th><th></th><th></th><th></th><th class="th-filter-ua-type"><select class="filter-select" data-filter="ua-type" data-filter-partial="1"><option value="">全て</option><option value="browser">ブラウザ</option><option value="win">Win同期</option><option value="ios">iOS</option><option value="android">Android</option><option value="internal">内部</option></select></th><th><span class="filter-count"></span></th></tr>';
	html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th>失敗内訳</th><th>件数</th><th>初回</th><th>最終アクセス</th><th>種別</th><th>ユーザー</th></tr></thead><tbody>';
	for (var r = 0; r < rows.length; r++) {
		var row = rows[r];
		var wl = isWhitelisted(row.ip);
		var bannedJail = BANNED_IPS[row.ip] || '';
		var disableCb = wl || !!bannedJail;
		var failKindVal = 'none';
		if (row.request_fail > 0 && row.auth_fail > 0) failKindVal = 'auth request';
		else if (row.request_fail > 0) failKindVal = 'request';
		else if (row.auth_fail > 0) failKindVal = 'auth';
		var allUaTypes = Object.keys(row.ua_counts).sort(function(a, b) {
			return row.ua_counts[b] - row.ua_counts[a];
		});
		if (!allUaTypes.length) allUaTypes = ['browser'];
		var uaBadgesHtml = allUaTypes.map(function(k) {
			var info = ncLoginGetUaInfo(k);
			return '<span class="ua-badge ' + info[0] + '">' + info[1] + '</span>';
		}).join(' ');
		var users = Object.keys(row.users).sort();
		var userLabel = users.length ? users.slice(0, 2).join(', ') : '--';
		if (users.length > 2) userLabel += ' +' + (users.length - 2);
		var failLabel = row.fail > 0
			? ('<span class="result-badge result-fail">認証 ' + row.auth_fail + '</span> <span class="result-badge result-warning">リクエスト ' + row.request_fail + '</span>')
			: '<span class="result-badge result-success">失敗なし</span>';
		var ipEsc = escapeHtml(row.ip);
		html += '<tr class="nc-summary-row" data-ip="' + ipEsc + '" data-fail-kind="' + escapeHtml(failKindVal) + '" data-ua-type="' + escapeHtml(allUaTypes.join(' ')) + '" data-country="' + escapeHtml(flags[row.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (bannedJail ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[row.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('detail', 'renderNcLoginDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')') + '>';
		html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="nclogin"' + (disableCb ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(row.ip) + '</td>';
		html += '<td class="col-country nowrap">' + escapeHtml(flags[row.ip] || '') + '</td>';
		html += '<td>' + failLabel + '</td>';
		html += '<td class="nowrap"><strong>' + formatCount(row.total) + '件</strong>（成功 ' + formatCount(row.success) + ' 件｜失敗 ' + formatCount(row.fail) + ' 件）</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(row.first_time, '-')) + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(row.last_time, '-')) + '</td>';
		html += '<td class="nowrap">' + uaBadgesHtml + '</td>';
		html += '<td>' + escapeHtml(userLabel) + '</td>';
		html += '</tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	initBulkBan('nclogin', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: rows.length });
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

function renderNcLoginDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var state = content && content.__ncLoginState ? content.__ncLoginState : null;
	var allLogins = state && state.logins ? state.logins : [];
	var flags = state && state.flags ? state.flags : {};
	var rate = state ? state.rate : null;
	if (!allLogins.length) {
		content.innerHTML = renderLoginRateStats(rate) + '<p class="empty">ログイン履歴はありません</p>';
		return;
	}
	var logins = filterIp ? allLogins.filter(function(l) { return String(l.ip || '') === String(filterIp); }) : allLogins.slice();
	var userSelectOptions = buildNcUserSelectOptions(logins);
	var countryOpts = buildCountrySelectOptions(flags, logins);
	var csrfToken = getCsrfToken();
	var html = renderLoginRateStats(rate);
	html += cardViewToggle('detail', 'renderNcLoginSummary(this.closest(\'.async-content\'))', 'renderNcLoginDetail(this.closest(\'.async-content\'), null)');
	if (filterIp) {
		html += '<div class="nc-filter-bar"><span class="nc-filter-badge">IP: ' + escapeHtml(filterIp) + '</span><button class="btn-secondary btn-sm" onclick="renderNcLoginDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button></div>';
	}
	html += '<form method="post" data-bulk-ban="nclogin"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="nclogin"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="nclogin"> 全選択</label><span class="bulk-ban-count" data-count="nclogin">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nclogin" disabled>選択したIPをBAN</button></div>';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th class="th-filter-result-sm"><select class="filter-select" data-filter="result"><option value="">全て</option><option value="success">成功</option><option value="fail">失敗</option></select></th><th class="th-filter-fail-kind"><select class="filter-select" data-filter="fail-kind" data-filter-partial="1"><option value="">全て</option><option value="auth">認証失敗</option><option value="request">リクエスト失敗</option></select></th><th class="th-filter-user-sel">' + buildFilterSelect('user', 'ユーザー', userSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th class="th-filter-ua-type"><select class="filter-select" data-filter="ua-type"><option value="">全て</option><option value="browser">ブラウザ</option><option value="win">Win同期</option><option value="ios">iOS</option><option value="android">Android</option><option value="internal">内部</option></select></th><th></th><th><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>結果</th><th>判定</th><th>ユーザー</th><th class="col-ip">IP</th><th class="col-country">国</th><th>種別</th><th>理由</th><th>経路</th></tr></thead><tbody>';
	for (var i = 0; i < logins.length; i++) {
		var l = logins[i];
		var wl = isWhitelisted(l.ip);
		var bannedJail = BANNED_IPS[l.ip] || '';
		var isFail = (l.result === 'fail');
		var disableCb = !isFail || wl || !!bannedJail;
		var trTitle = 'クリックして集計表示' + (bannedJail ? '（' + bannedJail + ' でBAN済み）' : '');
		var resultBadge = isFail ? '<span class="result-badge result-fail">失敗</span>' : '<span class="result-badge result-success">成功</span>';
		var uaType = l.ua_type || 'browser';
		var uaInfo = ncLoginGetUaInfo(uaType);
		var uaBadge = '<span class="ua-badge ' + uaInfo[0] + '">' + uaInfo[1] + '</span>';
		var displayName = (l.display_name || '').trim();
		var ncNameBadge = (displayName && displayName !== (l.user || '')) ? (' <span class="nc-name-badge">' + escapeHtml(displayName) + '</span>') : '';
		var userFilterVal = ((l.user || '') + ' ' + displayName).trim();
		var failureKind = ncLoginFailureKind(l);
		var failureBadge = '';
		if (isFail) {
			failureBadge = (failureKind === 'request')
				? '<span class="result-badge result-warning">リクエスト</span>'
				: '<span class="result-badge result-fail">認証</span>';
		}
		var route = ((l.method || '') + ' ' + (l.url || '')).trim();
		html += '<tr data-ip="' + escapeHtml(l.ip) + '" data-result="' + escapeHtml(l.result || '') + '" data-fail-kind="' + escapeHtml(failureKind) + '" data-user="' + escapeHtml(userFilterVal) + '" data-ua-type="' + escapeHtml(uaType) + '" data-country="' + escapeHtml(flags[l.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (bannedJail ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[l.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('summary', 'renderNcLoginSummary(this.closest(\'.async-content\'))', { title: trTitle }) + '><td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + escapeHtml(l.ip) + '" data-section="nclogin"' + (disableCb ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(l.time, '-')) + '</td><td>' + resultBadge + '</td><td>' + failureBadge + '</td><td>' + escapeHtml(l.user) + ncNameBadge + '</td><td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + escapeJsString(l.ip) + '\')">' + escapeHtml(l.ip) + '</code>' + ipBadges(l.ip) + '</td><td class="col-country nowrap">' + escapeHtml(flags[l.ip] || '') + '</td><td>' + uaBadge + '</td><td class="fail-reason">' + (isFail ? (l.reason ? escapeHtml(l.reason) : '—') : '') + '</td><td class="nc-login-route" title="' + escapeHtml(route || '-') + '">' + escapeHtml(route || '-') + '</td></tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	initBulkBan('nclogin', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: logins.length });
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

function renderNcLogin(content, data) {
	var logins = data.logins || [];
	var rate = data.rate || null;
	content.__ncLoginState = { logins: logins, rate: rate, flags: data.flags || {} };
	if (logins.length === 0) {
		content.innerHTML = renderLoginRateStats(rate) + '<p class="empty">ログイン履歴はありません</p>';
		return;
	}
	renderNcLoginSummary(content);
}

// ========================================
// Audit Anomaly (Nextcloud)
// ========================================
function renderAuditAnomaly(content, data) {
	var summary = data.summary || {};
	var anomalies = data.anomalies || [];
	var levels = summary.log_levels || {};
	var lvRecent = levels.recent || {};
	var lvPrev = levels.prev || {};
	var lvEx = levels.excluded_lexicon || {};
	var html = '';
	if (summary && typeof summary.total_recent === 'number') {
		var delta = (summary.total_recent - (summary.total_prev || 0));
		var deltaLabel = (delta >= 0 ? '+' : '') + delta;
		html += '<div class="stats-grid stats-grid-audit-anomaly">';
		html += '<div class="stat-box"><span class="stat-label">直近' + summary.window_min + '分</span><span class="stat-value">' + formatCount(summary.total_recent) + ' 件</span><span class="stat-sub">差分 ' + deltaLabel + '</span></div>';
		html += '<div class="stat-box"><span class="stat-label">前' + summary.window_min + '分</span><span class="stat-value">' + formatCount(summary.total_prev || 0) + ' 件</span></div>';
		html += '<div class="stat-box"><span class="stat-label">Warning/Error/Fatal（直近）</span><span class="stat-value">' + (lvRecent.warning || 0) + ' / ' + (lvRecent.error || 0) + ' / ' + (lvRecent.fatal || 0) + '</span><span class="stat-sub">前: ' + (lvPrev.warning || 0) + ' / ' + (lvPrev.error || 0) + ' / ' + (lvPrev.fatal || 0) + '</span></div>';
		html += '<div class="stat-box"><span class="stat-label">Lexicon除外</span><span class="stat-value">' + formatCount(lvEx.recent || 0) + ' 件</span><span class="stat-sub">前: ' + formatCount(lvEx.prev || 0) + ' 件</span></div>';
		html += '</div>';
	}
	if (!anomalies || anomalies.length === 0) {
		html += '<p class="empty">異常検知はありません</p>';
		content.innerHTML = html;
		return;
	}
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th><input type="text" class="filter-input" data-filter="event" placeholder="イベント絞り込み"></th><th></th><th></th><th></th><th></th><th><span class="filter-count"></span></th></tr><tr><th>イベント</th><th>直近</th><th>前回</th><th>増加率</th><th>最終時刻</th><th>サンプル</th></tr></thead><tbody>';
	for (var i = 0; i < anomalies.length; i++) {
		var a = anomalies[i];
		var pctLabel, pctClass;
		if (a.prev > 0) {
			var _pct = Math.round((a.recent - a.prev) / a.prev * 100);
			pctLabel = (_pct >= 0 ? '+' : '') + _pct + '%';
			pctClass = _pct >= 200 ? 'ratio-pct-spike' : (_pct > 0 ? 'ratio-pct-up' : (_pct < 0 ? 'ratio-pct-down' : 'ratio-pct-neutral'));
		} else {
			pctLabel = '—'; pctClass = 'ratio-pct-neutral';
		}
		var badge = '';
		if ((a.prev > 0 && a.recent >= a.prev * 3 && a.recent >= 20) || (a.prev === 0 && a.recent >= 15)) {
			badge = '<span class="result-badge result-fail">急増</span>';
		} else if ((a.prev > 0 && a.recent >= a.prev * 2 && a.recent >= 10) || (a.prev === 0 && a.recent >= 8)) {
			badge = '<span class="result-badge result-warning">増加</span>';
		}
		var sample = [];
		if (a.sample_user) sample.push(a.sample_user);
		if (a.sample_ip) sample.push(a.sample_ip);
		html += '<tr data-event="' + escapeHtml((a.event || '').toLowerCase()) + '">';
		html += '<td>' + escapeHtml(a.event || '') + '</td>';
		html += '<td>' + a.recent + '</td>';
		html += '<td>' + (a.prev || 0) + '</td>';
		html += '<td><span class="ratio-pct-cell ' + pctClass + '">' + pctLabel + '</span> ' + badge + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(a.last_time, '')) + '</td>';
		html += '<td>' + escapeHtml(sample.join(' / ')) + '</td>';
		html += '</tr>';
	}
	html += '</tbody></table>';
	content.innerHTML = html;
	autoInitCardFromDataset(content.closest('section.card'), { total: anomalies.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
}

// ========================================
// Login History helpers
// ========================================
function buildNcUserSelectOptions(rows) {
	var map = {};
	for (var i = 0; i < rows.length; i++) {
		var uid = (rows[i].user || '').trim();
		if (!uid) continue;
		var displayName = (rows[i].display_name || '').trim();
		if (!map[uid]) map[uid] = '';
		if (!map[uid] && displayName && displayName !== uid) {
			map[uid] = displayName;
		}
	}
	var list = Object.keys(map).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
	var out = '';
	for (var j = 0; j < list.length; j++) {
		var uid = list[j];
		var displayName = map[uid];
		var label = displayName ? (uid + ' (' + displayName + ')') : uid;
		out += '<option value="' + escapeHtml(uid) + '">' + escapeHtml(label) + '</option>';
	}
	return out;
}

function buildFieldDatalist(rows, field) {
	var set = {};
	for (var i = 0; i < rows.length; i++) {
		var v = rows[i][field] || '';
		if (v) set[v] = true;
	}
	var list = Object.keys(set).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
	var out = '';
	for (var j = 0; j < list.length; j++) {
		out += '<option value="' + escapeHtml(list[j]) + '">';
	}
	return out;
}

function buildFieldSelectOptions(rows, field) {
	var set = {};
	for (var i = 0; i < rows.length; i++) {
		var v = String(rows[i][field] || '').trim();
		if (v) set[v] = true;
	}
	var list = Object.keys(set).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
	var out = '';
	for (var j = 0; j < list.length; j++) {
		var val = list[j];
		out += '<option value="' + escapeHtml(val) + '">' + escapeHtml(val) + '</option>';
	}
	return out;
}

function buildCountrySelectOptions(flags, rows, ipField) {
	var set = {};
	for (var i = 0; i < rows.length; i++) {
		var ip = String(rows[i][ipField || 'ip'] || '').trim();
		var c = flags[ip] || '';
		if (c && c !== '-') set[c] = true;
	}
	var list = Object.keys(set).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
	var out = '';
	for (var j = 0; j < list.length; j++) {
		out += '<option value="' + escapeHtml(list[j]) + '">' + escapeHtml(list[j]) + '</option>';
	}
	return out;
}

var LOGIN_APP_LABELS = {
	heartdesk_monitor: 'Monitor',
	heartdesk_admin: 'Admin'
};

function loginAppLabel(app) {
	var key = String(app || '').trim();
	if (!key) return '不明';
	return LOGIN_APP_LABELS[key] || key;
}

function buildLoginAppSelectOptions(rows) {
	var set = {};
	for (var i = 0; i < rows.length; i++) {
		var app = String(rows[i].app || '').trim();
		if (app) set[app] = true;
	}
	var list = Object.keys(set).sort(function(a, b) { return loginAppLabel(a).localeCompare(loginAppLabel(b), 'ja'); });
	var out = '';
	for (var j = 0; j < list.length; j++) {
		var key = list[j];
		out += '<option value="' + escapeHtml(key) + '">' + escapeHtml(loginAppLabel(key)) + '</option>';
	}
	return out;
}

function buildFilterSelect(filterKey, placeholder, optionsHtml, partial) {
	return '<select class="filter-select" data-filter="' + escapeHtml(filterKey) + '"' + (partial ? ' data-filter-partial="1"' : '') + '><option value="">' + escapeHtml(placeholder) + '</option>' + (optionsHtml || '') + '</select>';
}

function deviceBadge(row) {
	var dev = row.device || 'unknown';
	var ua = row.ua || '不明';
	var icon = dev === 'mobile' ? '📱' : (dev === 'pc' ? '💻' : (dev === 'scanner' ? '🤖' : (dev === 'tool' ? '🔧' : '❓')));
	return '<span class="device-badge device-' + dev + '" title="' + escapeHtml(ua) + '">' + icon + ' ' + escapeHtml(ua) + '</span>';
}

function loginResultBadge(result) {
	if (result === 'fail') return '<span class="result-badge result-fail">失敗</span>';
	if (result === 'success') return '<span class="result-badge result-success">成功</span>';
	return '<span class="result-badge result-warning">不明</span>';
}

// ========================================
// 増加率 比較バー ヘルパー（Nginx・ログイン履歴・Audit共用）
// ========================================
function buildRatioBarHtml(recent, prev, isSpike) {
	var max = Math.max(recent, prev, 1);
	var prevPct = (prev / max * 100).toFixed(1);
	var recentPct = (recent / max * 100).toFixed(1);
	var recentBarClass = isSpike ? 'ratio-bar-fill-spike' : 'ratio-bar-fill-recent';
	var html = '<div class="ratio-bars">';
	html += '<div class="ratio-bar-row"><span class="ratio-bar-lbl">前</span><div class="ratio-bar-track"><div class="ratio-bar-fill ratio-bar-fill-prev" style="width:' + prevPct + '%"></div></div><span class="ratio-bar-cnt">' + Number(prev).toLocaleString() + '</span></div>';
	html += '<div class="ratio-bar-row"><span class="ratio-bar-lbl">直近</span><div class="ratio-bar-track"><div class="ratio-bar-fill ' + recentBarClass + '" style="width:' + recentPct + '%"></div></div><span class="ratio-bar-cnt">' + Number(recent).toLocaleString() + '</span></div>';
	html += '</div>';
	return html;
}
function buildRatioPctHtml(recent, prev, isSpike) {
	if (prev <= 0) return '<span class="ratio-pct ratio-pct-neutral">—</span>';
	var pct = Math.round((recent - prev) / prev * 100);
	var sign = pct >= 0 ? '+' : '';
	var cls = isSpike ? 'ratio-pct-spike' : (pct > 0 ? 'ratio-pct-up' : (pct < 0 ? 'ratio-pct-down' : 'ratio-pct-neutral'));
	return '<span class="ratio-pct ' + cls + '">' + sign + pct + '%</span>';
}
// opts: { spikeMinRecent: number }
function renderRateStatsGrid(rate, opts) {
	if (!rate || typeof rate.recent !== 'number') return '';
	var spikeMinRecent = (opts && opts.spikeMinRecent != null) ? opts.spikeMinRecent : 10;
	var recent = rate.recent || 0;
	var prev = rate.prev || 0;
	var delta = (typeof rate.delta === 'number') ? rate.delta : (recent - prev);
	var deltaLabel = (delta >= 0 ? '+' : '') + Number(delta).toLocaleString();
	var isSpike = prev > 0 && recent >= spikeMinRecent && recent >= prev * 2;
	var spikeBadge = isSpike ? '<span class="result-badge result-warning">急増</span>' : '';
	var html = '<div class="stats-grid">';
	html += '<div class="stat-box"><span class="stat-label">直近' + rate.window_min + '分</span><span class="stat-value stat-value-count"><span class="stat-number">' + Number(recent).toLocaleString() + '</span><span class="stat-unit">件</span></span><span class="stat-sub">差分 ' + deltaLabel + '</span></div>';
	html += '<div class="stat-box"><span class="stat-label">前' + rate.window_min + '分</span><span class="stat-value stat-value-count"><span class="stat-number">' + Number(prev).toLocaleString() + '</span><span class="stat-unit">件</span></span></div>';
	html += '<div class="stat-box"><span class="stat-label">増加率</span>' + buildRatioBarHtml(recent, prev, isSpike) + buildRatioPctHtml(recent, prev, isSpike) + spikeBadge + '</div>';
	html += '</div>';
	return html;
}

function renderLoginRateStats(rate) {
	return renderRateStatsGrid(rate, { spikeMinRecent: 10 });
}

// 集計/一覧 ビュー切替トグル（全カード共通）
// activeView: 'summary' | 'detail'
// onSummary / onDetail: onclick に埋め込む JS 式文字列
function cardViewToggle(activeView, onSummary, onDetail) {
	var html = '<div class="nc-view-toggle">';
	html += '<button class="btn-secondary btn-sm nc-view-btn' + (activeView === 'summary' ? ' active' : '') + '" onclick="' + onSummary + '">集計</button>';
	html += '<button class="btn-secondary btn-sm nc-view-btn' + (activeView === 'detail' ? ' active' : '') + '" onclick="' + onDetail + '">一覧</button>';
	html += '</div>';
	return html;
}

function rowToggleTitle(targetView) {
	return targetView === 'summary' ? 'クリックして集計表示' : 'クリックして一覧表示';
}

function rowToggleAttrs(targetView, onClickExpr, options) {
	var opts = options || {};
	var title = (opts.title != null) ? String(opts.title) : rowToggleTitle(targetView);
	return ' style="cursor:pointer" title="' + escapeHtml(title) + '" onmousedown="ncLoginRememberPointerDown(event)" onclick="if(ncLoginCanToggleRowClick(event)){' + onClickExpr + '}"';
}

function loginHistoryRowToggleAttrs(targetView, onClickExpr, options) {
	return rowToggleAttrs(targetView, onClickExpr, options);
}

function ncLoginRowToggleAttrs(targetView, onClickExpr, options) {
	return rowToggleAttrs(targetView, onClickExpr, options);
}

function renderSshLoginSummary(content) {
	saveCurrentViewFilter(content);
	var state = content && content.__sshLoginState ? content.__sshLoginState : null;
	var rows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!rows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var methodSelectOptions = buildFieldSelectOptions(rows, 'method');
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var countryOpts = buildCountrySelectOptions(flags, rows);

	var grouped = {};
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var ip = String(l.ip || '').trim();
		if (!ip) continue;
		if (!grouped[ip]) {
			grouped[ip] = { ip: ip, total: 0, success: 0, fail: 0, ssh: 0, sftp: 0, users: {}, methods: {}, last_time: '' };
		}
		var g = grouped[ip];
		g.total++;
		if (l.result === 'fail') g.fail++;
		else g.success++;
		var typeVal = String(l.type || '').toUpperCase();
		if (typeVal === 'SFTP') g.sftp++;
		else g.ssh++;
		var userVal = String(l.user || '').trim();
		if (userVal && userVal !== '?') g.users[userVal] = true;
		var methodVal = String(l.method || '').trim();
		if (methodVal) g.methods[methodVal] = true;
		if (!g.last_time) g.last_time = String(l.time || '');
	}
	var summaryRows = Object.keys(grouped).map(function(ip) { return grouped[ip]; });
	summaryRows.sort(function(a, b) {
		if (b.fail !== a.fail) return b.fail - a.fail;
		if (b.total !== a.total) return b.total - a.total;
		return String(b.last_time || '').localeCompare(String(a.last_time || ''));
	});

	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('summary', 'renderSshLoginSummary(this.closest(\'.async-content\'))', 'renderSshLoginDetail(this.closest(\'.async-content\'), null)');
	html += '<div class="nc-summary-meta">直近 ' + formatCount(rows.length) + ' 件 &nbsp;/&nbsp; ' + formatCount(summaryRows.length) + ' IP</div>';
	html += '<p class="section-note">ℹ️ ポート10022は鍵認証のみ許可しているため、パスワード攻撃は認証不可。手動BANは不要です。</p>';
	html += '<form method="post" data-bulk-ban="ssh-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="ssh_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="ssh-login"> 全選択</label><span class="bulk-ban-count" data-count="ssh-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="ssh-login" disabled>選択したIPをBAN</button></div>';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '<span class="filter-count"></span></th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="fail">失敗あり</option><option value="success">失敗なし</option></select></th><th><select class="filter-select" data-filter="type"><option value="">種別</option><option value="ssh">SSHのみ</option><option value="sftp">SFTP含む</option></select></th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, true) + '</th><th><select class="filter-select" data-filter="method" data-filter-partial="1"><option value="">認証方法</option>' + methodSelectOptions + '</select></th><th></th><th></th></tr><tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th>結果内訳</th><th>種別</th><th>ユーザー</th><th>認証方法</th><th>件数</th><th>最終アクセス</th></tr></thead><tbody>';
	for (var r = 0; r < summaryRows.length; r++) {
		var row = summaryRows[r];
		var wl = isWhitelisted(row.ip);
		var banned = BANNED_IPS[row.ip] || '';
		var disableCb = wl || !!banned;
		var ipEsc = escapeHtml(row.ip);
		var users = Object.keys(row.users).sort();
		var methods = Object.keys(row.methods).sort();
		var userLabel = users.length ? users.slice(0, 2).join(', ') : '--';
		if (users.length > 2) userLabel += ' +' + (users.length - 2);
		html += '<tr data-ip="' + ipEsc + '" data-result="' + (row.fail > 0 ? 'fail' : 'success') + '" data-type="' + (row.sftp > 0 ? 'sftp ssh' : 'ssh') + '" data-user="' + escapeHtml(users.join(' ')) + '" data-method="' + escapeHtml(methods.join(' ')) + '" data-country="' + escapeHtml(flags[row.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (banned ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[row.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('detail', 'renderSshLoginDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')') + '>';
		html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="ssh-login"' + (disableCb ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(row.ip) + '</td>';
		html += '<td class="col-country nowrap">' + escapeHtml(flags[row.ip] || '') + '</td>';
		html += '<td><span class="result-badge result-success">成功 ' + formatCount(row.success) + '</span> <span class="result-badge result-fail">失敗 ' + formatCount(row.fail) + '</span></td>';
		html += '<td>' + (row.sftp > 0 ? '<span class="sc sc-3">SFTP</span>' : '<span class="sc sc-2">SSH</span>') + '</td>';
		html += '<td>' + escapeHtml(userLabel) + '</td>';
		html += '<td>' + escapeHtml(methods.length ? methods.join(', ') : '-') + '</td>';
		html += '<td class="nowrap"><strong>' + formatCount(row.total) + '件</strong></td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(row.last_time, '-')) + '</td></tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	initBulkBan('ssh-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: summaryRows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

function renderSshLoginDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var state = content && content.__sshLoginState ? content.__sshLoginState : null;
	var allRows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!allRows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var rows = filterIp ? allRows.filter(function(l) { return String(l.ip || '') === String(filterIp); }) : allRows.slice();
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var methodSelectOptions = buildFieldSelectOptions(rows, 'method');
	var keyOptions = buildFieldDatalist(rows, 'key_name');
	var countryOpts = buildCountrySelectOptions(flags, rows);
	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('detail', 'renderSshLoginSummary(this.closest(\'.async-content\'))', 'renderSshLoginDetail(this.closest(\'.async-content\'), null)');
	if (filterIp) {
		html += '<div class="nc-filter-bar"><span class="nc-filter-badge">IP: ' + escapeHtml(filterIp) + '</span><button class="btn-secondary btn-sm" onclick="renderSshLoginDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button></div>';
	}
	html += '<form method="post" data-bulk-ban="ssh-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="ssh_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="ssh-login"> 全選択</label><span class="bulk-ban-count" data-count="ssh-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="ssh-login" disabled>選択したIPをBAN</button></div>';
	html += '<div class="login-section">';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="success">成功</option><option value="fail">失敗</option></select></th><th><select class="filter-select" data-filter="type"><option value="">種別</option><option value="ssh">SSH</option><option value="sftp">SFTP</option></select></th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="method"><option value="">認証方法</option>' + methodSelectOptions + '</select></th><th><input type="text" class="filter-input" data-filter="key" list="ssh-login-key-list" placeholder="鍵名"><datalist id="ssh-login-key-list">' + keyOptions + '</datalist><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>結果</th><th>種別</th><th>ユーザー</th><th class="col-ip">IP</th><th class="col-country">国</th><th class="col-count">攻撃先Port</th><th>認証方法</th><th>鍵名</th></tr></thead><tbody>';
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var wl = isWhitelisted(l.ip);
		var ipEsc = escapeHtml(l.ip);
		var keyName = l.key_name || '';
		var typeVal = (l.type || '').toLowerCase();
		html += '<tr data-ip="' + ipEsc + '" data-result="' + escapeHtml(l.result || '') + '" data-type="' + escapeHtml(typeVal) + '" data-user="' + escapeHtml(l.user || '') + '" data-method="' + escapeHtml(l.method || '') + '" data-key="' + escapeHtml(keyName) + '" data-country="' + escapeHtml(flags[l.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (BANNED_IPS[l.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[l.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('summary', 'renderSshLoginSummary(this.closest(\'.async-content\'))') + '><td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="ssh-login"' + (wl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(l.time, '-')) + '</td><td>' + loginResultBadge(l.result) + '</td><td><span class="sc sc-' + (l.type === 'SFTP' ? '3' : '2') + '">' + escapeHtml(l.type || '') + '</span></td><td><strong>' + escapeHtml(l.user || '') + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(l.ip) + '</td><td class="col-country nowrap">' + escapeHtml(flags[l.ip] || '') + '</td><td class="col-count">' + escapeHtml(l.dst_port || '-') + '</td><td>' + escapeHtml(l.method || '') + '</td><td><strong>' + escapeHtml(keyName) + '</strong></td></tr>';
	}
	html += '</tbody></table></div></form>';
	content.innerHTML = html;
	initBulkBan('ssh-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: rows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

function renderSshLoginHistory(content, data) {
	content.__sshLoginState = { rows: data.entries || [], rate: data.rate || null, flags: data.flags || {} };
	renderSshLoginSummary(content);
}

function renderAppLoginSummary(content) {
	saveCurrentViewFilter(content);
	var state = content && content.__appLoginState ? content.__appLoginState : null;
	var rows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!rows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var appSelectOptions = buildLoginAppSelectOptions(rows);
	var countryOpts = buildCountrySelectOptions(flags, rows);

	var grouped = {};
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var ip = String(l.ip || '').trim();
		if (!ip) continue;
		if (!grouped[ip]) grouped[ip] = { ip: ip, total: 0, success: 0, fail: 0, apps: {}, users: {}, devices: {}, last_time: '' };
		var g = grouped[ip];
		g.total++;
		if (l.result === 'fail') g.fail++;
		else g.success++;
		var appVal = String(l.app || '').trim();
		if (appVal) g.apps[appVal] = true;
		var userVal = String(l.user || '').trim();
		if (userVal) g.users[userVal] = true;
		var devVal = String(l.device || 'unknown').trim();
		g.devices[devVal] = (g.devices[devVal] || 0) + 1;
		if (!g.last_time) g.last_time = String(l.time || '');
	}
	var summaryRows = Object.keys(grouped).map(function(ip) { return grouped[ip]; });
	summaryRows.sort(function(a, b) {
		if (b.fail !== a.fail) return b.fail - a.fail;
		if (b.total !== a.total) return b.total - a.total;
		return String(b.last_time || '').localeCompare(String(a.last_time || ''));
	});

	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('summary', 'renderAppLoginSummary(this.closest(\'.async-content\'))', 'renderAppLoginDetail(this.closest(\'.async-content\'), null)');
	html += '<div class="nc-summary-meta">直近 ' + formatCount(rows.length) + ' 件 &nbsp;/&nbsp; ' + formatCount(summaryRows.length) + ' IP</div>';
	html += '<form method="post" data-bulk-ban="app-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="app_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="app-login"> 全選択</label><span class="bulk-ban-count" data-count="app-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="app-login" disabled>選択したIPをBAN</button></div>';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="fail">失敗あり</option><option value="success">失敗なし</option></select></th><th>' + buildFilterSelect('app', 'アプリ', appSelectOptions, true) + '</th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, true) + '</th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th><th><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th>結果内訳</th><th>アプリ</th><th>ユーザー</th><th>デバイス</th><th>最終アクセス</th></tr></thead><tbody>';
	for (var r = 0; r < summaryRows.length; r++) {
		var row = summaryRows[r];
		var wl = isWhitelisted(row.ip);
		var banned = BANNED_IPS[row.ip] || '';
		var disableCb = wl || !!banned;
		var ipEsc = escapeHtml(row.ip);
		var appList = Object.keys(row.apps).sort();
		var appLabelList = appList.map(function(app) { return loginAppLabel(app); });
		var userList = Object.keys(row.users).sort();
		var dominantDevice = 'unknown';
		var dominantCount = -1;
		Object.keys(row.devices).forEach(function(k) {
			if (row.devices[k] > dominantCount) { dominantCount = row.devices[k]; dominantDevice = k; }
		});
		html += '<tr data-ip="' + ipEsc + '" data-result="' + (row.fail > 0 ? 'fail' : 'success') + '" data-app="' + escapeHtml(appList.join(' ')) + '" data-user="' + escapeHtml(userList.join(' ')) + '" data-device="' + escapeHtml(dominantDevice) + '" data-country="' + escapeHtml(flags[row.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (banned ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[row.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('detail', 'renderAppLoginDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')') + '>';
		html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="app-login"' + (disableCb ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(row.ip) + '</td>';
		html += '<td class="col-country nowrap">' + escapeHtml(flags[row.ip] || '') + '</td>';
		html += '<td><span class="result-badge result-success">成功 ' + formatCount(row.success) + '</span> <span class="result-badge result-fail">失敗 ' + formatCount(row.fail) + '</span></td>';
		html += '<td>' + escapeHtml(appLabelList.join(', ') || '-') + '</td>';
		html += '<td>' + escapeHtml(userList.slice(0, 2).join(', ') || '--') + (userList.length > 2 ? ' +' + (userList.length - 2) : '') + '</td>';
		html += '<td>' + deviceBadge({ device: dominantDevice, ua: dominantDevice === 'pc' ? 'PC' : (dominantDevice === 'mobile' ? 'モバイル' : '不明') }) + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(row.last_time, '-')) + '</td></tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	initBulkBan('app-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: summaryRows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

function renderAppLoginDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var state = content && content.__appLoginState ? content.__appLoginState : null;
	var allRows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!allRows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var rows = filterIp ? allRows.filter(function(l) { return String(l.ip || '') === String(filterIp); }) : allRows.slice();
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var appSelectOptions = buildLoginAppSelectOptions(rows);
	var countryOpts = buildCountrySelectOptions(flags, rows);
	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('detail', 'renderAppLoginSummary(this.closest(\'.async-content\'))', 'renderAppLoginDetail(this.closest(\'.async-content\'), null)');
	if (filterIp) {
		html += '<div class="nc-filter-bar"><span class="nc-filter-badge">IP: ' + escapeHtml(filterIp) + '</span><button class="btn-secondary btn-sm" onclick="renderAppLoginDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button></div>';
	}
	html += '<form method="post" data-bulk-ban="app-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="app_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="app-login"> 全選択</label><span class="bulk-ban-count" data-count="app-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="app-login" disabled>選択したIPをBAN</button></div>';
	html += '<div class="login-section">';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="success">成功</option><option value="fail">失敗</option></select></th><th>' + buildFilterSelect('app', 'アプリ', appSelectOptions, false) + '</th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th><th><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>結果</th><th>アプリ</th><th>ユーザー</th><th class="col-ip">IP</th><th class="col-country">国</th><th>デバイス</th><th></th></tr></thead><tbody>';
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var wl = isWhitelisted(l.ip);
		var ipEsc = escapeHtml(l.ip);
		var user = l.user || '—';
		var userCell = '<strong>' + escapeHtml(user) + '</strong>';
		if (l.result === 'fail' && (l.reason || l.pw_stats)) {
			var failMeta = [];
			if (l.reason) failMeta.push(l.reason);
			if (l.pw_stats) failMeta.push(l.pw_stats);
			userCell += '<br><small class="muted">' + escapeHtml(failMeta.join(' / ')) + '</small>';
		}
		html += '<tr data-ip="' + ipEsc + '" data-result="' + escapeHtml(l.result || '') + '" data-app="' + escapeHtml(l.app || '') + '" data-user="' + escapeHtml(l.user || '') + '" data-device="' + escapeHtml(l.device || '') + '" data-country="' + escapeHtml(flags[l.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (BANNED_IPS[l.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[l.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('summary', 'renderAppLoginSummary(this.closest(\'.async-content\'))') + '><td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="app-login"' + (wl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(l.time, '-')) + '</td><td>' + loginResultBadge(l.result) + '</td><td>' + escapeHtml(loginAppLabel(l.app_label || l.app || '')) + '</td><td>' + userCell + '</td><td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(l.ip) + '</td><td class="col-country nowrap">' + escapeHtml(flags[l.ip] || '') + '</td><td>' + deviceBadge(l) + '</td></tr>';
	}
	html += '</tbody></table></div></form>';
	content.innerHTML = html;
	initBulkBan('app-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: rows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

function renderAppLoginHistory(content, data) {
	content.__appLoginState = { rows: data.entries || [], rate: data.rate || null, flags: data.flags || {} };
	renderAppLoginSummary(content);
}

function renderPhpmyadminLoginSummary(content) {
	saveCurrentViewFilter(content);
	var state = content && content.__pmaLoginState ? content.__pmaLoginState : null;
	var rows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!rows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var countryOpts = buildCountrySelectOptions(flags, rows);

	var grouped = {};
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var ip = String(l.ip || '').trim();
		if (!ip) continue;
		if (!grouped[ip]) grouped[ip] = { ip: ip, total: 0, success: 0, fail: 0, users: {}, devices: {}, last_time: '' };
		var g = grouped[ip];
		g.total++;
		if (l.result === 'fail') g.fail++;
		else g.success++;
		var userVal = String(l.user || '').trim();
		if (userVal) g.users[userVal] = true;
		var devVal = String(l.device || 'unknown').trim();
		g.devices[devVal] = (g.devices[devVal] || 0) + 1;
		if (!g.last_time) g.last_time = String(l.time || '');
	}
	var summaryRows = Object.keys(grouped).map(function(ip) { return grouped[ip]; });
	summaryRows.sort(function(a, b) {
		if (b.fail !== a.fail) return b.fail - a.fail;
		if (b.total !== a.total) return b.total - a.total;
		return String(b.last_time || '').localeCompare(String(a.last_time || ''));
	});

	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('summary', 'renderPhpmyadminLoginSummary(this.closest(\'.async-content\'))', 'renderPhpmyadminLoginDetail(this.closest(\'.async-content\'), null)');
	html += '<div class="nc-summary-meta">直近 ' + formatCount(rows.length) + ' 件 &nbsp;/&nbsp; ' + formatCount(summaryRows.length) + ' IP</div>';
	html += '<form method="post" data-bulk-ban="pma-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="phpmyadmin_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="pma-login"> 全選択</label><span class="bulk-ban-count" data-count="pma-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="pma-login" disabled>選択したIPをBAN</button></div>';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="fail">失敗あり</option><option value="success">失敗なし</option></select></th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, true) + '</th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th><th><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th><th>結果内訳</th><th>ユーザー</th><th>デバイス</th><th>最終アクセス</th></tr></thead><tbody>';
	for (var r = 0; r < summaryRows.length; r++) {
		var row = summaryRows[r];
		var wl = isWhitelisted(row.ip);
		var banned = BANNED_IPS[row.ip] || '';
		var disableCb = wl || !!banned;
		var ipEsc = escapeHtml(row.ip);
		var userList = Object.keys(row.users).sort();
		var dominantDevice = 'unknown';
		var dominantCount = -1;
		Object.keys(row.devices).forEach(function(k) {
			if (row.devices[k] > dominantCount) { dominantCount = row.devices[k]; dominantDevice = k; }
		});
		html += '<tr data-ip="' + ipEsc + '" data-result="' + (row.fail > 0 ? 'fail' : 'success') + '" data-user="' + escapeHtml(userList.join(' ')) + '" data-device="' + escapeHtml(dominantDevice) + '" data-country="' + escapeHtml(flags[row.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (banned ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[row.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('detail', 'renderPhpmyadminLoginDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')') + '>';
		html += '<td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="pma-login"' + (disableCb ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(row.ip) + '</td>';
		html += '<td class="col-country nowrap">' + escapeHtml(flags[row.ip] || '') + '</td>';
		html += '<td><span class="result-badge result-success">成功 ' + formatCount(row.success) + '</span> <span class="result-badge result-fail">失敗 ' + formatCount(row.fail) + '</span></td>';
		html += '<td>' + escapeHtml(userList.slice(0, 2).join(', ') || '--') + (userList.length > 2 ? ' +' + (userList.length - 2) : '') + '</td>';
		html += '<td>' + deviceBadge({ device: dominantDevice, ua: dominantDevice === 'pc' ? 'PC' : (dominantDevice === 'mobile' ? 'モバイル' : '不明') }) + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(row.last_time, '-')) + '</td></tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	initBulkBan('pma-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: summaryRows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

function renderPhpmyadminLoginDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var state = content && content.__pmaLoginState ? content.__pmaLoginState : null;
	var allRows = state && state.rows ? state.rows : [];
	var flags = state && state.flags ? state.flags : {};
	var rateHtml = renderLoginRateStats(state ? state.rate : null);
	if (!allRows.length) { content.innerHTML = rateHtml + '<p class="empty">記録なし</p>'; return; }
	var rows = filterIp ? allRows.filter(function(l) { return String(l.ip || '') === String(filterIp); }) : allRows.slice();
	var userSelectOptions = buildFieldSelectOptions(rows, 'user');
	var countryOpts = buildCountrySelectOptions(flags, rows);
	var csrfToken = getCsrfToken();
	var html = rateHtml;
	html += cardViewToggle('detail', 'renderPhpmyadminLoginSummary(this.closest(\'.async-content\'))', 'renderPhpmyadminLoginDetail(this.closest(\'.async-content\'), null)');
	if (filterIp) {
		html += '<div class="nc-filter-bar"><span class="nc-filter-badge">IP: ' + escapeHtml(filterIp) + '</span><button class="btn-secondary btn-sm" onclick="renderPhpmyadminLoginDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button></div>';
	}
	html += '<form method="post" data-bulk-ban="pma-login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="phpmyadmin_login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="pma-login"> 全選択</label><span class="bulk-ban-count" data-count="pma-login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="pma-login" disabled>選択したIPをBAN</button></div>';
	html += '<div class="login-section">';
	html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th><select class="filter-select" data-filter="result"><option value="">結果</option><option value="success">成功</option><option value="fail">失敗</option></select></th><th>' + buildFilterSelect('user', 'ユーザー', userSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '</th><th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th><th><span class="filter-count"></span></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>結果</th><th>ユーザー</th><th class="col-ip">IP</th><th class="col-country">国</th><th>デバイス</th><th></th></tr></thead><tbody>';
	for (var i = 0; i < rows.length; i++) {
		var l = rows[i];
		var wl = isWhitelisted(l.ip);
		var ipEsc = escapeHtml(l.ip);
		var user = l.user || '—';
		html += '<tr data-ip="' + ipEsc + '" data-result="' + escapeHtml(l.result || '') + '" data-user="' + escapeHtml(l.user || '') + '" data-device="' + escapeHtml(l.device || '') + '" data-country="' + escapeHtml(flags[l.ip] || '') + '"' + (wl ? ' data-wl="1"' : '') + (BANNED_IPS[l.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[l.ip] ? ' data-known="1"' : '') + loginHistoryRowToggleAttrs('summary', 'renderPhpmyadminLoginSummary(this.closest(\'.async-content\'))') + '><td class="cb-col" onclick="event.stopPropagation();"><input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="pma-login"' + (wl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(l.time, '-')) + '</td><td>' + loginResultBadge(l.result) + '</td><td><strong>' + escapeHtml(user) + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation(); openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(l.ip) + '</td><td class="col-country nowrap">' + escapeHtml(flags[l.ip] || '') + '</td><td>' + deviceBadge(l) + '</td></tr>';
	}
	html += '</tbody></table></div></form>';
	content.innerHTML = html;
	initBulkBan('pma-login', content);
	autoInitCardFromDataset(content.closest('section.card'), { total: rows.length });
	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

function renderPhpmyadminLoginHistory(content, data) {
	content.__pmaLoginState = { rows: data.entries || [], rate: data.rate || null, flags: data.flags || {} };
	renderPhpmyadminLoginSummary(content);
}

function resolveLoginHistorySections(content) {
	var sections = null;
	if (content) {
		var attr = content.getAttribute('data-sections');
		if (attr) {
			try {
				var parsed = JSON.parse(attr);
				if (Array.isArray(parsed)) sections = parsed;
			} catch (e) {}
		}
	}
	if (!sections || sections.length === 0) {
		var opts = getCardOptions('login_history');
		if (Array.isArray(opts.sections)) sections = opts.sections;
	}
		if (!sections || sections.length === 0) {
			sections = ['ssh', 'nextcloud', 'heartdesk_monitor', 'phpmyadmin'];
		}
	return sections;
}

function renderLoginHistory(content, data) {
	var sections = resolveLoginHistorySections(content);
	var allowed = {};
	sections.forEach(function(s) { allowed[s] = true; });
	var showSsh = !!allowed.ssh;
	var showNc = !!allowed.nextcloud;
		var showDash = !!allowed.heartdesk_monitor;
	var showPma = !!allowed.phpmyadmin;

	if (!showSsh && !showNc && !showDash && !showPma) {
		content.innerHTML = '<p class="empty">表示対象がありません</p>';
		return;
	}

	var sshLogins = data.ssh_logins || [];
	var ncLogins = data.nc_logins || [];
	var dashLogins = data.dash_logins || [];
	var pmaLogins = data.pma_logins || [];
	var csrfToken = getCsrfToken();
	var html = '<form method="post" data-bulk-ban="login"><input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '"><input type="hidden" name="ban_section" value="login"><div class="bulk-ban-bar"><label class="bulk-select-all"><input type="checkbox" data-select-all="login"> 全選択</label><span class="bulk-ban-count" data-count="login">0件選択中</span><button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="login" disabled>選択したIPをBAN</button></div>';
	html += '<div class="login-grid">';

	if (showSsh) {
		html += '<div class="login-section login-section-ssh"><h3>SSH / SFTP <span id="login-ssh-expand-btn"></span></h3>';
		if (sshLogins.length > 0) {
			var sshUserSelectOptions = buildFieldSelectOptions(sshLogins, 'user');
			var sshMethodSelectOptions = buildFieldSelectOptions(sshLogins, 'method');
			var sshKeyOptions = buildFieldDatalist(sshLogins, 'key_name');
			html += '<table class="log-table"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th><select class="filter-select" data-filter="type"><option value="">種別</option><option value="ssh">SSH</option><option value="sftp">SFTP</option></select></th><th>' + buildFilterSelect('user', 'ユーザー', sshUserSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '<span class="filter-count"></span></th><th><select class="filter-select" data-filter="method"><option value="">認証方法</option>' + sshMethodSelectOptions + '</select></th><th><input type="text" class="filter-input" data-filter="key" list="login-ssh-key-list" placeholder="鍵名"><datalist id="login-ssh-key-list">' + sshKeyOptions + '</datalist></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>種別</th><th>ユーザー</th><th class="col-ip">IP</th><th>認証方法</th><th>鍵名</th></tr></thead><tbody>';
			for (var i = 0; i < sshLogins.length; i++) {
				var l = sshLogins[i];
				var wl = isWhitelisted(l.ip);
				html += '<tr data-ip="' + escapeHtml(l.ip) + '" data-type="' + escapeHtml((l.type || '').toLowerCase()) + '" data-user="' + escapeHtml(l.user || '') + '" data-method="' + escapeHtml(l.method || '') + '" data-key="' + escapeHtml(l.key_name || '') + '"' + (wl ? ' data-wl="1"' : '') + (BANNED_IPS[l.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[l.ip] ? ' data-known="1"' : '') + '><td class="cb-col"><input type="checkbox" name="ban_ips[]" value="' + escapeHtml(l.ip) + '" data-section="login"' + (wl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(l.time, '-')) + '</td><td><span class="sc sc-' + (l.type === 'SFTP' ? '3' : '2') + '">' + escapeHtml(l.type) + '</span></td><td><strong>' + escapeHtml(l.user) + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="openIpModal(\'' + escapeJsString(l.ip) + '\')">' + escapeHtml(l.ip) + '</code>' + ipBadges(l.ip) + '</td><td>' + escapeHtml(l.method) + '</td><td><strong>' + escapeHtml(l.key_name || '') + '</strong></td></tr>';
			}
			html += '</tbody></table>';
		} else { html += '<p class="empty">記録なし</p>'; }
		html += '</div>';
	}

	if (showNc) {
		html += '<div class="login-section login-section-nc"><h3>NextCloud <span id="login-nc-expand-btn"></span></h3>';
		if (ncLogins.length > 0) {
			var ncUserSelectOptions = buildFieldSelectOptions(ncLogins, 'user');
			html += '<table class="login-table-user"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th>' + buildFilterSelect('user', 'ユーザー', ncUserSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '<span class="filter-count"></span></th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th></tr><tr><th class="cb-col"></th><th>時刻</th><th>ユーザー</th><th class="col-ip">IP</th><th>デバイス</th></tr></thead><tbody>';
			for (var j = 0; j < ncLogins.length; j++) {
				var nl = ncLogins[j];
				var wlNc = isWhitelisted(nl.ip);
				html += '<tr data-ip="' + escapeHtml(nl.ip) + '" data-user="' + escapeHtml(nl.user || '') + '" data-device="' + escapeHtml(nl.device || '') + '"' + (wlNc ? ' data-wl="1"' : '') + (BANNED_IPS[nl.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[nl.ip] ? ' data-known="1"' : '') + '><td class="cb-col"><input type="checkbox" name="ban_ips[]" value="' + escapeHtml(nl.ip) + '" data-section="login"' + (wlNc ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(nl.time, '-')) + '</td><td><strong>' + escapeHtml(nl.user) + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="openIpModal(\'' + escapeJsString(nl.ip) + '\')">' + escapeHtml(nl.ip) + '</code>' + ipBadges(nl.ip) + '</td><td>' + deviceBadge(nl) + '</td></tr>';
			}
			html += '</tbody></table>';
		} else { html += '<p class="empty">記録なし</p>'; }
		html += '</div>';
	}

	if (showDash) {
		html += '<div class="login-section login-section-dash"><h3>ダッシュボード <span id="login-dash-expand-btn"></span></h3>';
		if (dashLogins.length > 0) {
			var dashUserSelectOptions = buildFieldSelectOptions(dashLogins, 'user');
			html += '<table class="login-table-user"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th>' + buildFilterSelect('user', 'ユーザー', dashUserSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '<span class="filter-count"></span></th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th></tr><tr><th class="cb-col"></th><th>最終アクセス</th><th>ユーザー</th><th class="col-ip">IP</th><th>デバイス</th></tr></thead><tbody>';
			for (var di = 0; di < dashLogins.length; di++) {
				var dl = dashLogins[di];
				var dwl = isWhitelisted(dl.ip);
				html += '<tr data-ip="' + escapeHtml(dl.ip) + '" data-user="' + escapeHtml(dl.user || '') + '" data-device="' + escapeHtml(dl.device || '') + '"' + (dwl ? ' data-wl="1"' : '') + (BANNED_IPS[dl.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[dl.ip] ? ' data-known="1"' : '') + '><td class="cb-col"><input type="checkbox" name="ban_ips[]" value="' + escapeHtml(dl.ip) + '" data-section="login"' + (dwl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(dl.time, '-')) + '</td><td><strong>' + escapeHtml(dl.user) + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="openIpModal(\'' + escapeJsString(dl.ip) + '\')">' + escapeHtml(dl.ip) + '</code>' + ipBadges(dl.ip) + '</td><td>' + deviceBadge(dl) + '</td></tr>';
			}
			html += '</tbody></table>';
		} else { html += '<p class="empty">記録なし</p>'; }
		html += '</div>';
	}

	if (showPma) {
		html += '<div class="login-section login-section-pma"><h3>phpMyAdmin <span id="login-pma-expand-btn"></span></h3>';
		if (pmaLogins.length > 0) {
			var pmaUserSelectOptions = buildFieldSelectOptions(pmaLogins, 'user');
			html += '<table class="login-table-user"><thead><tr class="thead-filter-row"><th class="cb-col"></th><th></th><th>' + buildFilterSelect('user', 'ユーザー', pmaUserSelectOptions, false) + '</th><th class="col-ip">' + buildIpFilterCell({wl:true,wlm:true,wla:true,ban:true,known:true}) + '<span class="filter-count"></span></th><th><select class="filter-select" data-filter="device"><option value="">デバイス</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="unknown">不明</option></select></th></tr><tr><th class="cb-col"></th><th>最終アクセス</th><th>ユーザー</th><th class="col-ip">IP</th><th>デバイス</th></tr></thead><tbody>';
			for (var pi = 0; pi < pmaLogins.length; pi++) {
				var pl = pmaLogins[pi];
				var pwl = isWhitelisted(pl.ip);
				html += '<tr data-ip="' + escapeHtml(pl.ip) + '" data-user="' + escapeHtml(pl.user || '') + '" data-device="' + escapeHtml(pl.device || '') + '"' + (pwl ? ' data-wl="1"' : '') + (BANNED_IPS[pl.ip] ? ' data-banned="1"' : '') + (KNOWN_IPS && KNOWN_IPS[pl.ip] ? ' data-known="1"' : '') + '><td class="cb-col"><input type="checkbox" name="ban_ips[]" value="' + escapeHtml(pl.ip) + '" data-section="login"' + (pwl ? ' disabled' : '') + '></td><td class="nowrap">' + escapeHtml(formatDisplayDateTime(pl.time, '-')) + '</td><td><strong>' + escapeHtml(pl.user) + '</strong></td><td class="col-ip"><code class="ip-clickable" onclick="openIpModal(\'' + escapeJsString(pl.ip) + '\')">' + escapeHtml(pl.ip) + '</code>' + ipBadges(pl.ip) + '</td><td>' + deviceBadge(pl) + '</td></tr>';
			}
			html += '</tbody></table>';
		} else { html += '<p class="empty">記録なし</p>'; }
		html += '</div>';
	}

	html += '</div></form>';
	content.innerHTML = html;
	initBulkBan('login', content);

	var sshSection = content.querySelector('.login-section-ssh');
	if (sshSection) {
		initRowLimit(sshSection, ROW_LIMIT_DEFAULT, 'login-ssh-expand-btn');
		setupCardFilter(sshSection.querySelector('.thead-filter-row'), sshSection);
	}
	var ncSection = content.querySelector('.login-section-nc');
	if (ncSection) {
		initRowLimit(ncSection, ROW_LIMIT_DEFAULT, 'login-nc-expand-btn');
		setupCardFilter(ncSection.querySelector('.thead-filter-row'), ncSection);
	}
	var dashSection = content.querySelector('.login-section-dash');
	if (dashSection) {
		initRowLimit(dashSection, ROW_LIMIT_DEFAULT, 'login-dash-expand-btn');
		setupCardFilter(dashSection.querySelector('.thead-filter-row'), dashSection);
	}
	var pmaSection = content.querySelector('.login-section-pma');
	if (pmaSection) {
		initRowLimit(pmaSection, ROW_LIMIT_DEFAULT, 'login-pma-expand-btn');
		setupCardFilter(pmaSection.querySelector('.thead-filter-row'), pmaSection);
	}
}

// ========================================
// Services
// ========================================
function renderServices(content, data) {
	var html = '<div class="svc-grid">';
	var services = data.services || {};
	// order配列があればその順で、なければオブジェクトキー順で表示
	var order = (data.order && data.order.length) ? data.order : Object.keys(services);
	order.forEach(function(name) {
		if (!services.hasOwnProperty(name)) return;
		var svc = services[name];
		var cls = svc.status === 'active' ? 'svc-ok' : 'svc-down';
		var verStr = svc.version ? ' (' + escapeHtml(svc.version) + ')' : '';
		html += '<div class="svc-box ' + cls + '"><div class="svc-row"><span class="svc-dot"></span><span class="svc-name">' + escapeHtml(name) + verStr + '</span></div><span class="svc-mem">' + svc.mem + ' MB</span></div>';
	});
	if (data.nextcloud) {
		var nc = data.nextcloud;
		var ncColor = nc['class'] === 'ok' ? '#4caf50' : '#ff9800';
		var ncVerStr = nc.version && nc.version !== '-' ? ' (' + escapeHtml(nc.version) + ')' : '';
		html += '<div class="svc-box"><div class="svc-row"><span class="svc-dot" style="background: ' + ncColor + '; box-shadow: 0 0 6px ' + ncColor + ';"></span><span class="svc-name">Nextcloud' + ncVerStr + '</span><span class="svc-st ' + escapeHtml(nc['class']) + '">' + escapeHtml(nc.label || '-') + '</span></div><span class="svc-mem">' + escapeHtml(nc.capacity || '-') + '</span></div>';
	}
	html += '</div>';

	// --- 運用コマンドボタン ---
	var actions = data.actions || [];
	if (actions.length > 0) {
		html += '<div class="kernel-section" style="flex-direction:column; align-items:flex-start; gap:10px;">';
		html += '<div class="command-cards-grid">';
		if (actions.indexOf('maintenance_toggle') !== -1) {
			if (data.is_maint) {
				html += '<div class="command-card command-card--maintenance-off">'
					+ '<button type="button" class="btn-warning"'
					+ ' onclick="if(confirm(\'メンテナンスモードを解除します。よろしいですか？\')){svcAction(\'maintenance_off\',this);}">'
					+ 'Nextcloud メンテナンスモード OFF</button></div>';
			} else {
				html += '<div class="command-card command-card--maintenance-on">'
					+ '<button type="button" class="btn-warning"'
					+ ' onclick="if(confirm(\'Nextcloudメンテナンスモードを有効にします。ユーザーがアクセスできなくなります。よろしいですか？\')){svcAction(\'maintenance_on\',this);}">'
					+ 'Nextcloud メンテナンスモード ON</button></div>';
			}
		}
		if (actions.indexOf('nc_repair') !== -1) {
			html += '<div class="command-card command-card--repair">'
				+ '<button type="button" class="btn-success"'
				+ ' onclick="if(confirm(\'Nextcloudのメンテナンス修復を実行します。よろしいですか？\')){svcAction(\'nc_repair\',this);}">'
				+ 'Nextcloud メンテナンス修復</button></div>';
		}
		if (actions.indexOf('restart_heartdesk') !== -1) {
			html += '<div class="command-card command-card--service-restart">'
				+ '<button type="button" class="btn-warning"'
				+ ' onclick="if(confirm(\'heartdeskサービスを再起動します。監視画面が数秒切断される場合があります。よろしいですか？\')){svcAction(\'restart_heartdesk\',this);}">'
				+ 'heartdesk サービス再起動</button></div>';
		}
		if (actions.indexOf('reboot') !== -1) {
			html += '<div class="command-card command-card--reboot">'
				+ '<button type="button" class="btn-danger"'
				+ ' onclick="if(confirm(\'サーバーを再起動します。NextCloudが1〜3分間停止します。よろしいですか？\')){svcAction(\'reboot\',this);}">'
				+ 'サーバー再起動</button></div>';
		}
		html += '</div></div>';
	}

	content.innerHTML = html;
}

// updatesAction: updates カードのアクションボタン共通 Ajax POST
function updatesAction(api, btn, confirmMsg, extraBody) {
	if (confirmMsg && !confirm(confirmMsg)) return;
	if (btn) { btn.disabled = true; btn.setAttribute('data-orig-text', btn.textContent); btn.textContent = '実行中…'; }
	var fd = new FormData();
	if (extraBody) {
		var pairs = extraBody.split('&');
		pairs.forEach(function(pair) {
			var kv = pair.split('=');
			if (kv.length === 2) fd.append(decodeURIComponent(kv[0]), decodeURIComponent(kv[1]));
		});
	}
	fetch(monitorApiURL(api), {
		method: 'POST',
		headers: { 'X-Requested-With': 'XMLHttpRequest' },
		body: fd,
		credentials: 'same-origin'
	})
	.then(function(r) { return r.json(); })
	.then(function(d) {
		showFlashModal(d.ok ? '成功' : 'エラー', d.message || (d.ok ? '完了しました' : '失敗しました'));
		if (d.ok && api === 'toggle_auto_update' && typeof window.refreshCard === 'function') {
			// 状態が変わったのでカード全体を再取得してボタンラベルを反映
			window.refreshCard(getMonitorCardId('UPDATES', 'sec-updates'), null);
		} else {
			if (btn) { btn.disabled = false; btn.textContent = btn.getAttribute('data-orig-text') || '実行'; }
		}
	})
	.catch(function(err) {
		showFlashModal('エラー', err.message);
		if (btn) { btn.disabled = false; btn.textContent = btn.getAttribute('data-orig-text') || '実行'; }
	});
}

// svcAction: services カードのアクションボタン共通 Ajax POST
function svcAction(api, btn) {
	if (btn) { btn.setAttribute('data-orig-text', btn.textContent); btn.disabled = true; btn.textContent = '実行中…'; }
	var fd = new FormData();
	fetch(monitorApiURL(api), {
		method: 'POST',
		headers: { 'X-Requested-With': 'XMLHttpRequest' },
		body: fd,
		credentials: 'same-origin'
	})
	.then(function(r) { return r.json(); })
	.then(function(d) {
		showFlashModal(d.ok ? '成功' : 'エラー', d.message || (d.ok ? '完了しました' : '失敗しました'));
		if (d.ok && (api === 'maintenance_on' || api === 'maintenance_off') && typeof window.refreshCard === 'function') {
			// 状態が反転したのでカード全体を再取得してボタンラベルを反映
			window.refreshCard(getMonitorCardId('SERVICES', 'sec-services'), null);
		} else {
			if (btn) { btn.disabled = false; btn.textContent = btn.getAttribute('data-orig-text') || '実行'; }
		}
	})
	.catch(function(err) {
		showFlashModal('エラー', err.message);
		if (btn) { btn.disabled = false; btn.textContent = btn.getAttribute('data-orig-text') || '実行'; }
	});
}


// ===== Realtime Resource Monitor =====
var RTM = {
	running: false,
	timer: null,
	INTERVAL: 3000,
	MAX_POINTS: 20,
	buffers: { cpu: [], mem: [], swap: [], disk: [], net_rx: [], net_tx: [] },
	prev: { cpu_raw: null, net_rx: null, net_tx: null, timestamp: null },
	colors: {
		cpu:    { line: '#42a5f5', fill: 'rgba(66,165,245,0.15)' },
		mem:    { line: '#ab47bc', fill: 'rgba(171,71,188,0.15)' },
		swap:   { line: '#ff9800', fill: 'rgba(255,152,0,0.15)' },
		disk:   { line: '#4caf50', fill: 'rgba(76,175,80,0.15)' },
		net_rx: { line: '#42a5f5', fill: 'rgba(66,165,245,0.10)' },
		net_tx: { line: '#ef5350', fill: 'rgba(239,83,80,0.10)' }
	}
};

function toggleRealtimeMonitor() {
	if (RTM.running) {
		clearInterval(RTM.timer);
		RTM.running = false;
		RTM.timer = null;
		document.getElementById('rtm-toggle').textContent = '開始';
		document.getElementById('rtm-status').textContent = '停止中';
		document.getElementById('rtm-toggle').classList.remove('active');
		document.querySelector('.rtm-grid').classList.remove('active');
	} else {
		RTM.running = true;
		// 折りたたまれていたら展開
		var secRealtimeMonitor = getMonitorCardId('REALTIME_MONITOR', 'sec-realtime-monitor');
		var rtmCard = document.getElementById(secRealtimeMonitor);
		if (rtmCard && rtmCard.classList.contains('collapsed')) {
			rtmCard.classList.remove('collapsed');
			var set = loadCollapsedSet();
			delete set[secRealtimeMonitor];
			saveCollapsedSet(set);
		}
		document.getElementById('rtm-toggle').textContent = '停止';
		document.getElementById('rtm-status').textContent = '取得中...';
		document.getElementById('rtm-toggle').classList.add('active');
		document.querySelector('.rtm-grid').classList.add('active');
		rtmInitCanvases();
		rtmFetchData();
		RTM.timer = setInterval(rtmFetchData, RTM.INTERVAL);
	}
}

function rtmInitCanvases() {
	var ids = ['rtm-cpu-canvas', 'rtm-mem-canvas', 'rtm-swap-canvas', 'rtm-disk-canvas', 'rtm-net-canvas'];
	var dpr = window.devicePixelRatio || 1;
	ids.forEach(function(id) {
		var c = document.getElementById(id);
		if (!c) return;
		var rect = c.getBoundingClientRect();
		c.width = rect.width * dpr;
		c.height = rect.height * dpr;
		var ctx = c.getContext('2d');
		ctx.scale(dpr, dpr);
	});
}

function rtmFetchData() {
	fetch(getAppBase() + '/?api=realtime_resources')
		.then(function(r) {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		})
		.then(function(data) {
			rtmProcessData(data);
			rtmRenderAllCharts();
			document.getElementById('rtm-status').textContent =
				'更新: ' + new Date().toLocaleTimeString('ja-JP');
		})
		.catch(function() {
			document.getElementById('rtm-status').textContent = 'エラー';
		});
}

function rtmProcessData(data) {
	// CPU使用率の差分計算
	var cpuPct = 0;
	if (RTM.prev.cpu_raw && data.cpu_raw) {
		var p = RTM.prev.cpu_raw, c = data.cpu_raw;
		var pTotal = p.user + p.nice + p.system + p.idle + p.iowait + p.irq + p.softirq + (p.steal || 0);
		var cTotal = c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + (c.steal || 0);
		var totalDiff = cTotal - pTotal;
		var idleDiff = (c.idle + c.iowait) - (p.idle + p.iowait);
		cpuPct = totalDiff > 0 ? Math.round((1 - idleDiff / totalDiff) * 1000) / 10 : 0;
		cpuPct = Math.max(0, Math.min(100, cpuPct));
	}
	RTM.prev.cpu_raw = data.cpu_raw;

	// ネットワーク差分計算（バイト/秒）
	var netRxRate = 0, netTxRate = 0;
	if (RTM.prev.net_rx !== null && RTM.prev.timestamp !== null) {
		var elapsed = data.timestamp - RTM.prev.timestamp;
		if (elapsed > 0) {
			netRxRate = Math.max(0, (data.network.rx - RTM.prev.net_rx) / elapsed);
			netTxRate = Math.max(0, (data.network.tx - RTM.prev.net_tx) / elapsed);
		}
	}
	RTM.prev.net_rx = data.network.rx;
	RTM.prev.net_tx = data.network.tx;
	RTM.prev.timestamp = data.timestamp;

	// バッファ追加
	rtmPush(RTM.buffers.cpu, cpuPct);
	rtmPush(RTM.buffers.mem, data.memory.pct);
	rtmPush(RTM.buffers.swap, data.swap.pct);
	rtmPush(RTM.buffers.disk, data.disk.pct);
	rtmPush(RTM.buffers.net_rx, netRxRate);
	rtmPush(RTM.buffers.net_tx, netTxRate);

	// 数値表示更新
	document.getElementById('rtm-cpu-val').textContent = cpuPct.toFixed(1) + ' %';
	document.getElementById('rtm-mem-val').textContent = data.memory.pct + ' %';
	document.getElementById('rtm-swap-val').textContent = data.swap.pct + ' %';
	document.getElementById('rtm-disk-val').textContent = data.disk.pct + ' %';
	document.getElementById('rtm-net-val').textContent =
		rtmFormatBytes(netRxRate) + '/s ↓  ' + rtmFormatBytes(netTxRate) + '/s ↑';

	// 詳細表示
	document.getElementById('rtm-load-val').textContent =
		'負荷: ' + data.load['1m'] + ' / ' + data.load['5m'] + ' / ' + data.load['15m'];
	document.getElementById('rtm-mem-detail').textContent =
		rtmFormatBytes(data.memory.used) + ' / ' + rtmFormatBytes(data.memory.total);
	document.getElementById('rtm-swap-detail').textContent =
		rtmFormatBytes(data.swap.used) + ' / ' + rtmFormatBytes(data.swap.total);
	document.getElementById('rtm-disk-detail').textContent =
		rtmFormatBytes(data.disk.used) + ' / ' + rtmFormatBytes(data.disk.total);
	if (data.network.iface) {
		document.getElementById('rtm-net-iface').textContent = data.network.iface;
	}

	// 色分け
	rtmSetColor('rtm-cpu-val', cpuPct, 60, 80);
	rtmSetColor('rtm-mem-val', data.memory.pct, 60, 80);
	rtmSetColor('rtm-swap-val', data.swap.pct, 20, 50);
	rtmSetColor('rtm-disk-val', data.disk.pct, 60, 80);
}

function rtmPush(arr, val) {
	arr.push(val);
	if (arr.length > RTM.MAX_POINTS) arr.shift();
}

function rtmSetColor(id, val, warnAt, dangerAt) {
	var el = document.getElementById(id);
	if (!el) return;
	el.className = 'rtm-panel-value ' + (val > dangerAt ? 'danger' : (val > warnAt ? 'warning' : 'ok'));
}

function rtmFormatBytes(bytes) {
	if (bytes < 1024) return bytes.toFixed(0) + ' B';
	if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
	if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
	return (bytes / 1073741824).toFixed(2) + ' GB';
}

function rtmDrawLineChart(canvasId, dataArr, color, maxVal, skipClear) {
	var canvas = document.getElementById(canvasId);
	if (!canvas) return;
	var ctx = canvas.getContext('2d');
	var dpr = window.devicePixelRatio || 1;
	var W = canvas.width / dpr;
	var H = canvas.height / dpr;
	var pad = { top: 5, right: 5, bottom: 5, left: 5 };
	var gW = W - pad.left - pad.right;
	var gH = H - pad.top - pad.bottom;

	if (!skipClear) {
		ctx.clearRect(0, 0, W, H);

		// グリッド線（タスクマネージャー風）
		ctx.strokeStyle = 'rgba(255,255,255,0.06)';
		ctx.lineWidth = 1;
		for (var i = 1; i <= 3; i++) {
			var y = pad.top + gH * (i / 4);
			ctx.beginPath();
			ctx.moveTo(pad.left, y);
			ctx.lineTo(W - pad.right, y);
			ctx.stroke();
		}
		for (var j = 1; j <= 4; j++) {
			var x = pad.left + gW * (j / 5);
			ctx.beginPath();
			ctx.moveTo(x, pad.top);
			ctx.lineTo(x, H - pad.bottom);
			ctx.stroke();
		}

		// Y軸ラベル（maxVal=100の場合）
		if (maxVal === 100) {
			ctx.fillStyle = 'rgba(255,255,255,0.2)';
			ctx.font = '9px sans-serif';
			ctx.textAlign = 'right';
			ctx.fillText('100%', W - pad.right - 2, pad.top + 10);
			ctx.fillText('0%', W - pad.right - 2, H - pad.bottom - 2);
		}
	}

	if (dataArr.length < 2) return;

	var effectiveMax = maxVal;
	if (maxVal === 0) {
		effectiveMax = Math.max.apply(null, dataArr) * 1.2 || 1;
	}

	var step = gW / (RTM.MAX_POINTS - 1);
	var startIdx = RTM.MAX_POINTS - dataArr.length;

	// 塗りつぶしパス
	ctx.beginPath();
	for (var k = 0; k < dataArr.length; k++) {
		var px = pad.left + (startIdx + k) * step;
		var py = pad.top + gH - (Math.min(dataArr[k], effectiveMax) / effectiveMax) * gH;
		if (k === 0) ctx.moveTo(px, py);
		else ctx.lineTo(px, py);
	}
	ctx.lineTo(pad.left + (startIdx + dataArr.length - 1) * step, pad.top + gH);
	ctx.lineTo(pad.left + startIdx * step, pad.top + gH);
	ctx.closePath();
	ctx.fillStyle = color.fill;
	ctx.fill();

	// 折れ線
	ctx.beginPath();
	for (var l = 0; l < dataArr.length; l++) {
		var lx = pad.left + (startIdx + l) * step;
		var ly = pad.top + gH - (Math.min(dataArr[l], effectiveMax) / effectiveMax) * gH;
		if (l === 0) ctx.moveTo(lx, ly);
		else ctx.lineTo(lx, ly);
	}
	ctx.strokeStyle = color.line;
	ctx.lineWidth = 2;
	ctx.stroke();
}

function rtmRenderAllCharts() {
	rtmDrawLineChart('rtm-cpu-canvas', RTM.buffers.cpu, RTM.colors.cpu, 100, false);
	rtmDrawLineChart('rtm-mem-canvas', RTM.buffers.mem, RTM.colors.mem, 100, false);
	rtmDrawLineChart('rtm-swap-canvas', RTM.buffers.swap, RTM.colors.swap, 100, false);
	rtmDrawLineChart('rtm-disk-canvas', RTM.buffers.disk, RTM.colors.disk, 100, false);
	// ネットワークは2系列を重ね描き
	rtmDrawLineChart('rtm-net-canvas', RTM.buffers.net_rx, RTM.colors.net_rx, 0, false);
	rtmDrawLineChart('rtm-net-canvas', RTM.buffers.net_tx, RTM.colors.net_tx, 0, true);
}

// タブ非アクティブ時にポーリング自動停止
if (typeof document !== 'undefined') {
	document.addEventListener('visibilitychange', function() {
		if (!RTM.running) return;
		if (document.hidden) {
			if (RTM.timer) {
				clearInterval(RTM.timer);
				RTM.timer = null;
			}
		} else {
			if (!RTM.timer) {
				rtmInitCanvases();
				rtmFetchData();
				RTM.timer = setInterval(rtmFetchData, RTM.INTERVAL);
			}
		}
	});
}

// ウィンドウリサイズ時にCanvas再初期化
if (typeof window !== 'undefined') {
	window.addEventListener('resize', function() {
		if (RTM.running) {
			rtmInitCanvases();
			rtmRenderAllCharts();
		}
	});
}

function loadNotificationRulesRuntime() {
	var secNotificationRules = getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules');
	var section = document.getElementById(secNotificationRules);
	if (!section) return;
	fetch(getAppBase() + '/?api=alert_rules')
		.then(function(r) {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		})
		.then(function(data) {
			var runtime = (data && data.runtime) ? data.runtime : {};
			Object.keys(runtime).forEach(function(ruleId) {
				var row = runtime[ruleId] || {};
				var valueEl = section.querySelector('[data-alert-last-value="' + ruleId + '"]');
				var activeEl = section.querySelector('[data-alert-active="' + ruleId + '"]');
				if (valueEl) {
					valueEl.textContent = (row.last_value || '-');
					var isService = (row.value_type === 'service');
					valueEl.classList.toggle('nr-value-service-active', isService && row.last_value === 'active');
					valueEl.classList.toggle('nr-value-service-inactive', isService && row.last_value !== 'active' && !!row.evaluated);
				}
				if (activeEl) {
					var evaluated = !!row.evaluated;
					var active = !!row.active;
					if (!evaluated) {
						activeEl.textContent = '未評価';
					} else {
						activeEl.textContent = active ? 'active' : 'inactive';
					}
					activeEl.classList.toggle('notification-rules-active', evaluated && active);
					activeEl.classList.toggle('notification-rules-inactive', evaluated && !active);
					activeEl.classList.toggle('notification-rules-pending', !evaluated);
				}
			});
		})
		.catch(function(err) {
			console.error('[notification_rules] load failed:', err);
		});
}

function downloadNotificationRecipientsCsv() {
	var modal = document.getElementById('notification-recipient-modal');
	if (!modal) return;
	var rows = modal.querySelectorAll('[data-recipient-row]');
	if (rows.length === 0) return;

	// ルールIDとラベルを先頭行から収集
	var ruleHeaders = [];
	var firstRulesDiv = rows[0].querySelector('.recipient-item-rules');
	if (firstRulesDiv) {
		firstRulesDiv.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
			var label = cb.closest('label');
			var span = label ? label.querySelector('span') : null;
			var ruleId = cb.getAttribute('data-rule-id') || '';
			if (!ruleId) {
				var m = (cb.name || '').match(/\[rules\]\[([^\]]+)\]/);
				ruleId = m ? m[1] : '';
			}
			ruleHeaders.push({ id: ruleId, label: span ? span.textContent.trim() : ruleId });
		});
	}

	var csvRows = [['名前', 'メール', '送信設定'].concat(ruleHeaders.map(function(r) { return r.label; }))];

	rows.forEach(function(row) {
		var nameInput = row.querySelector('input[name*="[name]"], input[data-field="name"]');
		var emailInput = row.querySelector('input[name*="[email]"], input[data-field="email"]');
		var enabledInput = row.querySelector('input[name*="[enabled]"], input[data-field="enabled"]');
		var name = nameInput ? nameInput.value.trim() : '';
		var email = emailInput ? emailInput.value.trim() : '';
		var enabled = (enabledInput && enabledInput.checked) ? '送信ON' : '送信OFF';
		var ruleCols = ruleHeaders.map(function(r) {
			var cb = row.querySelector('input[name*="[rules][' + r.id + ']"], input[data-rule-id="' + r.id + '"]');
			return (cb && cb.checked) ? '✓' : '';
		});
		csvRows.push([name, email, enabled].concat(ruleCols));
	});

	var bom = '\uFEFF';
	var csv = bom + csvRows.map(function(cols) {
		return cols.map(function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
	}).join('\r\n');

	var d = new Date();
	var stamp = d.getFullYear() + ('0' + (d.getMonth() + 1)).slice(-2) + ('0' + d.getDate()).slice(-2);
	var blob = new Blob([csv], { type: 'text/csv' });
	var a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'notification_recipients_' + stamp + '.csv';
	a.click();
	URL.revokeObjectURL(a.href);
}

if (typeof document !== 'undefined') {
	document.addEventListener('DOMContentLoaded', loadNotificationRulesRuntime);
	document.addEventListener('card:refreshed', function(ev) {
		var cardId = ev && ev.detail && ev.detail.cardId;
		if (cardId === getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules')) {
			loadNotificationRulesRuntime();
		}
	});
}

function closeNotificationRecipientModal() {
	var modal = document.getElementById('notification-recipient-modal');
	if (modal) modal.style.display = 'none';
}

function openNotificationRecipientModal() {
	var modal = document.getElementById('notification-recipient-modal');
	if (modal) {
		modal.style.display = 'flex';
		syncNotificationRecipientRequired();
	}
}

function renumberNotificationRecipientRows() {
	var tbody = document.querySelector('#notification-recipient-modal [data-recipient-tbody]');
	if (!tbody) return;
	var rows = tbody.querySelectorAll('[data-recipient-row]');
	rows.forEach(function(row, idx) {
		var idInput = row.querySelector('input[name*="[id]"], input[data-field="id"]');
		var nameInput = row.querySelector('input[name*="[name]"], input[data-field="name"]');
		var emailInput = row.querySelector('input[name*="[email]"], input[data-field="email"]');
		var enabledInput = row.querySelector('input[name*="[enabled]"], input[data-field="enabled"]');
		if (idInput) idInput.name = 'recipients[' + idx + '][id]';
		if (nameInput) nameInput.name = 'recipients[' + idx + '][name]';
		if (emailInput) emailInput.name = 'recipients[' + idx + '][email]';
		if (enabledInput) enabledInput.name = 'recipients[' + idx + '][enabled]';
		var ruleInputs = row.querySelectorAll('input[name*="[rules]["], input[data-field="rule"]');
		ruleInputs.forEach(function(input) {
			var ruleId = input.getAttribute('data-rule-id');
			if (!ruleId) {
				var m = input.name.match(/\[rules\]\[([^\]]+)\]/);
				ruleId = m ? m[1] : '';
			}
			if (ruleId) input.name = 'recipients[' + idx + '][rules][' + ruleId + ']';
		});
	});
}

function syncNotificationRecipientRequired() {
	var tbody = document.querySelector('#notification-recipient-modal [data-recipient-tbody]');
	if (!tbody) return;
	var rows = tbody.querySelectorAll('[data-recipient-row]');
	rows.forEach(function(row) {
		var nameInput = row.querySelector('input[name*="[name]"], input[data-field="name"]');
		var emailInput = row.querySelector('input[name*="[email]"], input[data-field="email"]');
		if (!nameInput || !emailInput) return;
		var hasValue = (nameInput.value || '').trim() !== '' || (emailInput.value || '').trim() !== '';
		nameInput.required = hasValue;
		emailInput.required = hasValue;
	});
}

function addNotificationRecipientRow() {
	var tmpl = document.getElementById('notification-recipient-row-template');
	var tbody = document.querySelector('#notification-recipient-modal [data-recipient-tbody]');
	if (!tmpl || !tbody) return;
	var frag = tmpl.content.cloneNode(true);
	tbody.appendChild(frag);
	renumberNotificationRecipientRows();
	syncNotificationRecipientRequired();
}

var notificationRulesSaveTimer = null;
var notificationRulesSaveInflight = false;
var notificationRulesSavePendingForm = null;
var notificationRecipientsSaveTimer = null;
var notificationRecipientsSaveInflight = false;
var notificationRecipientsSavePendingForm = null;

function setNotificationRulesSaveStatus(message, stateClass) {
	var secNotificationRules = getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules');
	var statusEl = document.querySelector('#' + secNotificationRules + ' [data-alert-save-status]');
	if (!statusEl) return;
	statusEl.textContent = message || '';
	statusEl.classList.remove('is-saving', 'is-ok', 'is-error');
	if (stateClass) statusEl.classList.add(stateClass);
}

function postNotificationRules(form) {
	if (!form || notificationRulesSaveInflight) return;
	if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;
	notificationRulesSaveInflight = true;
	setNotificationRulesSaveStatus('保存中...', 'is-saving');

	var data = new FormData(form);
	fetch(getAppBase() + '/?api=save_alert_rules', {
		method: 'POST',
		body: data,
		credentials: 'same-origin',
		headers: { 'X-Requested-With': 'XMLHttpRequest' }
	})
		.then(function(resp) {
			return resp.json().catch(function() { return null; }).then(function(payload) {
				return { ok: resp.ok, payload: payload };
			});
		})
		.then(function(result) {
			var payload = result.payload || {};
			if (result.ok && payload.ok) {
				setNotificationRulesSaveStatus('保存済み', 'is-ok');
				return;
			}
			var errs = (payload && payload.errors && payload.errors.length) ? payload.errors.join(' / ') : '保存失敗';
			setNotificationRulesSaveStatus(errs, 'is-error');
		})
		.catch(function(err) {
			console.error('[notification_rules] save failed:', err);
			setNotificationRulesSaveStatus('保存失敗', 'is-error');
		})
		.finally(function() {
			notificationRulesSaveInflight = false;
			if (notificationRulesSavePendingForm) {
				var pending = notificationRulesSavePendingForm;
				notificationRulesSavePendingForm = null;
				postNotificationRules(pending);
			}
		});
}

function scheduleNotificationRulesSave(form) {
	if (!form) return;
	notificationRulesSavePendingForm = form;
	setNotificationRulesSaveStatus('保存待機中...', 'is-saving');
	if (notificationRulesSaveTimer) {
		clearTimeout(notificationRulesSaveTimer);
	}
	notificationRulesSaveTimer = setTimeout(function() {
		notificationRulesSaveTimer = null;
		var pending = notificationRulesSavePendingForm;
		notificationRulesSavePendingForm = null;
		if (!pending) return;
		if (notificationRulesSaveInflight) {
			notificationRulesSavePendingForm = pending;
			return;
		}
		postNotificationRules(pending);
	}, 300);
}

function setNotificationRecipientsSaveStatus(message, stateClass) {
	var statusEl = document.querySelector('#notification-recipient-modal [data-recipient-save-status]');
	if (!statusEl) return;
	statusEl.textContent = message || '';
	statusEl.classList.remove('is-saving', 'is-ok', 'is-error');
	if (stateClass) statusEl.classList.add(stateClass);
}

function postNotificationRecipients(form) {
	if (!form || notificationRecipientsSaveInflight) return;
	if (typeof form.checkValidity === 'function' && !form.checkValidity()) {
		setNotificationRecipientsSaveStatus('未保存', 'is-error');
		return;
	}
	notificationRecipientsSaveInflight = true;
	setNotificationRecipientsSaveStatus('保存中...', 'is-saving');

	var data = new FormData(form);
	fetch(getAppBase() + '/?api=save_alert_recipients', {
		method: 'POST',
		body: data,
		credentials: 'same-origin',
		headers: { 'X-Requested-With': 'XMLHttpRequest' }
	})
		.then(function(resp) {
			return resp.json().catch(function() { return null; }).then(function(payload) {
				return { ok: resp.ok, payload: payload };
			});
		})
		.then(function(result) {
			var payload = result.payload || {};
			if (result.ok && payload.ok) {
				setNotificationRecipientsSaveStatus('保存済み', 'is-ok');
				return;
			}
			var errs = (payload && payload.errors && payload.errors.length) ? payload.errors.join(' / ') : '保存失敗';
			setNotificationRecipientsSaveStatus(errs, 'is-error');
		})
		.catch(function(err) {
			console.error('[notification_recipients] save failed:', err);
			setNotificationRecipientsSaveStatus('保存失敗', 'is-error');
		})
		.finally(function() {
			notificationRecipientsSaveInflight = false;
			if (notificationRecipientsSavePendingForm) {
				var pending = notificationRecipientsSavePendingForm;
				notificationRecipientsSavePendingForm = null;
				postNotificationRecipients(pending);
			}
		});
}

function scheduleNotificationRecipientsSave(form) {
	if (!form) return;
	renumberNotificationRecipientRows();
	syncNotificationRecipientRequired();
	notificationRecipientsSavePendingForm = form;
	setNotificationRecipientsSaveStatus('保存待機中...', 'is-saving');
	if (notificationRecipientsSaveTimer) {
		clearTimeout(notificationRecipientsSaveTimer);
	}
	notificationRecipientsSaveTimer = setTimeout(function() {
		notificationRecipientsSaveTimer = null;
		var pending = notificationRecipientsSavePendingForm;
		notificationRecipientsSavePendingForm = null;
		if (!pending) return;
		if (notificationRecipientsSaveInflight) {
			notificationRecipientsSavePendingForm = pending;
			return;
		}
		postNotificationRecipients(pending);
	}, 300);
}

function bindNotificationRecipientModal() {
	var openBtn = document.querySelector('[data-open-recipient-modal]');
	if (openBtn && openBtn.dataset.boundModalOpen !== '1') {
		openBtn.dataset.boundModalOpen = '1';
		openBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			openNotificationRecipientModal();
		});
	}
	var closeBtn = document.querySelector('[data-close-recipient-modal]');
	if (closeBtn && closeBtn.dataset.boundModalClose !== '1') {
		closeBtn.dataset.boundModalClose = '1';
		closeBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			closeNotificationRecipientModal();
		});
	}
	var addBtn = document.querySelector('[data-add-recipient-row]');
	if (addBtn && addBtn.dataset.boundModalAdd !== '1') {
		addBtn.dataset.boundModalAdd = '1';
		addBtn.addEventListener('click', function(ev) {
			ev.preventDefault();
			addNotificationRecipientRow();
		});
	}
	var modal = document.getElementById('notification-recipient-modal');
	if (modal && modal.dataset.boundModalOverlay !== '1') {
		modal.dataset.boundModalOverlay = '1';
		modal.addEventListener('click', function(ev) {
			if (ev.target === modal) closeNotificationRecipientModal();
		});
	}
}

if (typeof document !== 'undefined') {
	document.addEventListener('click', function(ev) {
		var openBtn = ev.target.closest('[data-open-recipient-modal]');
		if (openBtn) {
			ev.preventDefault();
			openNotificationRecipientModal();
			return;
		}
		var closeBtn = ev.target.closest('[data-close-recipient-modal]');
		if (closeBtn) {
			ev.preventDefault();
			closeNotificationRecipientModal();
			return;
		}
		if (ev.target.id === 'recipient-list-download') {
			ev.preventDefault();
			downloadNotificationRecipientsCsv();
			return;
		}
		var addBtn = ev.target.closest('[data-add-recipient-row]');
		if (addBtn) {
			ev.preventDefault();
			addNotificationRecipientRow();
			return;
		}
		var removeBtn = ev.target.closest('[data-remove-recipient-row]');
		if (removeBtn) {
			ev.preventDefault();
			var row = removeBtn.closest('[data-recipient-row]');
			if (row) row.remove();
			renumberNotificationRecipientRows();
			var recipientForm = removeBtn.closest('#notification-recipient-modal .notification-recipient-form');
			if (recipientForm) scheduleNotificationRecipientsSave(recipientForm);
			return;
		}
		if (ev.target.id === 'notification-recipient-modal') {
			closeNotificationRecipientModal();
		}
	});

	document.addEventListener('change', function(ev) {
		var rulesInput = ev.target;
		var secNotificationRules = getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules');
		var rulesForm = rulesInput && rulesInput.closest('#' + secNotificationRules + ' .notification-rules-form');
		if (rulesForm && rulesInput.name && rulesInput.name.indexOf('alert_rules[') === 0) {
			scheduleNotificationRulesSave(rulesForm);
			return;
		}

		var checkbox = ev.target;
		if (!checkbox.matches('#notification-recipient-modal input[type="checkbox"]')) return;
		if (checkbox.matches('input[name*="[enabled]"], input[data-field="enabled"]')) {
			var label = checkbox.closest('label');
			if (label) {
				var toggleText = label.querySelector('.toggle-text');
				if (toggleText) toggleText.textContent = checkbox.checked ? '送信ON' : '送信OFF';
			}
		}
		var recipientForm = checkbox.closest('#notification-recipient-modal .notification-recipient-form');
		if (recipientForm) scheduleNotificationRecipientsSave(recipientForm);
	});

	document.addEventListener('input', function(ev) {
		var input = ev.target;
		if (!input.matches('#notification-recipient-modal input[name*="[name]"], #notification-recipient-modal input[name*="[email]"], #notification-recipient-modal input[data-field="name"], #notification-recipient-modal input[data-field="email"]')) return;
		syncNotificationRecipientRequired();
	});

	document.addEventListener('submit', function(ev) {
		var form = ev.target;
		var secNotificationRules = getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules');
		if (!form.matches('#' + secNotificationRules + ' .notification-rules-form')) return;
		ev.preventDefault();
		scheduleNotificationRulesSave(form);
	});

	document.addEventListener('change', function(ev) {
		var input = ev.target;
		if (!input.matches('#notification-recipient-modal input[name*="[name]"], #notification-recipient-modal input[name*="[email]"], #notification-recipient-modal input[data-field="name"], #notification-recipient-modal input[data-field="email"]')) return;
		var recipientForm = input.closest('#notification-recipient-modal .notification-recipient-form');
		if (recipientForm) scheduleNotificationRecipientsSave(recipientForm);
	});

	document.addEventListener('submit', function(ev) {
		var form = ev.target;
		if (!form.matches('#notification-recipient-modal .notification-recipient-form')) return;
		ev.preventDefault();
		scheduleNotificationRecipientsSave(form);
	});

	document.addEventListener('DOMContentLoaded', function() {
		renumberNotificationRecipientRows();
		syncNotificationRecipientRequired();
		bindNotificationRecipientModal();
	});
	document.addEventListener('card:refreshed', function(ev) {
		var cardId = ev && ev.detail && ev.detail.cardId;
		if (cardId === getMonitorCardId('NOTIFICATION_RULES', 'sec-notification-rules')) {
			renumberNotificationRecipientRows();
			syncNotificationRecipientRequired();
			bindNotificationRecipientModal();
			setNotificationRulesSaveStatus('', '');
			setNotificationRecipientsSaveStatus('', '');
		}
	});
}

// =============================================================================
// 汎用モーダル基盤: openModal / closeModal / confirmModal
//   - 開いた要素を記憶し、閉じたらフォーカスを復帰する
//   - 開いた時の初期フォーカスを .modal-close（無ければ最初の可フォーカス要素）へ移す
//   - Tab/Shift+Tab をモーダル内に拘束（フォーカストラップ）
//   - 全モーダル共通の document レベル Escape ハンドラ1本で最前面モーダルを閉じる
// 既存モーダルは id を持つ .modal-overlay（display:flex/none で開閉）。本基盤はその規約に乗る。
// =============================================================================
(function() {
	var openStack = [];          // 現在開いているモーダル id のスタック（最後＝最前面）
	var lastFocus = {};          // id -> 開く前にフォーカスしていた要素

	function focusable(modal) {
		return Array.prototype.slice.call(modal.querySelectorAll(
			'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
		)).filter(function(el) { return el.offsetParent !== null || el === document.activeElement; });
	}

	function openModal(id) {
		var modal = document.getElementById(id);
		if (!modal) return null;
		lastFocus[id] = document.activeElement;
		modal.style.display = 'flex';
		if (openStack.indexOf(id) === -1) openStack.push(id);
		// 初期フォーカス: .modal-close 優先、無ければ最初の可フォーカス要素
		var closeBtn = modal.querySelector('.modal-close');
		var target = closeBtn || focusable(modal)[0];
		if (target && typeof target.focus === 'function') {
			try { target.focus(); } catch (e) {}
		}
		return modal;
	}

	function closeModal(id) {
		var modal = document.getElementById(id);
		if (modal) modal.style.display = 'none';
		var idx = openStack.indexOf(id);
		if (idx !== -1) openStack.splice(idx, 1);
		// フォーカス復帰
		var prev = lastFocus[id];
		delete lastFocus[id];
		if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
			try { prev.focus(); } catch (e) {}
		}
	}

	function topModalId() {
		return openStack.length ? openStack[openStack.length - 1] : null;
	}

	// 共通 Escape / フォーカストラップ（document 1本）
	document.addEventListener('keydown', function(ev) {
		var id = topModalId();
		if (!id) return;
		var modal = document.getElementById(id);
		if (!modal || modal.style.display === 'none') return;
		if (ev.key === 'Escape' || ev.keyCode === 27) {
			ev.preventDefault();
			closeModal(id);
			return;
		}
		if (ev.key === 'Tab' || ev.keyCode === 9) {
			var items = focusable(modal);
			if (!items.length) return;
			var first = items[0];
			var last = items[items.length - 1];
			if (ev.shiftKey && document.activeElement === first) {
				ev.preventDefault();
				last.focus();
			} else if (!ev.shiftKey && document.activeElement === last) {
				ev.preventDefault();
				first.focus();
			}
		}
	});

	window.openModal = openModal;
	window.closeModal = closeModal;

	// confirmModal(message) -> Promise<bool>。openModal/closeModal 基盤上の確認ダイアログ。
	// 専用 DOM を1つ用意し（無ければ生成）、OK/キャンセルで Promise を解決する。
	window.confirmModal = function(message) {
		return new Promise(function(resolve) {
			var ID = 'heartdesk-confirm-modal';
			var modal = document.getElementById(ID);
			if (!modal) {
				modal = document.createElement('div');
				modal.id = ID;
				modal.className = 'modal-overlay';
				modal.style.display = 'none';
				modal.setAttribute('role', 'dialog');
				modal.setAttribute('aria-modal', 'true');
				modal.setAttribute('aria-labelledby', ID + '-title');
				modal.innerHTML = ''
					+ '<div class="modal-content">'
					+ '  <div class="modal-header">'
					+ '    <h3 id="' + ID + '-title" class="modal-title">確認</h3>'
					+ '    <button type="button" class="modal-close" data-confirm-cancel aria-label="閉じる">&times;</button>'
					+ '  </div>'
					+ '  <div class="modal-body"><p data-confirm-message></p></div>'
					+ '  <div class="modal-footer" style="display:flex;gap:8px;justify-content:flex-end;padding:12px;">'
					+ '    <button type="button" class="btn-secondary btn-sm" data-confirm-cancel>キャンセル</button>'
					+ '    <button type="button" class="btn-primary btn-sm" data-confirm-ok>OK</button>'
					+ '  </div>'
					+ '</div>';
				document.body.appendChild(modal);
			}
			var msgEl = modal.querySelector('[data-confirm-message]');
			if (msgEl) msgEl.textContent = message == null ? '' : String(message);

			var done = false;
			function cleanup(result) {
				if (done) return;
				done = true;
				modal.removeEventListener('click', onClick);
				document.removeEventListener('keydown', onKey);
				closeModal(ID);
				resolve(result);
			}
			function onClick(ev) {
				if (ev.target.closest('[data-confirm-ok]')) { cleanup(true); }
				else if (ev.target.closest('[data-confirm-cancel]')) { cleanup(false); }
				else if (ev.target === modal) { cleanup(false); }
			}
			function onKey(ev) {
				if (ev.key === 'Escape' || ev.keyCode === 27) cleanup(false);
			}
			modal.addEventListener('click', onClick);
			document.addEventListener('keydown', onKey);
			openModal(ID);
			// OK ボタンへ初期フォーカス（confirm の既定動作に寄せる）
			var okBtn = modal.querySelector('[data-confirm-ok]');
			if (okBtn) { try { okBtn.focus(); } catch (e) {} }
		});
	};
})();

// =============================================================================
// Flash Message Modal
// =============================================================================
var showFlashModal;
(function() {
	var overlay  = document.getElementById('flash-modal');
	var content  = document.getElementById('flash-modal-content');
	var titleEl  = document.getElementById('flash-modal-title');
	var bodyEl   = document.getElementById('flash-modal-body');
	var closeBtn = document.getElementById('flash-modal-close');

	var queue   = (typeof FLASH_MSGS !== 'undefined') ? FLASH_MSGS.slice() : [];
	var current = 0;

	var TYPE_CLASS = {
		'success': 'flash-type-success',
		'ban':     'flash-type-ban',
		'warning': 'flash-type-warning',
		'error':   'flash-type-error',
		'maint':   'flash-type-maint',
		'unban':   'flash-type-unban',
	};

	showFlashModal = function(title, message, type, output, sticky) {
		if (!overlay || !bodyEl) return;
		
		// 新しいメッセージをキューに追加
		queue.push({
			title: title,
			message: message,
			type: type || 'success',
			output: output,
			sticky: !!sticky
		});

		// 現在表示中でなければ表示開始
		if (overlay.style.display !== 'flex') {
			showFlash(current);
		}
	};

	function showFlash(idx) {
		if (idx >= queue.length) { 
			overlay.style.display = 'none'; 
			current = 0;
			queue = [];
			return; 
		}
		var msg = queue[idx];

		content.className = 'modal-content';
		var cls = TYPE_CLASS[msg.type] || 'flash-type-success';
		content.classList.add(cls);

		titleEl.textContent = msg.title || '通知';

		var html = '<p>' + escapeHtml(msg.message) + '</p>';
		if (msg.output) {
			html += '<details><summary>実行結果</summary>'
			      + '<pre class="pre-output-scroll">' + escapeHtml(msg.output) + '</pre>'
			      + '</details>';
		}
		if (queue.length > 1) {
			html += '<p class="flash-counter">' + (idx + 1) + ' / ' + queue.length + '</p>';
		}
		bodyEl.innerHTML = html;

		overlay.style.display = 'flex';

		if (!msg.sticky) {
			setTimeout(function() { if (current === idx) showFlash(idx + 1); }, 5000);
		}
	}

	if (closeBtn) {
		closeBtn.addEventListener('click', function() { showFlash(++current); });
	}
	if (overlay) {
		overlay.addEventListener('click', function(e) {
			if (e.target === overlay) showFlash(++current);
		});
	}

	if (queue.length > 0) {
		showFlash(0);
	}
})();

// =============================================================================
// showToast — 軽量通知 API。
// 多数のカードが showToast(msg, kind) を呼ぶが定義が無く、
// typeof ガードで握り潰されて成功通知が消えていた。showFlashModal をラップして1本化する。
// kind: 'success'(既定) / 'error' / 'warning' / 'info' を flash-type-* へマップする。
// =============================================================================
window.showToast = function(msg, kind) {
	var type = 'success';
	if (kind === 'error' || kind === 'danger') type = 'error';
	else if (kind === 'warning' || kind === 'warn') type = 'warning';
	else if (kind === 'success' || kind === 'ok') type = 'success';
	else if (kind === 'info') type = 'success';
	var title = (type === 'error') ? 'エラー' : (type === 'warning' ? '警告' : '通知');
	if (typeof showFlashModal === 'function') {
		showFlashModal(title, msg == null ? '' : String(msg), type);
	}
};

// =============================================================================
// カードレンダラー — resources / fail2ban / ip_mgmt
// =============================================================================

// ---- Resources ----
function renderResources(content, data) {
	var memUsedMB = Math.round(data.mem_used / 1024 / 1024);
	var memTotalMB = Math.round(data.mem_total / 1024 / 1024);
	var swapUsedMB = Math.round((data.swap_total - data.swap_free) / 1024 / 1024);
	var swapTotalMB = Math.round(data.swap_total / 1024 / 1024);
	var cpuBar = Math.min(100, Math.round(data.cpu_pct || 0));
	var memBar = Math.min(100, Math.round(data.mem_pct || 0));
	var diskBar = Math.min(100, Math.max(0, Math.round(parseFloat(String(data.disk_pct || '0').replace('%', '')) || 0)));
	function bar(pct, danger, warn) {
		var cls = pct >= danger ? 'res-bar-danger' : pct >= warn ? 'res-bar-warn' : 'res-bar-ok';
		return '<div class="res-bar-outer"><div class="res-bar ' + cls + '" style="width:' + pct + '%"></div></div>';
	}
	var html = '<div class="res-grid">';
	if (data.ram_total || data.cpu_model || data.kernel || data.os_label) {
		html += '<div class="res-item">'
			+ '<span class="res-label">ハードウェア</span>';
		if (data.ram_total) {
			html += '<span class="res-val">' + escapeHtml(data.ram_total) + ' RAM</span>';
		}
		if (data.cpu_model) {
			html += '<span class="res-sub">' + (data.cpu_cores ? escapeHtml(String(data.cpu_cores)) + ' x ' : '') + escapeHtml(data.cpu_model) + '</span>';
		}
		if (data.kernel || data.os_label) {
			html += '<span class="res-sub">GNU/Linux ' + escapeHtml(data.kernel || '') + (data.os_label ? ' ' + escapeHtml(data.os_label) : '') + '</span>';
		}
		html += '</div>';
	}
	// CPU
	html += '<div class="res-item">'
		+ '<span class="res-label">CPU</span>'
		+ '<span class="res-val">' + (data.cpu_pct || 0) + '%</span>'
		+ bar(cpuBar, 90, 70)
		+ '<span class="res-sub">Load: ' + (data.load1||0) + ' / ' + (data.load5||0) + ' / ' + (data.load15||0) + '</span>'
		+ '</div>';
	// メモリ
	html += '<div class="res-item">'
		+ '<span class="res-label">メモリ</span>'
		+ '<span class="res-val">' + memUsedMB + ' / ' + memTotalMB + ' MB (' + (data.mem_pct||0) + '%)</span>'
		+ bar(memBar, 90, 75)
		+ '</div>';
	// スワップ
	if (swapTotalMB > 0) {
		var swapBar = Math.min(100, Math.round(swapUsedMB / swapTotalMB * 100));
		html += '<div class="res-item">'
			+ '<span class="res-label">スワップ</span>'
			+ '<span class="res-val">' + swapUsedMB + ' / ' + swapTotalMB + ' MB</span>'
			+ bar(swapBar, 80, 50)
			+ '</div>';
	}
	// ディスク
	html += '<div class="res-item">'
		+ '<span class="res-label">ディスク (/)</span>'
		+ '<span class="res-val">' + escapeHtml(data.disk_used||'?') + ' / ' + escapeHtml(data.disk_total||'?') + ' (' + escapeHtml(data.disk_pct||'?') + ')</span>'
		+ bar(diskBar, 90, 75)
		+ '</div>';
	// ネットワーク
	if (data.net_iface) {
		html += '<div class="res-item">'
			+ '<span class="res-label">通信量 (' + escapeHtml(data.net_iface) + ')</span>'
			+ '<span class="res-val">↓ ' + escapeHtml(data.net_rx_human||'?') + ' ↑ ' + escapeHtml(data.net_tx_human||'?') + '</span>'
			+ '</div>';
	}
	// 稼働時間
	html += '<div class="res-item">'
		+ '<span class="res-label">稼働時間</span>'
		+ '<span class="res-val">' + escapeHtml(data.uptime||'?') + '</span>'
		+ '<span class="res-sub">起動: ' + escapeHtml(data.uptime_since||'?') + '</span>'
		+ '</div>';
	html += '</div>';
	// 非同期サブカード（SSL・NC容量・DB・Nginxトラフィック）のプレースホルダー
	html += '<div class="res-sub-cards">';
	html += '<div class="res-sub-card"><h3>SSL証明書</h3><div id="async-ssl" class="async-content section-loading"></div></div>';
	html += '<div class="res-sub-card"><h3>SSL自動更新</h3><div id="async-ssl-renew" class="async-content section-loading"></div></div>';
	html += '<div class="res-sub-card"><h3>NC・ログ容量</h3><div id="res-async-disk-detail" class="async-content section-loading"></div></div>';
	html += '<div class="res-sub-card"><h3>データベース</h3><div id="res-async-db" class="async-content section-loading"></div></div>';
	html += '<div class="res-sub-card"><h3>Nginxトラフィック</h3><div id="res-async-nginx" class="async-content section-loading"></div></div>';
	html += '</div>';
	html += '<p class="res-updated">更新: ' + escapeHtml(data.updated_at||'') + '</p>';
	content.innerHTML = html;
}

// ---- Fail2ban ----
function renderFail2ban(content, data) {
	var jails = data.jails || [];
	var flags = data.flags || {};
	var jailTooltips = data.jail_tooltips || {};

	// BANNED_IPS グローバルを更新（ipBadges で参照）
	jails.forEach(function(jail) {
		(jail.banned_ips || []).forEach(function(ip) {
			BANNED_IPS[ip] = jail.name;
		});
	});

	var html = '<div class="f2b-summary">合計 BAN 中: <strong>' + (data.ban_total || 0) + '</strong> IP</div>';

	// jail ステータスグリッド（クリックで BAN 詳細モーダルを開く）
	var manualBans = data.manual_bans || [];
	html += '<div class="jail-grid">';
	jails.forEach(function(jail) {
		var ips = jail.banned_ips || [];
		var hasBan = jail.ban_count > 0;
		html += '<div class="jail-box jail-clickable" data-jail="' + escapeHtml(jail.name) + '" style="cursor:pointer">';
		html += '<h3>' + escapeHtml(jail.name) + ' <span class="jail-active-badge">有効</span></h3>';
		html += '<div class="jail-stats">'
			+ '<span>BAN中: <strong class="' + (hasBan ? 'f2b-active-danger' : '') + '">' + jail.ban_count + '</strong></span>'
			+ '</div>';
		if (jailTooltips[jail.name]) {
			html += '<div class="jail-condition"><span class="jail-condition-label">BAN条件:</span> ' + escapeHtml(jailTooltips[jail.name]) + '</div>';
		}
		if (ips.length > 0) {
			html += '<div class="ip-list">';
			ips.slice(0, 3).forEach(function(ip) {
				var flag = flags[ip] || '';
				html += '<div class="f2b-ip-item">'
					+ (flag ? '<span class="f2b-flag">' + escapeHtml(flag.split(' ')[0]) + '</span> ' : '')
					+ "<span class=\"ip-clickable\" onclick=\"event.stopPropagation();openIpModal('" + escapeJsString(ip) + "')\">" + escapeHtml(ip) + '</span>'
					+ ipBadges(ip)
					+ '</div>';
			});
			if (ips.length > 3) {
				html += '<span class="f2b-more">+' + (ips.length - 3) + ' more</span>';
			}
			html += '</div>';
		}
		html += '<span class="jail-hover-hint">クリックで履歴を表示</span>';
		html += '</div>';
	});
	html += '</div>';

	// BANトレンド3グラフ
	if (data.ban_trend_7d || data.ban_trend_14d || data.ban_trend_4w) {
		html += '<div class="ban-trend-row">';

		function buildTrendChart(trendData, topData, title) {
			if (!trendData) return '';
			var keys = Object.keys(trendData);
			var values = keys.map(function(k) { return trendData[k]; });
			var trendMax = Math.max(1, Math.max.apply(null, values));
			var h = '<div class="ban-trend-child">';
			h += '<h3 class="ban-trend-title">' + escapeHtml(title) + '</h3>';
			h += '<div class="ban-chart">';
			keys.forEach(function(date) {
				var count = trendData[date];
				var topIps = (topData && topData[date]) || [];
				var barH = Math.round(count / trendMax * 100);
				var label = date.indexOf('-') >= 0 ? date.substring(5) : date;
				h += '<div class="chart-bar-wrap">';
				h += '<div class="chart-bar chart-bar-ban" style="height:' + barH + '%">';
				if (count > 0) h += '<span class="chart-val">' + count + '</span>';
				h += '</div>';
				if (count > 0 && topIps.length > 0) {
					h += '<div class="chart-bar-tooltip">';
					h += '<div class="tip-date">' + escapeHtml(date) + ': ' + count + ' BAN</div>';
					topIps.forEach(function(t) {
						var fl = flags[t.ip] || '';
						var flEmoji = fl ? fl.split(' ')[0] + ' ' : '';
						h += '<div class="tip-row">' + flEmoji + '<code>' + escapeHtml(t.ip) + '</code> <span class="tip-count">×' + t.count + '</span></div>';
					});
					h += '</div>';
				}
				h += '<span class="chart-label">' + escapeHtml(label) + '</span>';
				h += '</div>';
			});
			h += '</div></div>';
			return h;
		}

		html += buildTrendChart(data.ban_trend_7d,  data.ban_trend_top,      'BANトレンド (直近7日間)');
		html += buildTrendChart(data.ban_trend_14d, data.ban_trend_14d_top,  'BANトレンド (直近14日間)');
		html += buildTrendChart(data.ban_trend_4w,  data.ban_trend_4w_top,   'BANトレンド (1か月を週集計)');

		html += '</div>';
	}

	// BAN/UNBAN アクション
	html += '<div class="f2b-actions">'
		+ '<input type="text" id="f2b-ip-input" class="filter-input" placeholder="対象 IP" style="width:180px">'
		+ '<select id="f2b-jail-select" class="filter-select" style="width:160px">'
		+ '<option value="">-- jail --</option>';
	jails.forEach(function(j) {
		html += '<option value="' + escapeHtml(j.name) + '">' + escapeHtml(j.name) + '</option>';
	});
	html += '</select>'
		+ '<button class="btn-ban btn-sm" onclick="f2bAction(\'ban\')">BAN</button>'
		+ '<button class="btn-warning btn-sm" onclick="f2bAction(\'unban\')">UNBAN</button>'
		+ '</div>';
	html += '<p class="res-updated">更新: ' + escapeHtml(data.updated_at || '') + '</p>';

	content.innerHTML = html;

	// jail カードにクリックイベントを付与（openJailModal を呼ぶ）
	var jailMap = {};
	jails.forEach(function(j) { jailMap[j.name] = j; });
	content.querySelectorAll('.jail-box[data-jail]').forEach(function(box) {
		var jailName = box.getAttribute('data-jail');
		box.addEventListener('click', function() {
			openJailModal(jailName, jailMap[jailName], flags, manualBans);
		});
	});

	// BAN履歴ボタンをカードヘッダに統一配置
	initCardHeaderActions(content, {
		customButtons: [
			{
				label: 'BAN履歴',
				cls: 'btn-primary btn-sm f2b-banhistory-btn',
				group: 'list',
				selector: '.f2b-banhistory-btn',
				onclick: function() { openBanHistoryModal(); }
			}
		]
	});

}

function f2bAction(type) {
	var ip = document.getElementById('f2b-ip-input').value.trim();
	var jail = document.getElementById('f2b-jail-select').value;
	if (!ip) { alert('IPを入力してください'); return; }
	var params = new URLSearchParams({ ip: ip });
	if (jail) params.set('jail', jail);
	var api = type === 'ban' ? 'fail2ban_ban' : 'fail2ban_unban';
	fetch(monitorApiURL(api), {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
		body: params.toString()
	}).then(function(r) { return r.json(); })
	.then(function(d) {
		alert(d.message || (d.ok ? '完了' : '失敗'));
		var secFail2ban = getMonitorCardId('FAIL2BAN', 'sec-fail2ban');
		loadSection(getMonitorCardAPI(secFail2ban, 'fail2ban'), secFail2ban + '-content', renderFail2ban);
	}).catch(function(e) { alert('エラー: ' + e); });
}

// ========== 共通ヘルパー（jail モーダル / BAN履歴モーダル で使用） ==========

// 手動BANかどうかを判定（manual_bans 配列と fail2ban ログのタイムスタンプを ±60秒 で照合）
function isManualBan(ip, bannedAt, manualBans) {
	if (!manualBans || !bannedAt) return false;
	var f2bTs = new Date(bannedAt.replace(' ', 'T')).getTime();
	if (isNaN(f2bTs)) return false;
	for (var i = 0; i < manualBans.length; i++) {
		if (manualBans[i].ip === ip) {
			var mTs = new Date(manualBans[i].datetime.replace(' ', 'T')).getTime();
			if (!isNaN(mTs) && Math.abs(f2bTs - mTs) <= 60000) return true;
		}
	}
	return false;
}

// 既知IPをBANする際の確認（単体用）
function confirmBanKnown(ip) {
	if (typeof KNOWN_IPS !== 'undefined' && KNOWN_IPS[ip]) {
		return confirm(ip + ' は既知IP「' + KNOWN_IPS[ip] + '」として登録されています。\n本当にBANしますか？');
	}
	return true;
}

// 既知IPをBANする際の確認（一括BAN用）
function confirmBulkBanWithKnown(ips, baseMsg) {
	var knownLines = [];
	if (typeof KNOWN_IPS !== 'undefined') {
		ips.forEach(function(ip) {
			if (KNOWN_IPS[ip]) knownLines.push('  ' + ip + '（' + KNOWN_IPS[ip] + '）');
		});
	}
	var msg = baseMsg;
	if (knownLines.length > 0) {
		msg = '⚠ 以下の既知IPが含まれています:\n' + knownLines.join('\n') + '\n\n' + msg;
	}
	return confirm(msg);
}

// ========== fail2ban jail 詳細モーダル ==========

function openJailModal(jailName, jailInfo, flags, manualBans) {
	var modal = document.getElementById('jail-detail-modal');
	var title = document.getElementById('jail-modal-title');
	var body  = document.getElementById('jail-modal-body');
	var dlBtn = document.getElementById('jail-modal-download');
	if (!modal || !title || !body) return;

	title.textContent = jailName + ' — BAN履歴';
	manualBans = manualBans || [];

	// history 配列から全 BAN 履歴を構築（同一IPの複数回BANも個別表示）
	var allEntries = [];
	if (jailInfo && jailInfo.history && jailInfo.history.length > 0) {
		for (var i = 0; i < jailInfo.history.length; i++) {
			var h = jailInfo.history[i];
			allEntries.push({
				ip:          h.ip,
				status:      h.active ? 'active' : 'unbanned',
				banned_at:   h.banned_at  || '',
				unbanned_at: h.unbanned_at || ''
			});
		}
	}

	if (allEntries.length === 0) {
		body.innerHTML = '<p class="empty">BAN履歴はありません</p>';
	} else {
		var banCount  = jailInfo ? (jailInfo.ban_count  || 0) : 0;
		var html = '<p class="search-summary">BAN中: <strong>' + formatCount(banCount) + '</strong>　表示: <strong>' + formatCount(allEntries.length) + '</strong> 件</p>';
		html += '<table class="log-table"><thead><tr><th>#</th><th class="col-ip">IP</th><th>国</th><th>状態</th><th>種別</th><th>BAN日時</th><th>解除日時</th></tr></thead><tbody>';
		for (var i = 0; i < allEntries.length; i++) {
			var entry = allEntries[i];
			var flag  = (flags && flags[entry.ip]) || '';
			var statusBadge = entry.status === 'active'
				? '<span class="ban-status-active">BAN中</span>'
				: '<span class="ban-status-unbanned">解除済</span>';
			var sourceBadge = isManualBan(entry.ip, entry.banned_at, manualBans)
				? '<span class="ban-source-manual">手動</span>'
				: '<span class="ban-source-auto">自動</span>';
			html += '<tr class="' + (entry.status === 'unbanned' ? 'row-unbanned' : '') + '">'
				+ '<td>' + (i + 1) + '</td>'
				+ '<td class="col-ip"><code class="ip-clickable" onclick="closeJailModal();openIpModal(\'' + escapeJsString(entry.ip) + '\')">' + escapeHtml(entry.ip) + '</code></td>'
				+ '<td>' + escapeHtml(flag) + '</td>'
				+ '<td>' + statusBadge + '</td>'
				+ '<td>' + sourceBadge + '</td>'
				+ '<td>' + escapeHtml(entry.banned_at  || '-') + '</td>'
				+ '<td>' + escapeHtml(entry.unbanned_at || '-') + '</td>'
				+ '</tr>';
		}
		html += '</tbody></table>';
		body.innerHTML = html;
	}

	// ダウンロードボタン
	if (dlBtn) {
		dlBtn.onclick = function() {
			var lines = [jailName + ' BAN履歴', 'Generated: ' + new Date().toLocaleString('ja-JP'), '---'];
			lines.push('BAN中: ' + (jailInfo ? jailInfo.ban_count : 0));
			lines.push('');
			for (var i = 0; i < allEntries.length; i++) {
				var e = allEntries[i];
				var statusLabel = e.status === 'active'
					? '[BAN中 ' + e.banned_at + ']'
					: '[解除済 ' + e.banned_at + ' → ' + e.unbanned_at + ']';
				lines.push((i + 1) + '. ' + e.ip + ' ' + statusLabel);
			}
			if (allEntries.length === 0) lines.push('(BAN履歴なし)');
			var blob = new Blob([lines.join('\n')], { type: 'text/plain' });
			var a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = jailName + '_ban_history.txt';
			a.click();
			URL.revokeObjectURL(a.href);
		};
	}

	modal.style.display = 'flex';
}

function closeJailModal() {
	var modal = document.getElementById('jail-detail-modal');
	if (modal) modal.style.display = 'none';
}

// ========== BAN履歴モーダル ==========

function openBanHistoryModal() {
	var modal = document.getElementById('ban-history-modal');
	var title = document.getElementById('ban-history-title');
	var body  = document.getElementById('ban-history-body');
	var dlBtn = document.getElementById('ban-history-download');
	if (!modal || !title || !body) return;

	body.innerHTML = '<p class="section-loading">読み込み中...</p>';
	modal.style.display = 'flex';

	fetch(monitorApiURL('ban_history'))
		.then(function(r) { return r.json(); })
		.then(function(data) {
			var history    = data.history    || [];
			var flags      = data.flags      || {};
			var manualBans = data.manual_bans || [];

			title.textContent = 'BAN履歴 (' + formatCount(history.length) + '件)';

			var html = '';
			// BAN追加フォーム
			html += '<div class="ban-list-add-form">';
			html += '<input type="text" id="ban-history-ip-input" placeholder="203.0.113.100" pattern="\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}">';
			html += '<button class="btn-danger btn-sm" id="ban-history-add-btn">BAN追加</button>';
			html += '<input type="text" id="ban-history-search" placeholder="IP検索..." class="ban-list-search-input">';
			html += '<select id="ban-history-jail-filter" class="ban-list-jail-filter"><option value="">全てのJail</option><option value="nextcloud">nextcloud</option><option value="nginx-suspicious">nginx-suspicious</option><option value="nginx-basic-auth">nginx-basic-auth</option><option value="recidive">recidive</option></select>';
			html += '<span id="ban-history-msg" class="ban-list-msg"></span>';
			html += '</div>';

			if (history.length === 0) {
				html += '<p class="empty">BAN履歴はありません</p>';
			} else {
				html += '<div class="ban-list-actions-bar">';
				html += '<label class="ban-list-select-all"><input type="checkbox" id="ban-history-select-all"> すべて選択</label>';
				html += '<button class="btn-danger btn-sm btn-bulk-unban" id="ban-history-bulk-ban" disabled>選択したIPを一括BAN</button>';
				html += '</div>';
				html += '<div class="ban-list-table-wrap">';
				html += '<table class="ban-list-table log-table"><thead><tr><th style="width:30px;"></th><th>#</th><th class="col-ip">IP</th><th>国</th><th>Jail</th><th>種別</th><th>BAN日時</th><th style="width:60px;"></th></tr></thead><tbody>';
				for (var i = 0; i < history.length; i++) {
					var item  = history[i];
					var ip    = item.ip;
					var wl    = isWhitelisted(ip);
					var currentlyBanned = !!BANNED_IPS[ip];
					var jailClass = 'jail-tag jail-tag-' + item.jail.replace('nginx-', 'ng-');
					var jailTag = '<span class="' + jailClass + '">' + escapeHtml(item.jail) + '</span>';
					var flagHtml = flags[ip] || '';

					// BAN日時フォーマット（YYYY/MM/DD HH:MM）
					var bannedAtStr = '-';
					if (item.datetime) {
						var bd = new Date(item.datetime.replace(' ', 'T'));
						if (!isNaN(bd.getTime())) {
							bannedAtStr = bd.getFullYear() + '/' + ('0' + (bd.getMonth() + 1)).slice(-2) + '/' + ('0' + bd.getDate()).slice(-2)
								+ ' ' + ('0' + bd.getHours()).slice(-2) + ':' + ('0' + bd.getMinutes()).slice(-2);
						}
					}

					var sourceBadge = isManualBan(ip, item.datetime, manualBans)
						? '<span class="ban-source-manual">手動</span>'
						: '<span class="ban-source-auto">自動</span>';

					var statusHtml, actionHtml = '', isUnbanned = false;
					if (wl) {
						statusHtml = '<span class="wl-badge">WL</span>';
					} else if (currentlyBanned) {
						statusHtml = '<span class="ban-badge">BAN中</span>';
					} else {
						isUnbanned = true;
						statusHtml = '<span class="unban-badge">解除済</span>';
						actionHtml = '<button class="btn-danger btn-sm ban-history-ban-btn" data-ip="' + escapeHtml(ip) + '">BAN追加</button>';
					}

					var cbDisabled = (wl || currentlyBanned) ? ' disabled title="' + (wl ? 'ホワイトリストIP' : 'BAN中') + '"' : '';
					var rowClass = isUnbanned ? ' class="is-unbanned"' : '';
					html += '<tr' + rowClass + ' data-ip="' + escapeHtml(ip) + '" data-jail="' + escapeHtml(item.jail) + '">';
					html += '<td><input type="checkbox" class="ban-history-cb" value="' + escapeHtml(ip) + '"' + cbDisabled + '></td>';
					html += '<td>' + (i + 1) + '</td>';
					html += "<td class=\"col-ip\"><code class=\"ip-clickable\" onclick=\"closeBanHistoryModal();openIpModal('" + escapeJsString(ip) + "')\">" + escapeHtml(ip) + '</code>' + ipBadges(ip) + '</td>';
					html += '<td>' + escapeHtml(flagHtml) + '</td>';
					html += '<td>' + jailTag + '</td>';
					html += '<td>' + sourceBadge + '</td>';
					html += '<td class="ban-list-date">' + bannedAtStr + '</td>';
					html += '<td>' + statusHtml + '</td>';
					html += '<td>' + actionHtml + '</td>';
					html += '</tr>';
				}
				html += '</tbody></table>';
				html += '</div>';
			}
			body.innerHTML = html;

			// イベント設定
			setupBanHistoryEvents(data);
		})
		.catch(function(err) {
			body.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escapeHtml(String(err)) + '</p>';
		});

	// ダウンロードボタン
	if (dlBtn) {
		dlBtn.onclick = function() {
			var rows = document.querySelectorAll('#ban-history-body .ban-list-table tbody tr');
			var lines = ['BAN履歴', 'Generated: ' + new Date().toLocaleString('ja-JP'), '---', ''];
			for (var i = 0; i < rows.length; i++) {
				var ip = rows[i].getAttribute('data-ip');
				var jailCells = rows[i].querySelectorAll('.jail-tag');
				var jails = [];
				for (var j = 0; j < jailCells.length; j++) jails.push(jailCells[j].textContent);
				var dateCell = rows[i].querySelector('.ban-list-date');
				var banDate = dateCell ? dateCell.textContent.trim() : '-';
				lines.push((i + 1) + '. ' + ip + '  [' + jails.join(', ') + ']  BAN: ' + banDate);
			}
			var blob = new Blob([lines.join('\n')], { type: 'text/plain' });
			var a = document.createElement('a');
			a.href = URL.createObjectURL(blob);
			a.download = 'ban_history.txt';
			a.click();
			URL.revokeObjectURL(a.href);
		};
	}
}

function setupBanHistoryEvents(data) {
	// BAN追加ボタン
	var addBtn   = document.getElementById('ban-history-add-btn');
	var addInput = document.getElementById('ban-history-ip-input');
	var msg      = document.getElementById('ban-history-msg');
	if (addBtn) {
		addBtn.addEventListener('click', function() {
			var ip = addInput.value.trim();
			if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
				msg.textContent = '有効なIPアドレスを入力してください';
				msg.className = 'ban-list-msg error';
				return;
			}
			if (isWhitelisted(ip)) {
				msg.textContent = 'ホワイトリストIPのためBANできません';
				msg.className = 'ban-list-msg error';
				return;
			}
			if (!confirmBanKnown(ip)) return;
			addBtn.disabled = true;
			msg.textContent = '処理中...';
			msg.className = 'ban-list-msg';
			var params = new URLSearchParams({ ip: ip });
			fetch(monitorApiURL('fail2ban_ban'), {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
				body: params.toString()
			})
			.then(function(r) { return r.json(); })
			.then(function(res) {
				msg.textContent = res.message || (res.ok ? '完了' : '失敗');
				msg.className = 'ban-list-msg ' + (res.ok ? 'success' : 'error');
				addBtn.disabled = false;
				addInput.value = '';
				if (res.ok) {
					if (ip && window.BANNED_IPS) window.BANNED_IPS[ip] = 'recidive';
					setTimeout(function() { openBanHistoryModal(); }, 800);
					var secFail2ban = getMonitorCardId('FAIL2BAN', 'sec-fail2ban');
					loadSection(getMonitorCardAPI(secFail2ban, 'fail2ban'), secFail2ban + '-content', renderFail2ban);
				}
			})
			.catch(function() {
				msg.textContent = 'エラーが発生しました';
				msg.className = 'ban-list-msg error';
				addBtn.disabled = false;
			});
		});
	}

	// 個別BANボタン
	var banBtns = document.querySelectorAll('.ban-history-ban-btn');
	for (var i = 0; i < banBtns.length; i++) {
		(function(btn) {
			btn.addEventListener('click', function() {
				var ip = btn.getAttribute('data-ip');
				if (!confirmBanKnown(ip)) return;
				btn.disabled = true;
				btn.textContent = '...';
				var params = new URLSearchParams({ ip: ip });
				fetch(monitorApiURL('fail2ban_ban'), {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: params.toString()
				})
				.then(function(r) { return r.json(); })
				.then(function(res) {
					if (res.ok) {
						btn.textContent = '済';
						var row = btn.closest('tr');
						if (row) row.style.opacity = '0.3';
						if (ip && window.BANNED_IPS) window.BANNED_IPS[ip] = 'recidive';
						var secFail2ban = getMonitorCardId('FAIL2BAN', 'sec-fail2ban');
						loadSection(getMonitorCardAPI(secFail2ban, 'fail2ban'), secFail2ban + '-content', renderFail2ban);
					} else {
						btn.textContent = 'BAN';
						btn.disabled = false;
						alert(res.message || '失敗');
					}
				})
				.catch(function() {
					btn.textContent = 'BAN';
					btn.disabled = false;
				});
			});
		})(banBtns[i]);
	}

	// フィルタイベント
	var searchInput = document.getElementById('ban-history-search');
	if (searchInput) searchInput.addEventListener('input', function() { applyBanHistoryFilter(); });
	var jailFilter = document.getElementById('ban-history-jail-filter');
	if (jailFilter) jailFilter.addEventListener('change', function() { applyBanHistoryFilter(); });

	// 全選択チェックボックス
	var selectAll = document.getElementById('ban-history-select-all');
	if (selectAll) {
		selectAll.addEventListener('change', function() {
			var cbs = document.querySelectorAll('.ban-history-cb:not(:disabled)');
			for (var i = 0; i < cbs.length; i++) {
				var row = cbs[i].closest('tr');
				if (row && row.style.display !== 'none') cbs[i].checked = selectAll.checked;
			}
			updateBulkBanBtn();
		});
	}

	// 個別チェックボックスの変更を監視
	var bodyEl = document.getElementById('ban-history-body');
	if (bodyEl) {
		bodyEl.addEventListener('change', function(e) {
			if (e.target.classList.contains('ban-history-cb')) updateBulkBanBtn();
		});
	}

	// 一括BANボタン
	var bulkBtn = document.getElementById('ban-history-bulk-ban');
	if (bulkBtn) {
		bulkBtn.addEventListener('click', function() {
			var checked = document.querySelectorAll('.ban-history-cb:checked');
			var ips = [];
			for (var i = 0; i < checked.length; i++) {
				var row = checked[i].closest('tr');
				if (row && row.style.display !== 'none') ips.push(checked[i].value);
			}
			if (ips.length === 0) return;
			if (!confirmBulkBanWithKnown(ips, formatCount(ips.length) + '件のIPをBANしますか？')) return;
			bulkBtn.disabled = true;
			bulkBtn.textContent = '処理中...';
			var promises = ips.map(function(ip) {
				var params = new URLSearchParams({ ip: ip });
				return fetch(monitorApiURL('fail2ban_ban'), {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: params.toString()
				}).then(function(r) { return r.json(); });
			});
			Promise.all(promises).then(function(results) {
				var successCount = results.filter(function(r) { return r.ok; }).length;
				results.forEach(function(res, idx) {
					if (res.ok && window.BANNED_IPS) window.BANNED_IPS[ips[idx]] = 'recidive';
				});
				alert(formatCount(successCount) + '件をBANしました');
				openBanHistoryModal();
				var secFail2ban = getMonitorCardId('FAIL2BAN', 'sec-fail2ban');
				loadSection(getMonitorCardAPI(secFail2ban, 'fail2ban'), secFail2ban + '-content', renderFail2ban);
			}).catch(function() {
				alert('エラーが発生しました');
				bulkBtn.disabled = false;
				bulkBtn.textContent = '選択したIPを一括BAN';
			});
		});
	}
}

function applyBanHistoryFilter() {
	var searchVal = (document.getElementById('ban-history-search') && document.getElementById('ban-history-search').value || '').trim().toLowerCase();
	var jailVal   = document.getElementById('ban-history-jail-filter') ? document.getElementById('ban-history-jail-filter').value : '';
	var rows      = document.querySelectorAll('#ban-history-body .ban-list-table tbody tr');
	var totalCount = rows.length, visibleCount = 0;

	for (var i = 0; i < rows.length; i++) {
		var row  = rows[i];
		var ip   = (row.getAttribute('data-ip') || '').toLowerCase();
		var jail = row.getAttribute('data-jail') || '';
		var matchIp   = !searchVal || ip.indexOf(searchVal) !== -1;
		var matchJail = !jailVal  || jail === jailVal;
		if (matchIp && matchJail) {
			row.style.display = '';
			visibleCount++;
		} else {
			row.style.display = 'none';
		}
	}

	var title = document.getElementById('ban-history-title');
	if (title) {
		title.textContent = (searchVal || jailVal)
			? 'BAN履歴 (' + formatCount(visibleCount) + '件 / ' + formatCount(totalCount) + '件中)'
			: 'BAN履歴 (' + formatCount(totalCount) + '件)';
	}

	var selectAll = document.getElementById('ban-history-select-all');
	if (selectAll) selectAll.checked = false;
	updateBulkBanBtn();
}

function updateBulkBanBtn() {
	var checked = document.querySelectorAll('.ban-history-cb:checked');
	var visibleChecked = 0;
	for (var i = 0; i < checked.length; i++) {
		var row = checked[i].closest('tr');
		if (row && row.style.display !== 'none') visibleChecked++;
	}
	var bulkBtn = document.getElementById('ban-history-bulk-ban');
	if (bulkBtn) {
		bulkBtn.disabled = visibleChecked === 0;
		bulkBtn.textContent = visibleChecked > 0
			? formatCount(visibleChecked) + '件を一括BAN'
			: '選択したIPを一括BAN';
	}
}

function closeBanHistoryModal() {
	var modal = document.getElementById('ban-history-modal');
	if (modal) modal.style.display = 'none';
}


// ---- SSH Chart (時間帯別) ----
function buildSSHHourlyChart(hourly) {
	if (!hourly || hourly.length !== 24) return '<p style="color:#555">データなし</p>';
	var maxVal = Math.max.apply(null, Array.prototype.slice.call(hourly).concat([1]));
	var html = '<div class="ssh-chart">';
	for (var h = 0; h < 24; h++) {
		var cnt = hourly[h] || 0;
		var pct = Math.round(cnt / maxVal * 100);
		var label = ('0' + h).slice(-2);
		html += '<div class="ssh-chart-col" title="' + label + ':00 — ' + cnt + '件">'
			+ '<div class="ssh-chart-bar" style="height:' + Math.max(2, pct) + '%">'
			+ (cnt > 0 ? '<span class="ssh-chart-val">' + cnt + '</span>' : '')
			+ '</div>'
			+ '<span class="ssh-chart-label">' + label + '</span>'
			+ '</div>';
	}
	html += '</div>';
	return html;
}

function sshChartTab(btn) {
	var container = btn.closest('[data-ssh-chart-root]');
	if (!container) return;
	container.querySelectorAll('.ssh-chart-tab').forEach(function(t) { t.classList.remove('ssh-chart-tab-active'); });
	btn.classList.add('ssh-chart-tab-active');
	var view = btn.getAttribute('data-view');
	container.querySelectorAll('[data-ssh-chart-panel]').forEach(function(p) {
		p.style.display = (p.getAttribute('data-ssh-chart-panel') === view) ? '' : 'none';
	});
}

function renderSSHChart(content, data) {
	var h24 = data.hourly_attacks    || [];
	var h7d = data.hourly_attacks_7d || [];
	var html = '<div data-ssh-chart-root>';
	html += '<div class="ssh-chart-tabs">'
		+ '<button class="ssh-chart-tab ssh-chart-tab-active" data-view="h24" onclick="sshChartTab(this)">直近24時間</button>'
		+ '<button class="ssh-chart-tab" data-view="h7d" onclick="sshChartTab(this)">直近7日</button>'
		+ '</div>';
	html += '<div data-ssh-chart-panel="h24">' + buildSSHHourlyChart(h24) + '</div>';
	html += '<div data-ssh-chart-panel="h7d" style="display:none">' + buildSSHHourlyChart(h7d) + '</div>';
	html += '</div>';
	html += '<p class="res-updated">更新: ' + escapeHtml(data.updated_at||'') + '</p>';
	content.innerHTML = html;
}

// ---- IP Management ----
function renderIPMgmt(content, data) {
	var ips = data.ips || [];
	var html = '<div class="ip-mgmt-section">';

	// サマリー
	html += '<div class="ipm-summary">'
		+ escapeHtml(window.ipTypeShortLabel('wlm')) + ': <strong>' + (data.total_wlm||0) + '</strong>件 / '
		+ escapeHtml(window.ipTypeShortLabel('wla')) + ': <strong>' + (data.total_wla||0) + '</strong>件 / '
		+ escapeHtml(window.ipTypeShortLabel('known')) + ': <strong>' + (data.total_known||0) + '</strong>件 / '
		+ escapeHtml(window.ipTypeShortLabel('wl')) + ': <strong>' + (data.total_wl||0) + '</strong>件'
		+ '</div>';

	// IP 追加フォーム（WL/WLM/WLA/既知）
	html += '<h4 class="ipm-section-title">許可IP 追加</h4>';
	html += '<div class="action-form ip-mgmt-add-form">'
		+ '<input type="text" id="ip-mgmt-add-ip" class="filter-input" placeholder="例: 203.0.113.1" style="width:140px" autocomplete="off">'
		+ '<input type="text" id="ip-mgmt-add-name" class="filter-input" placeholder="名前" style="width:110px" autocomplete="off">'
		+ '<select id="ip-mgmt-add-type" class="filter-select">'
		+ '<option value="wl">' + escapeHtml(window.ipTypeFullLabel('wl')) + '</option>'
		+ '<option value="wla">' + escapeHtml(window.ipTypeFullLabel('wla')) + '</option>'
		+ '<option value="wlm">' + escapeHtml(window.ipTypeFullLabel('wlm')) + '</option>'
		+ '<option value="known">' + escapeHtml(window.ipTypeFullLabel('known')) + '</option>'
		+ '</select>'
		+ '<input type="password" id="ip-mgmt-pin" class="filter-input" placeholder="PIN（4桁）" maxlength="4" style="width:5.5em" autocomplete="new-password">'
		+ '<button type="button" class="btn-primary btn-sm" id="ip-mgmt-add-btn">追加</button>'
		+ '</div>';

	if (ips.length === 0) {
		html += '<p style="padding:8px 0;color:#777">登録なし</p>';
	} else {
		// カラム: IP | 種別 | 名前 | NC状態 | BF試行 | 直近アクセス | 更新者 | 更新日 | (削除)
		html += '<table class="log-table">'
			+ '<thead>'
			// フィルター行
			+ '<tr class="thead-filter-row">'
			+ '<th>' + buildIpFilterCell({wl:true, wlm:true, wla:true, ban:true, known:true}) + '<span class="filter-count"></span></th>'
			+ '<th><select class="filter-select" data-filter="type"><option value="">全種別</option><option value="wl">' + escapeHtml(window.ipTypeShortLabel('wl')) + '</option><option value="wlm">' + escapeHtml(window.ipTypeShortLabel('wlm')) + '</option><option value="wla">' + escapeHtml(window.ipTypeShortLabel('wla')) + '</option><option value="known">' + escapeHtml(window.ipTypeShortLabel('known')) + '</option></select></th>'
			+ '<th><input type="text" class="filter-input" data-filter="name" placeholder="名前絞り込み"></th>'
			+ '<th></th><th></th><th></th><th></th><th></th><th></th>'
			+ '</tr>'
			// カラムヘッダー行
			+ '<tr><th>IP</th><th>種別</th><th>名前</th><th>NC状態</th><th>BF試行</th><th>直近アクセス</th><th>更新者</th><th>更新日</th><th></th></tr>'
			+ '</thead><tbody>';

		for (var i = 0; i < ips.length; i++) {
			var ip = ips[i];
			var isProtected = (ip.admin_protected === true); // サーバーが保護対象管理者と判定した行（admin_protect_names）
			var isWl = (ip.type === 'wl' || ip.type === 'wlm' || ip.type === 'wla' || ip.type === 'known');

			// 種別バッジ（保護対象管理者以外はクリックで変更可）
			var typeCls = ip.type === 'wl' ? 'wl-badge' : ip.type === 'wlm' ? 'wlm-badge' : ip.type === 'wla' ? 'wla-badge' : 'known-badge';
			var typeLabel = window.ipTypeShortLabel(ip.type);
			var editableCls = isProtected ? '' : ' ip-mgmt-type-editable';
			var typeBadge = '<span class="' + typeCls + editableCls + '">' + typeLabel + '</span>';

			// NC状態バッジ
			var ncBadge;
			if (isWl) {
				ncBadge = ip.nc_registered
					? '<span class="result-badge result-success">登録済み</span>'
					: '<span class="result-badge result-warning">未登録</span>';
			} else {
				ncBadge = '<span class="nc-na">—</span>';
			}

			// BF試行
			var bfText = isWl ? (ip.bf_attempts || 0) + '回' : '—';

			// 名前（保護対象管理者以外はクリックで変更可）
			var nameCls = isProtected ? '' : ' ip-mgmt-name-editable';
			var nameHtml = '<td class="ip-mgmt-name-col"><strong class="' + nameCls.trim() + '">' + escapeHtml(ip.name||'') + '</strong></td>';

			// 削除ボタン（保護対象管理者は削除不可、WLMはwlm-del-btnクラス追加）
			var delBtn = '';
			if (!isProtected) {
				var delCls = 'btn-danger btn-sm ip-mgmt-del-btn' + (ip.type === 'wlm' ? ' wlm-del-btn' : '');
				delBtn = '<button type="button" class="' + delCls + '" data-ip="' + escapeHtml(ip.ip) + '" data-name="' + escapeHtml(ip.name||'') + '" data-type="' + escapeHtml(ip.type) + '" title="削除">削除</button>';
			}

			html += '<tr data-ip="' + escapeHtml(ip.ip) + '" data-name="' + escapeHtml(ip.name||'') + '" data-type="' + escapeHtml(ip.type) + '"'
				+ (ip.type === 'known' ? ' data-known="1"' : '')
				+ ' data-wl="' + (isWl ? '1' : '0') + '"'
				+ ' data-banned="0"'
				+ '>'
				+ '<td><code class="ip-clickable" data-no-auto-badge="1" onclick="openIpModal(\'' + escapeJsString(ip.ip) + '\')">' + escapeHtml(ip.ip) + '</code></td>'
				+ '<td style="position:relative">' + typeBadge + '</td>'
				+ nameHtml
				+ '<td class="nowrap">' + ncBadge + '</td>'
				+ '<td class="col-count">' + escapeHtml(bfText) + '</td>'
				+ '<td class="nowrap datetime-cell">' + escapeHtml(ip.last_access || '—') + '</td>'
				+ '<td class="nowrap ip-mgmt-updated-by" title="' + escapeHtml(ip.updated_by||'') + '">' + escapeHtml(ip.updated_by || '—') + '</td>'
				+ '<td class="nowrap datetime-cell ip-mgmt-updated-at">' + escapeHtml(ip.updated_at_display || ip.updated_at || '—') + '</td>'
				+ '<td class="nowrap">' + delBtn + '</td>'
				+ '</tr>';
		}
		html += '</tbody></table>';
	}

	html += '<p class="res-updated">更新: ' + escapeHtml(data.updated_at||'') + '</p>';
	html += '</div>'; // .ip-mgmt-section

	content.innerHTML = html;
	applyNoPasswordManagerAttrs(content);

	// イベント委譲セットアップ
	ipmInitEvents(content, data);

	// 件数バッジ・ヘッダーアクション初期化
	autoInitCardFromDataset(content.closest('section.card'), { total: ips.length });

	// テーブルフィルター初期化
	if (typeof initTableFilter === 'function') {
		var table = content.querySelector('table.log-table');
		if (table) initTableFilter(table);
	}

	// 種別セレクトでPINの活性/非活性切替（WLMのみ必須、WLA/既知は不要）
	var typeSelect = content.querySelector('#ip-mgmt-add-type');
	var pinInput   = content.querySelector('#ip-mgmt-pin');
	var ipInput    = content.querySelector('#ip-mgmt-add-ip');
	var addBtn     = content.querySelector('#ip-mgmt-add-btn');
	var registeredIPs = {};
	for (var j = 0; j < ips.length; j++) {
		var normalizedIp = window.__heartdeskNormalizeIP(ips[j] && ips[j].ip);
		if (normalizedIp) registeredIPs[normalizedIp] = true;
	}
	function updatePinState() {
		var isWlm = typeSelect.value === 'wlm';
		pinInput.disabled = !isWlm;
		if (!isWlm) { pinInput.value = ''; pinInput.placeholder = '入力不要'; }
		else { pinInput.placeholder = 'PIN（4桁）'; }
	}
	function updateAddButtonState() {
		if (!ipInput || !addBtn) return;
		var normalizedInput = window.__heartdeskNormalizeIP(ipInput.value);
		var isDuplicate = !!(normalizedInput && registeredIPs[normalizedInput]);
		addBtn.disabled = isDuplicate;
		addBtn.title = isDuplicate ? 'このIPは既に登録されています' : '';
	}
	if (typeSelect && pinInput) {
		typeSelect.addEventListener('change', updatePinState);
		updatePinState();
	}
	if (ipInput) {
		ipInput.addEventListener('input', updateAddButtonState);
		ipInput.addEventListener('change', updateAddButtonState);
	}
	updateAddButtonState();
}

// ipmInitEvents は IP 管理カードのコンテンツ内にイベント委譲を設定する
function ipmInitEvents(container, data) {
	container.addEventListener('click', function(e) {
		// 名前インライン編集
		var nameEl = e.target.closest && e.target.closest('.ip-mgmt-name-editable');
		if (nameEl && !nameEl.querySelector('input')) {
			var row = nameEl.closest('tr');
			if (!row) return;
			var ip = row.getAttribute('data-ip');
			var currentName = row.getAttribute('data-name');
			var input = document.createElement('input');
			input.type = 'text';
			input.value = currentName;
			input.className = 'filter-input ip-mgmt-inline-input';
			input.style.width = '100%';
			applyNoPasswordManagerAttrs(input);
			nameEl.textContent = '';
			nameEl.appendChild(input);
			input.focus();
			input.select();
			var committed = false;
			function commitRename() {
				if (committed) return;
				committed = true;
				var newName = input.value.trim();
				if (!newName || newName === currentName) {
					nameEl.textContent = currentName;
					return;
				}
				nameEl.textContent = newName + ' ...';
				var params = new URLSearchParams({ ip: ip, name: newName });
				fetch(monitorApiURL('ip_rename'), {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
					body: params.toString()
				}).then(function(r) { return r.json(); })
				.then(function(d) {
					if (d.ok) {
						nameEl.textContent = newName;
						row.setAttribute('data-name', newName);
						var delBtn = row.querySelector('.ip-mgmt-del-btn');
						if (delBtn) delBtn.setAttribute('data-name', newName);
						if (d.updated_by) {
							var ubCell = row.querySelector('.ip-mgmt-updated-by');
							if (ubCell) { ubCell.textContent = d.updated_by; ubCell.title = d.updated_by; }
						}
						if (d.updated_at_display || d.updated_at) {
							var uaCell = row.querySelector('.ip-mgmt-updated-at');
							if (uaCell) uaCell.textContent = d.updated_at_display || d.updated_at;
						}
					} else {
						nameEl.textContent = currentName;
						alert(d.message || '名前変更に失敗しました');
					}
				}).catch(function() { nameEl.textContent = currentName; });
			}
			input.addEventListener('blur', commitRename);
			input.addEventListener('keydown', function(ev) {
				if (ev.key === 'Enter') { ev.preventDefault(); input.blur(); }
				if (ev.key === 'Escape') { committed = true; nameEl.textContent = currentName; }
			});
			return;
		}

		// 種別変更（バッジクリック → ドロップダウンメニュー）
		var typeEl = e.target.closest && e.target.closest('.ip-mgmt-type-editable');
		if (typeEl) {
			var existing = document.querySelector('.ip-mgmt-type-menu');
			if (existing) {
				var wasInSameTd = existing.parentNode === typeEl.parentNode;
				existing.remove();
				if (wasInSameTd) return;
			}
			var row = typeEl.closest('tr');
			if (!row) return;
			var ip = row.getAttribute('data-ip');
			var currentType = row.getAttribute('data-type');
			var td = typeEl.parentNode;
			var menu = document.createElement('div');
			menu.className = 'ip-mgmt-type-menu';
			var items = [
				{ value: 'wl', label: window.ipTypeShortLabel('wl'), cls: 'wl-badge' },
				{ value: 'wlm', label: window.ipTypeShortLabel('wlm'), cls: 'wlm-badge' },
				{ value: 'wla', label: window.ipTypeShortLabel('wla'), cls: 'wla-badge' },
				{ value: 'known', label: window.ipTypeShortLabel('known'), cls: 'known-badge' }
			];
			items.forEach(function(item) {
				if (item.value === currentType) return;
				var btn = document.createElement('button');
				btn.type = 'button';
				btn.className = 'ip-mgmt-type-menu-item';
				btn.innerHTML = '<span class="' + item.cls + '" style="margin-left:0">' + item.label + '</span>';
				btn.addEventListener('click', function(ev) {
					ev.stopPropagation();
					menu.remove();
					var newType = item.value;
					var pin = '';
					if (newType === 'wlm' || currentType === 'wlm') {
						pin = prompt(window.ipTypeShortLabel('wlm') + '操作にはPINが必要です（4桁）:');
						if (pin === null) return;
					}
					td.innerHTML = '<span style="color:#888;font-size:0.75rem">変更中...</span>';
					var params = new URLSearchParams({ ip: ip, type: newType, pin: pin });
					fetch(monitorApiURL('ip_changetype'), {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
						body: params.toString()
					}).then(function(r) { return r.json(); })
					.then(function(d) {
						if (d.ok) {
							var cls2 = newType === 'wl' ? 'wl-badge' : newType === 'wlm' ? 'wlm-badge' : newType === 'wla' ? 'wla-badge' : 'known-badge';
							var lbl2 = window.ipTypeShortLabel(newType);
							td.style.position = 'relative';
							td.innerHTML = '<span class="' + cls2 + ' ip-mgmt-type-editable">' + lbl2 + '</span>';
							row.setAttribute('data-type', newType);
							if (newType === 'known') row.setAttribute('data-known', '1');
							else row.removeAttribute('data-known');
							row.setAttribute('data-wl', (newType === 'wl' || newType === 'wlm' || newType === 'wla' || newType === 'known') ? '1' : '0');
							var delBtn = row.querySelector('.ip-mgmt-del-btn');
							if (delBtn) {
								delBtn.setAttribute('data-type', newType);
								if (newType === 'wlm') delBtn.classList.add('wlm-del-btn');
								else delBtn.classList.remove('wlm-del-btn');
							}
							if (d.updated_by) {
								var ubCell = row.querySelector('.ip-mgmt-updated-by');
								if (ubCell) { ubCell.textContent = d.updated_by; ubCell.title = d.updated_by; }
							}
							if (d.updated_at_display || d.updated_at) {
								var uaCell = row.querySelector('.ip-mgmt-updated-at');
								if (uaCell) uaCell.textContent = d.updated_at_display || d.updated_at;
							}
						} else {
							var cls3 = currentType === 'wl' ? 'wl-badge' : currentType === 'wlm' ? 'wlm-badge' : currentType === 'wla' ? 'wla-badge' : 'known-badge';
							var lbl3 = window.ipTypeShortLabel(currentType);
							td.style.position = 'relative';
							td.innerHTML = '<span class="' + cls3 + ' ip-mgmt-type-editable">' + lbl3 + '</span>';
							alert(d.message || '種別変更に失敗しました');
						}
					}).catch(function() {
						var cls3 = currentType === 'wl' ? 'wl-badge' : currentType === 'wlm' ? 'wlm-badge' : currentType === 'wla' ? 'wla-badge' : 'known-badge';
						var lbl3 = window.ipTypeShortLabel(currentType);
						td.style.position = 'relative';
						td.innerHTML = '<span class="' + cls3 + ' ip-mgmt-type-editable">' + lbl3 + '</span>';
					});
				});
				menu.appendChild(btn);
			});
			td.appendChild(menu);
			setTimeout(function() {
				document.addEventListener('click', function closeMenu(ev) {
					if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('click', closeMenu); }
				});
			}, 0);
			return;
		}

		// 削除ボタン
		var delBtn = e.target.closest && e.target.closest('button.ip-mgmt-del-btn');
		if (delBtn) {
			var ip   = delBtn.getAttribute('data-ip');
			var name = delBtn.getAttribute('data-name') || ip;
			var isWlm = delBtn.classList.contains('wlm-del-btn');
			var row = delBtn.closest('tr');
			if (isWlm) {
				if (!confirm(name + ' (' + window.ipTypeShortLabel('wlm') + ') を削除しますか？\nSSHアクセスも削除されます。')) return;
				var pin = prompt(window.ipTypeShortLabel('wlm') + '削除にはPINが必要です（4桁）:');
				if (pin === null) return;
				ipmDoRemove(ip, pin, row);
			} else {
				if (!confirm(name + ' を削除しますか？')) return;
				ipmDoRemove(ip, '', row);
			}
			return;
		}

		// 追加ボタン
		if (e.target.id === 'ip-mgmt-add-btn' || (e.target.closest && e.target.closest('#ip-mgmt-add-btn'))) {
			var ipVal   = (container.querySelector('#ip-mgmt-add-ip')   || {}).value || '';
			var nameVal = (container.querySelector('#ip-mgmt-add-name') || {}).value || '';
			var typeVal = (container.querySelector('#ip-mgmt-add-type') || {}).value || 'wla';
			var pinVal  = (container.querySelector('#ip-mgmt-pin')      || {}).value || '';
			ipVal = ipVal.trim(); nameVal = nameVal.trim(); pinVal = pinVal.trim();
			if (!ipVal || !nameVal) { alert('IPアドレスと名前を入力してください'); return; }
			if (!window.__heartdeskIsValidIP(ipVal)) { alert('IPアドレスの形式が正しくありません'); return; }
			var normalizedIpVal = window.__heartdeskNormalizeIP(ipVal);
			var duplicateRow = null;
			if (normalizedIpVal) {
				var rows = container.querySelectorAll('tr[data-ip]');
				for (var i = 0; i < rows.length; i++) {
					if (window.__heartdeskNormalizeIP(rows[i].getAttribute('data-ip')) === normalizedIpVal) {
						duplicateRow = rows[i];
						break;
					}
				}
			}
			if (duplicateRow) { alert('このIPは既に登録されています'); return; }
			if (typeVal === 'wlm' && !pinVal) { alert(window.ipTypeShortLabel('wlm') + '追加にはPINが必要です'); return; }
			var params = new URLSearchParams({ ip: ipVal, name: nameVal, type: typeVal, pin: pinVal });
			fetch(monitorApiURL('ip_add'), {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
				body: params.toString()
			}).then(function(r) { return r.json(); })
			.then(function(d) {
				alert(d.message || (d.ok ? '完了' : '失敗'));
				if (d.ok) {
					var secIPMgmt = getMonitorCardId('IP_MGMT', 'sec-ip-mgmt');
					loadSection(getMonitorCardAPI(secIPMgmt, 'ip_mgmt'), secIPMgmt + '-content', renderIPMgmt);
				}
			}).catch(function(err) { alert('エラー: ' + err); });
		}
	});
}

function ipmDoRemove(ip, pin, row) {
	var user = (typeof HD_REMOTE_USER !== 'undefined' && HD_REMOTE_USER) ? HD_REMOTE_USER : '';
	var params = new URLSearchParams({ ip: ip, user: user, pin: pin });
	fetch(monitorApiURL('ip_remove'), {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
		body: params.toString()
	}).then(function(r) { return r.json(); })
	.then(function(d) {
		alert(d.message || (d.ok ? '完了' : '失敗'));
		if (d.ok) {
			if (row) {
				row.style.transition = 'opacity 0.3s';
				row.style.opacity = '0';
				setTimeout(function() { row.remove(); }, 300);
			} else {
				var secIPMgmt = getMonitorCardId('IP_MGMT', 'sec-ip-mgmt');
				loadSection(getMonitorCardAPI(secIPMgmt, 'ip_mgmt'), secIPMgmt + '-content', renderIPMgmt);
			}
		}
	}).catch(function(e) { alert('エラー: ' + e); });
}

// =============================================================================
// IP 詳細モーダル（openIpModal / closeIpModal）
// =============================================================================

function openIpModal(ip) {
	var modal = document.getElementById('ip-search-modal');
	var title = document.getElementById('modal-ip-title');
	var body  = document.getElementById('modal-ip-body');
	if (!modal) return;
	title.textContent = ip + ' の履歴';
	body.innerHTML = '<p class="section-loading">読み込み中...</p>';
	// 共通 openModal 経由（フォーカス管理・Escape・トラップを共有）。フォールバックで従来の display 切替。
	if (typeof window.openModal === 'function') { window.openModal('ip-search-modal'); }
	else { modal.style.display = 'flex'; }

	fetch(getAppBase() + '/?api=search_ip&ip=' + encodeURIComponent(ip))
		.then(function(r) { return r.json(); })
		.then(function(data) {
			var html = '';

			// ---- アクション行 ----
			var wl = isWhitelisted(ip);
			var bannedJail = (window.BANNED_IPS && window.BANNED_IPS[ip]) || '';
			var banDisabled  = wl || !!bannedJail;
			var unbanDisabled = wl || !bannedJail;
			var banMsg = '';
			if (wl) banMsg = 'WLのためBAN不可';
			else if (bannedJail) banMsg = bannedJail + ' でBAN済み';

			var countryHtml = '';
			if (data.country) {
				if (data.is_japan === true) {
					countryHtml = '<span class="jp-badge">' + escapeHtml(data.country) + ' 国内</span>';
				} else if (data.is_japan === false) {
					countryHtml = '<span class="foreign-badge">' + escapeHtml(data.country) + ' 海外</span>';
				} else {
					countryHtml = '<span class="result-badge">' + escapeHtml(data.country) + '</span>';
				}
			}

			html += '<div class="ban-list-add-form">';
			html += '<span class="ip-label">' + escapeHtml(ip) + '</span>';
			html += '<span id="ip-modal-badges">' + ipBadges(ip) + '</span>';
			html += countryHtml;
			html += '<button type="button" class="btn-ban btn-sm" id="ip-modal-ban-btn"'   + (banDisabled   ? ' disabled' : '') + '>BAN追加</button>';
			html += '<button type="button" class="btn-warning btn-sm" id="ip-modal-unban-btn"' + (unbanDisabled ? ' disabled' : '') + '>BAN解除</button>';
			html += '<span id="ip-modal-ban-msg" class="ban-list-msg">' + escapeHtml(banMsg) + '</span>';
			html += '</div>';

			if (!data.results || data.results.length === 0) {
				html += '<p class="empty">' + escapeHtml(ip) + ' の記録なし</p>';
				body.innerHTML = html;
				setupIpModalBanEvents(ip);
				return;
			}

			html += buildIpModalTypeFilter(data.results);
			html += '<table><thead><tr><th>時刻</th><th class="col-ip">IP</th><th>種別</th><th>詳細</th></tr></thead><tbody>';
			for (var i = 0; i < data.results.length; i++) {
				var r = data.results[i];
				var typeClass = '';
				if (r.type.indexOf('失敗') !== -1 || r.type.indexOf('BAN') !== -1) typeClass = 'danger';
				else if (r.type.indexOf('成功') !== -1 || r.type.indexOf('解除') !== -1) typeClass = 'ok';
				html += '<tr data-type="' + escapeHtml(r.type) + '">'
					+ '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(r.time, '')) + '</td>'
					+ '<td class="nowrap">' + escapeHtml(r.ip) + '</td>'
					+ '<td><span class="search-type ' + typeClass + '">' + escapeHtml(r.type) + '</span></td>'
					+ '<td class="detail-cell">' + escapeHtml(r.detail) + '</td>'
					+ '</tr>';
			}
			html += '</tbody></table>';
			body.innerHTML = html;
			setupIpModalTypeFilter(body, ip, data.results.length);
			setupIpModalBanEvents(ip);
		})
		.catch(function(err) {
			body.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + escapeHtml(String(err)) + '</p>';
		});
}

function closeIpModal() {
	// 共通 closeModal 経由（フォーカス復帰を共有）。フォールバックで従来の display 切替。
	if (typeof window.closeModal === 'function') { window.closeModal('ip-search-modal'); return; }
	var modal = document.getElementById('ip-search-modal');
	if (modal) modal.style.display = 'none';
}

function buildIpModalTypeFilter(results) {
	var typeMap = {};
	for (var i = 0; i < results.length; i++) typeMap[results[i].type] = true;
	var types = Object.keys(typeMap).sort(function(a, b) { return a.localeCompare(b, 'ja'); });
	var html = '<div class="filter-bar ip-modal-filter">';
	html += '<select class="filter-select" id="ip-modal-type-filter"><option value="">全ての種別</option>';
	for (var j = 0; j < types.length; j++) {
		html += '<option value="' + escapeHtml(types[j]) + '">' + escapeHtml(types[j]) + '</option>';
	}
	html += '</select>';
	html += '<span class="filter-count" id="ip-modal-filter-count"></span>';
	html += '</div>';
	return html;
}

function setupIpModalTypeFilter(container, ip, totalCount) {
	var select = container.querySelector('#ip-modal-type-filter');
	if (!select) return;
	var rows  = container.querySelectorAll('tbody tr');
	var count = container.querySelector('#ip-modal-filter-count');
	var title = document.getElementById('modal-ip-title');

	function update() {
		var selected = select.value;
		var visible  = 0;
		for (var i = 0; i < rows.length; i++) {
			var show = !selected || rows[i].getAttribute('data-type') === selected;
			rows[i].style.display = show ? '' : 'none';
			if (show) visible++;
		}
		if (title)  title.textContent  = ip + ' の履歴: ' + formatCount(visible) + ' 件 / ' + formatCount(totalCount) + ' 件';
		if (count)  count.textContent  = formatCount(visible) + ' / ' + formatCount(totalCount) + ' 件';
	}

	select.addEventListener('change', update);
	update();
}

function setupIpModalBanEvents(ip) {
	var banBtn   = document.getElementById('ip-modal-ban-btn');
	var unbanBtn = document.getElementById('ip-modal-unban-btn');
	var msg      = document.getElementById('ip-modal-ban-msg');

	if (banBtn) {
		banBtn.addEventListener('click', function() {
			if (!confirm(ip + ' を recidive jail に BAN しますか？')) return;
			banBtn.disabled = true;
			msg.textContent = '処理中...';
			msg.className = 'ban-list-msg';
			var params = new URLSearchParams({ ip: ip });
			fetch(monitorApiURL('fail2ban_ban'), {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
				body: params.toString()
			})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				msg.textContent = d.message || (d.ok ? 'BAN しました' : '失敗');
				msg.className = 'ban-list-msg ' + (d.ok ? 'success' : 'error');
				banBtn.disabled = false;
				if (d.ok) {
					if (window.BANNED_IPS) window.BANNED_IPS[ip] = 'recidive';
					unbanBtn.disabled = false;
				}
			})
			.catch(function() {
				msg.textContent = 'エラーが発生しました';
				msg.className = 'ban-list-msg error';
				banBtn.disabled = false;
			});
		});
	}

	if (unbanBtn) {
		unbanBtn.addEventListener('click', function() {
			if (!confirm(ip + ' を全 jail から解除しますか？')) return;
			unbanBtn.disabled = true;
			msg.textContent = '処理中...';
			msg.className = 'ban-list-msg';
			var params = new URLSearchParams({ ip: ip });
			fetch(monitorApiURL('fail2ban_unban'), {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
				body: params.toString()
			})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				msg.textContent = d.message || (d.ok ? '解除しました' : '失敗');
				msg.className = 'ban-list-msg ' + (d.ok ? 'success' : 'error');
				unbanBtn.disabled = false;
				if (d.ok && window.BANNED_IPS) {
					delete window.BANNED_IPS[ip];
					banBtn.disabled = false;
				}
			})
			.catch(function() {
				msg.textContent = 'エラーが発生しました';
				msg.className = 'ban-list-msg error';
				unbanBtn.disabled = false;
			});
		});
	}
}

// ============================================================
// ハニーポット アクセス一覧レンダラー
// (renderHoneypotAccess / Summary / Detail / toggleHpPostBody)
// ============================================================

var HP_TRIGGER_LABELS = {
	dotfile:      'ドットファイル',
	wordpress:    'WordPress',
	db_tool:      'DB管理ツール',
	microsoft:    'Microsoft系',
	framework:    'フレームワーク',
	backdoor:     'バックドア/シェル',
	query_string: 'クエリ攻撃',
	other:        'その他'
};

/**
 * カードヘッダーの .card-header-actions にスロット span を確保して返す。
 * 既存スロットがあれば中身をクリアして返す。el = async-content 要素
 */
function ensureCardSlot(el, slotId) {
	var slot = document.getElementById(slotId);
	if (slot) { slot.innerHTML = ''; return slot; }
	var card    = el.closest('section.card');
	var actions = card && card.querySelector('.card-header-actions');
	if (!actions) return null;
	var s = document.createElement('span');
	s.id  = slotId;
	actions.insertBefore(s, actions.firstChild);
	return s;
}

/**
 * カード右上（.card-header-actions）のボタン・バッジを統一配置する。
 * @param {Element} el       - async-content要素またはカード内の任意の要素
 * @param {Object}  opts
 * @param {number}  opts.total           - データ全件数
 * @param {number}  [opts.filtered]      - 絞り込み後件数（省略時=total）
 * @param {number}  [opts.defaultLimit]  - 行表示制限数（省略時=制限なし）
 * @param {string}  [opts.slotId]        - 件数バッジスロットのDOM ID
 * @param {Array}   [opts.customButtons] - 独自ボタン定義
 *   [{label, cls, onclick, group:'register'|'list', selector}]
 * @param {Function} [opts.badgeFormatter] - バッジテキストカスタマイズ (opts) => string
 */
function initCardHeaderActions(el, opts) {
	opts = opts || {};
	var card    = el.closest ? el.closest('section.card') : null;
	var actions = card && card.querySelector('.card-header-actions');
	if (!actions) return;

	// 独自ボタン挿入（selector で重複防止）
	var customButtons = opts.customButtons || [];
	customButtons.forEach(function(def) {
		if (def.selector && actions.querySelector(def.selector)) return;
		var btn = document.createElement('button');
		btn.textContent = def.label;
		btn.className   = def.cls || '';
		if (def.onclick) btn.addEventListener('click', def.onclick);
		btn.setAttribute('data-header-order', def.group === 'register' ? '10' : '20');
		actions.appendChild(btn);
	});

	// DLボタンに data-header-order 付与
	actions.querySelectorAll('.export-btn').forEach(function(b) {
		if (!b.getAttribute('data-header-order')) b.setAttribute('data-header-order', '30');
	});
	// 更新ボタンに data-header-order 付与
	actions.querySelectorAll('.btn-card-refresh').forEach(function(b) {
		if (!b.getAttribute('data-header-order')) b.setAttribute('data-header-order', '40');
	});

	// 件数バッジスロット作成または既存クリア
	var slotId = opts.slotId;
	var slot   = slotId ? document.getElementById(slotId) : null;
	if (slotId && !slot) {
		slot    = document.createElement('span');
		slot.id = slotId;
		actions.appendChild(slot);
	}
	if (slot) {
		slot.innerHTML = '';
		slot.setAttribute('data-header-order', '50');
	}

	// countMode に応じてバッジテキストをスロットに表示
	var countMode = opts.countMode || 'none';
	if (slot && countMode !== 'none') {
		var total    = opts.total    != null ? opts.total    : null;
		var filtered = opts.filtered != null ? opts.filtered : null;
		var text = '';
		if (countMode === 'ratio' && filtered != null && total != null && filtered !== total) {
			text = formatCount(filtered) + ' / ' + formatCount(total) + '件';
		} else if (total != null) {
			text = formatCount(total) + '件';
		}
		if (text) {
			var badge = document.createElement('span');
			badge.className = 'expand-btn expand-btn-static';
			badge.textContent = text;
			slot.appendChild(badge);
		}
	}

	// data-header-order でソートして再挿入
	var children = Array.prototype.slice.call(actions.children);
	children.sort(function(a, b) {
		var oa = parseInt(a.getAttribute('data-header-order') || '99', 10);
		var ob = parseInt(b.getAttribute('data-header-order') || '99', 10);
		return oa - ob;
	});
	children.forEach(function(child) { actions.appendChild(child); });

	// expand-btn のテキストは initRowLimit が設定するため、ここでは何もしない
}

/**
 * card 要素の data-card-* 属性から opts を組み立てて initCardHeaderActions を呼ぶ。
 * 非同期ロード完了後（async-content が置き換わった直後）に呼び出す。
 * @param {Element} card    - section.card 要素
 * @param {Object}  runtime - { total, filtered } をレンダラから渡す（省略可）
 */
function autoInitCardFromDataset(card, runtime) {
	if (!card || !card.dataset) return;
	runtime = runtime || {};

	var mode         = card.dataset.cardCountMode   || 'none';
	var defaultLimit = parseInt(card.dataset.cardDefaultLimit || '0', 10);
	var slotId       = card.dataset.cardSlotId      || (card.id + '-count-btn');
	var content      = card.querySelector('.async-content, .card-body');
	if (!content) return;

	initCardHeaderActions(content, {
		slotId:       slotId,
		countMode:    mode,
		total:        runtime.total    != null ? runtime.total    : undefined,
		filtered:     runtime.filtered != null ? runtime.filtered : undefined,
		defaultLimit: defaultLimit,
	});

	if (defaultLimit > 0) {
		initRowLimit(content, defaultLimit, slotId);
	}
}

/**
 * 件数バッジテキストを再計算してスロットに反映する。
 * initRowLimit の data-row-limit-* 属性と連携する。
 * @param {Element} el    - async-content またはカード内任意要素
 * @param {Object}  [overrides] - {total, filtered, defaultLimit, slotId} で上書き可能
 */
function updateHeaderBadge(el, overrides) {
	// 将来の拡張用に残す（現在はボタンテキストは updateFilterCount が管理）
}

// 不審アクセス一覧エントリポイント（loadSection コールバック）
function renderHoneypotAccess(content, data) {
	var acc     = data && data.access ? data.access : data;
	var records = acc  && acc.records ? acc.records : [];
	var total   = acc  && acc.total   ? acc.total   : 0;
	if (records.length === 0) {
		content.innerHTML = '<p class="empty">ハニーポット記録はありません</p>';
		return;
	}
	content._hpData  = records;
	content._hpTotal = total;
	content._hpFlags = (acc && acc.flags) ? acc.flags : {};
	renderHoneypotAccessSummary(content);
}

// 集計ビュー: IP別にまとめて表示
function renderHoneypotAccessSummary(content) {
	saveCurrentViewFilter(content);
	var records   = content._hpData  || [];
	var total     = content._hpTotal || 0;
	var flags     = content._hpFlags || {};
	var csrfToken = getCsrfToken();

	// IP別集計
	var ipMap = {};
	records.forEach(function(r) {
		var ip = r.ip || '';
		if (!ip) return;
		if (!ipMap[ip]) {
			ipMap[ip] = { ip: ip, count: 0, first_ts: r.ts, last_ts: '', triggers: {}, paths: {},
				device: r.device, ua: r.ua, is_whitelisted: r.is_whitelisted, is_banned: r.is_banned };
		}
		var e = ipMap[ip];
		e.count++;
		if (!e.last_ts || r.ts > e.last_ts) { e.last_ts = r.ts; e.device = r.device; e.ua = r.ua; }
		if (!e.first_ts || r.ts < e.first_ts) e.first_ts = r.ts;
		if (r.trigger) e.triggers[r.trigger] = (e.triggers[r.trigger] || 0) + 1;
		if (r.path)    e.paths[r.path]       = (e.paths[r.path]       || 0) + 1;
	});
	var ips = Object.values(ipMap).sort(function(a, b) { return b.count - a.count; });

	// 国セレクト選択肢
	var countrySet = {};
	ips.forEach(function(e) { var c = flags[e.ip] || ''; if (c && c !== '-') countrySet[c] = true; });
	var countryOpts = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); })
		.map(function(c) { return '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</option>'; }).join('');

	// トリガーセレクト選択肢（件数順）
	var trigCounts = {};
	ips.forEach(function(e) {
		Object.keys(e.triggers).forEach(function(t) {
			var label = HP_TRIGGER_LABELS[t] || t;
			trigCounts[label] = (trigCounts[label] || 0) + (e.triggers[t] || 0);
		});
	});
	var trigLabelsSorted = Object.keys(trigCounts).sort(function(a, b) {
		var d = (trigCounts[b] || 0) - (trigCounts[a] || 0);
		return d !== 0 ? d : a.localeCompare(b, 'ja');
	});
	var trigOpts = trigLabelsSorted.map(function(t) {
		return '<option value="' + escapeHtml(t) + '">' + escapeHtml(t) + '</option>';
	}).join('');

	var html = cardViewToggle('summary',
		"renderHoneypotAccessSummary(this.closest('.async-content'))",
		"renderHoneypotAccessDetail(this.closest('.async-content'), null)");
	html += '<div class="hp-summary-meta">直近 ' + formatCount(total) + ' 件 &nbsp;/&nbsp; ' + formatCount(ips.length) + ' IP</div>';
	html += '<form method="post" data-bulk-ban="hp-summary">'
		+ '<input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '">'
		+ '<input type="hidden" name="ban_section" value="hp-summary">'
		+ '<div class="bulk-ban-bar">'
		+ '<label class="bulk-select-all"><input type="checkbox" data-select-all="hp-summary"> 全選択</label>'
		+ '<span class="bulk-ban-count" data-count="hp-summary">0件選択中</span>'
		+ '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="hp-summary" disabled>選択したIPをBAN</button>'
		+ '</div>';
	html += '<table class="log-table"><thead>';
	html += '<tr class="thead-filter-row">'
		+ '<th class="cb-col"></th>'
		+ '<th class="col-ip">' + buildIpFilterCell({wl:false,wlm:false,wla:false,ban:true,known:true}) + '<span class="filter-count"></span></th>'
		+ '<th></th><th></th><th></th>'
		+ '<th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts + '</select></th>'
		+ '<th class="th-filter-trigger"><select class="filter-select" data-filter="trigger" data-filter-partial="1"><option value="">全て</option>' + trigOpts + '</select></th>'
		+ '<th></th>'
		+ '<th class="th-filter-device"><select class="filter-select" data-filter="device"><option value="">全て</option><option value="pc">PC</option><option value="mobile">モバイル</option><option value="scanner">スキャナー</option><option value="tool">ツール</option><option value="unknown">不明</option></select></th>'
		+ '<th></th>'
		+ '</tr>';
	html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th>件数</th><th>初回</th><th>最終アクセス</th><th class="col-country">国</th><th>トリガー</th><th>代表パス</th><th>UA種別</th><th style="width:120px;"></th></tr>';
	html += '</thead><tbody>';
	ips.forEach(function(e) {
		var wl        = isWhitelisted(e.ip);
		var banned    = e.is_banned || !!BANNED_IPS[e.ip];
		var disableCb = wl || banned;
		var flagHtml  = flags[e.ip] || '-';
		var firstShort = formatDisplayDateTime(e.first_ts, '-');
		var lastShort  = formatDisplayDateTime(e.last_ts,  '-');
		var rowTrigLabels = Object.keys(e.triggers).map(function(t) { return HP_TRIGGER_LABELS[t] || t; });
		var trigHtml = Object.entries(e.triggers).sort(function(a, b) { return b[1] - a[1]; }).map(function(kv) {
			return '<span class="result-badge hp-trig-badge">' + escapeHtml(HP_TRIGGER_LABELS[kv[0]] || kv[0]) + '</span>';
		}).join('');
		var pathEntries = Object.entries(e.paths).sort(function(a, b) { return b[1] - a[1]; });
		var topPathHtml = '<span class="typo-faint">-</span>';
		if (pathEntries.length > 0) {
			var tp = pathEntries[0][0];
			var tpShort = tp.length > 24 ? tp.substring(0, 24) + '…' : tp;
			topPathHtml = '<span class="typo-sub-weak" style="word-break:break-all;" title="' + escapeHtml(tp) + '">' + escapeHtml(tpShort) + '</span>';
			if (pathEntries.length > 1) topPathHtml += '<br><span class="typo-sub-weak">他 ' + (pathEntries.length - 1) + ' 種</span>';
		}
		var ipEsc = escapeHtml(e.ip);
		html += '<tr class="hp-summary-row"'
			+ ' data-ip="'      + ipEsc + '"'
			+ ' data-wl="'      + (wl     ? '1' : '0') + '"'
			+ ' data-banned="'  + (banned ? '1' : '0') + '"'
			+ (KNOWN_IPS && KNOWN_IPS[e.ip] ? ' data-known="1"' : '')
			+ ' data-country="' + escapeHtml(flagHtml) + '"'
			+ ' data-trigger="' + escapeHtml(rowTrigLabels.join(' ')) + '"'
			+ ' data-device="'  + escapeHtml(e.device || 'unknown') + '"'
			+ ' style="cursor:pointer" title="クリックして一覧表示"'
			+ ' onclick="renderHoneypotAccessDetail(this.closest(\'.async-content\'), \'' + ipEsc + '\')">';
		html += '<td class="cb-col" onclick="event.stopPropagation();">'
			+ '<input type="checkbox" name="ban_ips[]" value="' + ipEsc + '" data-section="hp-summary"' + (disableCb ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation();openIpModal(\'' + ipEsc + '\')">' + ipEsc + '</code>' + ipBadges(e.ip) + '</td>';
		html += '<td><strong>' + formatCount(e.count) + '</strong> 件</td>';
		html += '<td class="nowrap datetime-cell">' + escapeHtml(firstShort) + '</td>';
		html += '<td class="nowrap datetime-cell">' + escapeHtml(lastShort)  + '</td>';
		html += '<td class="col-country">' + escapeHtml(flagHtml) + '</td>';
		html += '<td>' + trigHtml + '</td>';
		html += '<td style="max-width:180px;">' + topPathHtml + '</td>';
		html += '<td>' + deviceBadge(e) + '</td>';
		if (wl) {
			html += '<td><span class="wl-badge">WL</span></td>';
		} else if (banned) {
			html += '<td><span class="jail-tag jail-tag-banned">BAN済</span></td>';
		} else {
			html += '<td><button class="btn-ban btn-sm" onclick="event.stopPropagation();'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>';
		}
		html += '</tr>';
	});
	html += '</tbody></table></form>';
	content.innerHTML = html;
	autoInitCardFromDataset(content.closest('section.card'), { total: ips.length });
	initBulkBan('hp-summary', content);
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

// 一覧ビュー: IP絞り込み対応の詳細テーブル
function renderHoneypotAccessDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var records   = content._hpData  || [];
	var total     = content._hpTotal || 0;
	var flags     = content._hpFlags || {};
	var filtered  = filterIp ? records.filter(function(r) { return r.ip === filterIp; }) : records;
	var csrfToken = getCsrfToken();

	var countrySet = {}, trigCounts2 = {}, deviceSet = {};
	filtered.forEach(function(fr) {
		var fc = flags[fr.ip] || '';
		if (fc && fc !== '-') countrySet[fc] = true;
		var tl = HP_TRIGGER_LABELS[fr.trigger] || String(fr.trigger || '');
		if (tl) trigCounts2[tl] = (trigCounts2[tl] || 0) + 1;
		deviceSet[String(fr.device || 'unknown')] = true;
	});
	var countryOpts2 = Object.keys(countrySet).sort(function(a, b) { return a.localeCompare(b, 'ja'); })
		.map(function(c) { return '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</option>'; }).join('');
	var trigLabels2 = Object.keys(trigCounts2).sort(function(a, b) {
		var d = (trigCounts2[b] || 0) - (trigCounts2[a] || 0);
		return d !== 0 ? d : a.localeCompare(b, 'ja');
	});
	var trigOpts2 = trigLabels2.map(function(t) {
		return '<option value="' + escapeHtml(t) + '">' + escapeHtml(t) + '</option>';
	}).join('');
	var devLabelMap = { pc: 'PC', mobile: 'モバイル', scanner: 'スキャナー', tool: 'ツール', unknown: '不明' };
	var devOrder    = ['pc', 'mobile', 'scanner', 'tool', 'unknown'];
	var devOpts     = devOrder.filter(function(d) { return !!deviceSet[d]; })
		.map(function(d) { return '<option value="' + escapeHtml(d) + '">' + escapeHtml(devLabelMap[d] || d) + '</option>'; }).join('');

	var html = cardViewToggle('detail',
		"renderHoneypotAccessSummary(this.closest('.async-content'))",
		"renderHoneypotAccessDetail(this.closest('.async-content'), null)");
	if (filterIp) {
		html += '<div class="hp-filter-bar">'
			+ '<span class="hp-filter-badge">IP: ' + escapeHtml(filterIp) + '</span>'
			+ '<button class="btn-secondary btn-sm" onclick="renderHoneypotAccessDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button>'
			+ '<span class="typo-meta" style="margin-left:auto;">' + formatCount(filtered.length) + ' 件（全 ' + formatCount(total) + ' 件）</span>'
			+ '</div>';
	}
	html += '<form method="post" data-bulk-ban="hp-access">'
		+ '<input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '">'
		+ '<input type="hidden" name="ban_section" value="hp-access">'
		+ '<div class="bulk-ban-bar">'
		+ '<label class="bulk-select-all"><input type="checkbox" data-select-all="hp-access"> 全選択</label>'
		+ '<span class="bulk-ban-count" data-count="hp-access">0件選択中</span>'
		+ '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="hp-access" disabled>選択したIPをBAN</button>';
	if (!filterIp) html += '<span class="typo-meta" style="margin-left:auto;">直近 ' + formatCount(total) + ' 件</span>';
	html += '</div>';
	html += '<table class="log-table"><thead>';
	html += '<tr class="thead-filter-row"><th class="cb-col"></th>'
		+ '<th></th>'
		+ '<th class="col-ip">' + buildIpFilterCell({wl:false,wlm:false,wla:false,ban:true,known:true}) + '<span class="filter-count"></span></th>'
		+ '<th class="col-country"><select class="filter-select" data-filter="country"><option value="">全て</option>' + countryOpts2 + '</select></th>'
		+ '<th></th><th></th>'
		+ '<th class="th-filter-trigger"><select class="filter-select" data-filter="trigger" data-filter-partial="1"><option value="">全て</option>' + trigOpts2 + '</select></th>'
		+ '<th class="th-filter-device"><select class="filter-select" data-filter="device"><option value="">全て</option>' + devOpts + '</select></th>'
		+ '<th></th></tr>';
	html += '<tr><th class="cb-col"></th><th>日時</th><th class="col-ip">IP</th><th class="col-country">国</th><th>メソッド</th><th>パス</th><th>トリガー</th><th>UA種別</th><th style="width:70px;"></th></tr>';
	html += '</thead><tbody>';
	for (var i = 0; i < filtered.length; i++) {
		var r         = filtered[i];
		var wl2       = isWhitelisted(r.ip);
		var banned2   = r.is_banned || !!BANNED_IPS[r.ip];
		var disableCb2 = wl2 || banned2;
		var flagHtml2 = flags[r.ip] || '-';
		var trigLabel = HP_TRIGGER_LABELS[r.trigger] || escapeHtml(r.trigger || '');
		var tsShort   = formatDisplayDateTime(r.ts, '-');
		html += '<tr class="hp-detail-row"'
			+ ' data-ip="'      + escapeHtml(r.ip) + '"'
			+ ' data-wl="'      + (wl2     ? '1' : '0') + '"'
			+ ' data-banned="'  + (banned2 ? '1' : '0') + '"'
			+ (KNOWN_IPS && KNOWN_IPS[r.ip] ? ' data-known="1"' : '')
			+ ' data-country="' + escapeHtml(flagHtml2) + '"'
			+ ' data-trigger="' + escapeHtml(trigLabel) + '"'
			+ ' data-device="'  + escapeHtml(String(r.device || 'unknown')) + '"'
			+ ' style="cursor:pointer" title="クリックして集計表示"'
			+ ' onclick="renderHoneypotAccessSummary(this.closest(\'.async-content\'))">';
		html += '<td class="cb-col" onclick="event.stopPropagation();">'
			+ '<input type="checkbox" name="ban_ips[]" value="' + escapeHtml(r.ip) + '" data-section="hp-access"' + (disableCb2 ? ' disabled' : '') + '></td>';
		html += '<td class="nowrap datetime-cell">' + escapeHtml(tsShort) + '</td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation();openIpModal(\'' + escapeJsString(r.ip) + '\')">' + escapeHtml(r.ip) + '</code>' + ipBadges(r.ip) + '</td>';
		html += '<td class="col-country">' + escapeHtml(flagHtml2) + '</td>';
		var hasPostBody = r.method === 'POST' && r.post_body;
		var methodCell  = escapeHtml(r.method || '');
		if (hasPostBody) {
			methodCell += ' <button class="btn-secondary btn-sm typo-mini-btn"'
				+ ' onclick="event.stopPropagation();toggleHpPostBody(this,' + escapeHtml(JSON.stringify(r.post_body)) + ')">▼</button>';
		}
		html += '<td class="typo-meta">' + methodCell + '</td>';
		var pathFull  = (r.path || '') + (r.query ? '?' + r.query : '');
		var pathShort = pathFull.length > 30 ? pathFull.substring(0, 30) + '…' : pathFull;
		var pathCell  = '<span class="typo-sub" title="' + escapeHtml(pathFull) + '">' + escapeHtml(pathShort) + '</span>';
		if (r.referer) {
			var refShort = r.referer.length > 32 ? r.referer.substring(0, 32) + '…' : r.referer;
			pathCell += '<br><span class="typo-sub-weak" title="Referer: ' + escapeHtml(r.referer) + '">↩ ' + escapeHtml(refShort) + '</span>';
		}
		html += '<td style="max-width:220px;">' + pathCell + '</td>';
		html += '<td><span class="result-badge hp-trig-badge">' + escapeHtml(trigLabel) + '</span></td>';
		html += '<td>' + deviceBadge(r) + '</td>';
		if (wl2) {
			html += '<td><span class="wl-badge">WL</span></td>';
		} else if (banned2) {
			html += '<td><span class="jail-tag jail-tag-banned">BAN済</span></td>';
		} else {
			html += '<td onclick="event.stopPropagation();">'
				+ '<button class="btn-ban btn-sm"'
				+ ' onclick="this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>';
		}
		html += '</tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	autoInitCardFromDataset(content.closest('section.card'), { total: filtered.length });
	initBulkBan('hp-access', content);
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

// POSTボディ展開トグル
function toggleHpPostBody(btn, body) {
	var tr   = btn.closest('tr');
	var next = tr.nextElementSibling;
	if (next && next.classList.contains('hp-postbody-row')) {
		next.remove();
		btn.textContent = '▼';
	} else {
		var newTr = document.createElement('tr');
		newTr.className = 'hp-postbody-row';
		var colCount = tr.querySelectorAll('td').length;
		newTr.innerHTML = '<td colspan="' + colCount + '" class="hp-postbody-cell"><code>' + escapeHtml(body) + '</code></td>';
		tr.parentNode.insertBefore(newTr, tr.nextSibling);
		btn.textContent = '▲';
	}
}

// ============================================================
// NC 4xx アクセスレンダラー
// (renderNC4xxAccess / renderNc4xxSummary / renderNc4xxDetail / nc4xxChangeDays)
// ============================================================

// NC4xxアクセスエントリポイント（loadSection コールバック）
function renderNC4xxAccess(el, d) {
	var records = d && d.records   ? d.records   : [];
	var total   = d && d.total     ? d.total     : 0;
	if (records.length === 0) {
		el.innerHTML = '<p class="empty">Nextcloud 4xxアクセス記録はありません</p>';
		return;
	}
	el._nc4xxData  = records;
	el._nc4xxTotal = total;
	el._nc4xxFlags = (d && d.flags)     ? d.flags     : {};
	el._nc4xxDays  = (d && d.days_span) ? d.days_span : 1;
	renderNc4xxSummary(el);
}

// NC4xx 集計ビュー
function renderNc4xxSummary(content) {
	saveCurrentViewFilter(content);
	var records = content._nc4xxData  || [];
	var total   = content._nc4xxTotal || 0;
	var flags   = content._nc4xxFlags || {};

	var ipMap = {};
	records.forEach(function(r) {
		var ip = r.ip || '';
		if (!ip) return;
		if (!ipMap[ip]) {
			ipMap[ip] = { ip: ip, count: 0, s400: 0, s403: 0, s404: 0, first_ts: r.ts, last_ts: '' };
		}
		var e  = ipMap[ip];
		var st = r.status || 0;
		e.count++;
		if (st === 400) e.s400++;
		else if (st === 403) e.s403++;
		else if (st === 404) e.s404++;
		if (!e.last_ts  || r.ts > e.last_ts)  e.last_ts  = r.ts;
		if (!e.first_ts || r.ts < e.first_ts) e.first_ts = r.ts;
	});
	var ips = Object.values(ipMap).sort(function(a, b) { return b.count - a.count; });

	var html = cardViewToggle('summary',
		"renderNc4xxSummary(this.closest('.async-content'))",
		"renderNc4xxDetail(this.closest('.async-content'), null)");
	html += '<div class="hp-summary-meta">直近 ' + formatCount(total) + ' 件 &nbsp;/&nbsp; ' + formatCount(ips.length) + ' IP</div>';
	html += '<form method="post" data-bulk-ban="nc4xx-summary">'
		+ '<input type="hidden" name="csrf_token" value="' + escapeHtml(getCsrfToken()) + '">'
		+ '<input type="hidden" name="ban_section" value="nc4xx-summary">'
		+ '<div class="bulk-ban-bar">'
		+ '<label class="bulk-select-all"><input type="checkbox" data-select-all="nc4xx-summary"> 全選択</label>'
		+ '<span class="bulk-ban-count" data-count="nc4xx-summary">0件選択中</span>'
		+ '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nc4xx-summary" disabled>選択したIPをBAN</button>'
		+ '</div>';
	html += '<table class="log-table"><thead>';
	html += '<tr class="thead-filter-row">'
		+ '<th class="cb-col"></th>'
		+ '<th class="col-ip">' + buildIpFilterCell({wl:false,wlm:false,wla:false,ban:false,known:true}) + '<span class="filter-count"></span></th>'
		+ '<th class="col-country"></th>'
		+ '<th></th><th></th><th></th><th></th><th></th><th></th><th></th>'
		+ '</tr>';
	html += '<tr><th class="cb-col"></th><th class="col-ip">IP</th><th class="col-country">国</th>'
		+ '<th>件数</th><th>400</th><th>403</th><th>404</th>'
		+ '<th>初回</th><th>最終</th><th style="width:120px;"></th></tr>';
	html += '</thead><tbody>';
	ips.forEach(function(e) {
		var wl3       = isWhitelisted(e.ip);
		var banned3   = !!BANNED_IPS[e.ip];
		var disableCb3 = wl3 || banned3;
		var flagHtml3 = flags[e.ip] || '-';
		var ipEsc3    = escapeHtml(e.ip);
		html += '<tr class="nc4xx-summary-row"'
			+ ' data-ip="'     + ipEsc3 + '"'
			+ ' data-wl="'     + (wl3     ? '1' : '0') + '"'
			+ ' data-banned="' + (banned3 ? '1' : '0') + '"'
			+ (KNOWN_IPS && KNOWN_IPS[e.ip] ? ' data-known="1"' : '')
			+ ' style="cursor:pointer" title="クリックして一覧表示"'
			+ ' onclick="renderNc4xxDetail(this.closest(\'.async-content\'), \'' + ipEsc3 + '\')">';
		html += '<td class="cb-col" onclick="event.stopPropagation();">'
			+ '<input type="checkbox" name="ban_ips[]" value="' + ipEsc3 + '" data-section="nc4xx-summary"' + (disableCb3 ? ' disabled' : '') + '></td>';
		html += '<td class="col-ip"><code class="ip-clickable" onclick="event.stopPropagation();openIpModal(\'' + ipEsc3 + '\')">' + ipEsc3 + '</code>' + ipBadges(e.ip) + '</td>';
		html += '<td class="col-country">' + escapeHtml(flagHtml3) + '</td>';
		html += '<td><strong>' + formatCount(e.count) + '</strong></td>';
		html += '<td>' + (e.s400 > 0 ? e.s400 : '-') + '</td>';
		html += '<td>' + (e.s403 > 0 ? e.s403 : '-') + '</td>';
		html += '<td>' + (e.s404 > 0 ? e.s404 : '-') + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(e.first_ts, '-')) + '</td>';
		html += '<td class="nowrap">' + escapeHtml(formatDisplayDateTime(e.last_ts,  '-')) + '</td>';
		if (wl3) {
			html += '<td><span class="wl-badge">WL</span></td>';
		} else if (banned3) {
			html += '<td><span class="jail-tag jail-tag-banned">BAN済</span></td>';
		} else {
			html += '<td><button class="btn-ban btn-sm" onclick="event.stopPropagation();'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>';
		}
		html += '</tr>';
	});
	html += '</tbody></table></form>';
	content.innerHTML = html;
	autoInitCardFromDataset(content.closest('section.card'), { total: ips.length });
	initBulkBan('nc4xx-summary', content);
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'summary'));
}

// NC4xx 一覧ビュー
function renderNc4xxDetail(content, filterIp) {
	saveCurrentViewFilter(content);
	var records     = content._nc4xxData  || [];
	var total       = content._nc4xxTotal || 0;
	var flags       = content._nc4xxFlags || {};
	var filtered    = filterIp ? records.filter(function(r) { return r.ip === filterIp; }) : records;
	var csrfToken   = getCsrfToken();
	var currentDays = content._nc4xxDays || 1;

	var statusSet = {};
	filtered.forEach(function(r) { if (r.status) statusSet[r.status] = true; });
	var statusOpts = Object.keys(statusSet).sort().map(function(s) {
		return '<option value="' + escapeHtml(String(s)) + '">' + escapeHtml(String(s)) + '</option>';
	}).join('');

	var html = cardViewToggle('detail',
		"renderNc4xxSummary(this.closest('.async-content'))",
		"renderNc4xxDetail(this.closest('.async-content'), null)");
	if (filterIp) {
		html += '<div class="hp-filter-bar">'
			+ '<span class="hp-filter-badge">IP: ' + escapeHtml(filterIp) + '</span>'
			+ '<button class="btn-secondary btn-sm" onclick="renderNc4xxDetail(this.closest(\'.async-content\'), null)">× 絞り込みを解除</button>'
			+ '<span class="typo-meta" style="margin-left:auto;">' + formatCount(filtered.length) + ' 件（全 ' + formatCount(total) + ' 件）</span>'
			+ '</div>';
	}
	html += '<div class="hp-filter-bar"><span class="typo-meta">期間:</span>';
	[1, 7, 30].forEach(function(d) {
		var active = (currentDays === d) ? ' active' : '';
		html += '<button class="btn-secondary btn-sm' + active + '" onclick="nc4xxChangeDays(this.closest(\'.async-content\'), ' + d + ')">' + d + '日</button>';
	});
	html += '</div>';
	html += '<form method="post" data-bulk-ban="nc4xx-detail">'
		+ '<input type="hidden" name="csrf_token" value="' + escapeHtml(csrfToken) + '">'
		+ '<input type="hidden" name="ban_section" value="nc4xx-detail">'
		+ '<div class="bulk-ban-bar">'
		+ '<label class="bulk-select-all"><input type="checkbox" data-select-all="nc4xx-detail"> 全選択</label>'
		+ '<span class="bulk-ban-count" data-count="nc4xx-detail">0件選択中</span>'
		+ '<button type="submit" class="btn-ban btn-bulk-ban" data-ban-btn="nc4xx-detail" disabled>選択したIPをBAN</button>';
	if (!filterIp) html += '<span class="typo-meta" style="margin-left:auto;">直近 ' + formatCount(total) + ' 件</span>';
	html += '</div>';
	html += '<table class="log-table"><thead>';
	html += '<tr class="thead-filter-row"><th class="cb-col"></th>'
		+ '<th></th>'
		+ '<th class="col-ip">' + buildIpFilterCell({wl:false,wlm:false,wla:false,ban:false,known:true}) + '<span class="filter-count"></span></th>'
		+ '<th></th><th></th>'
		+ '<th class="th-filter-device"><select class="filter-select" data-filter="status"><option value="">全て</option>' + statusOpts + '</select></th>'
		+ '<th></th><th></th>'
		+ '</tr>';
	html += '<tr><th class="cb-col"></th><th>日時</th><th class="col-ip">IP</th><th>メソッド</th><th>パス</th><th>ステータス</th><th>UA</th><th style="width:70px;"></th></tr>';
	html += '</thead><tbody>';
	for (var j = 0; j < filtered.length; j++) {
		var rj        = filtered[j];
		var wl4       = isWhitelisted(rj.ip);
		var banned4   = !!BANNED_IPS[rj.ip];
		var disableCb4 = wl4 || banned4;
		var ipEsc4    = escapeHtml(rj.ip);
		var tsShort4  = formatDisplayDateTime(rj.ts, '-');
		var pathFull4 = rj.path || '';
		var pathShort4 = pathFull4.length > 30 ? pathFull4.substring(0, 30) + '…' : pathFull4;
		var uaFull4   = rj.ua || '';
		var uaShort4  = uaFull4.length > 30 ? uaFull4.substring(0, 30) + '…' : uaFull4;
		html += '<tr'
			+ ' data-ip="'     + ipEsc4 + '"'
			+ ' data-wl="'     + (wl4     ? '1' : '0') + '"'
			+ ' data-banned="' + (banned4 ? '1' : '0') + '"'
			+ (KNOWN_IPS && KNOWN_IPS[rj.ip] ? ' data-known="1"' : '')
			+ ' data-status="' + escapeHtml(String(rj.status || '')) + '"'
			+ ' style="cursor:pointer" title="クリックして集計表示"'
			+ ' onclick="renderNc4xxSummary(this.closest(\'.async-content\'))">';
		html += '<td class="cb-col" onclick="event.stopPropagation();">'
			+ '<input type="checkbox" name="ban_ips[]" value="' + ipEsc4 + '" data-section="nc4xx-detail"' + (disableCb4 ? ' disabled' : '') + '></td>';
		html += '<td class="nowrap datetime-cell">' + escapeHtml(tsShort4) + '</td>';
		html += '<td class="col-ip" onclick="event.stopPropagation();"><code class="ip-clickable" onclick="openIpModal(\'' + ipEsc4 + '\')">' + ipEsc4 + '</code>' + ipBadges(rj.ip) + '</td>';
		html += '<td class="typo-meta">' + escapeHtml(rj.method || '') + '</td>';
		html += '<td style="max-width:220px;cursor:pointer;"'
			+ ' title="' + escapeHtml(pathFull4) + '&#10;クリックでコピー"'
			+ ' onclick="event.stopPropagation();copyText(' + escapeHtml(JSON.stringify(pathFull4)) + ', this)">'
			+ '<span class="typo-sub">' + escapeHtml(pathShort4) + '</span></td>';
		html += '<td><span class="result-badge">' + escapeHtml(String(rj.status || '')) + '</span></td>';
		html += '<td class="typo-sub" title="' + escapeHtml(uaFull4) + '">' + escapeHtml(uaShort4) + '</td>';
		if (wl4) {
			html += '<td><span class="wl-badge">WL</span></td>';
		} else if (banned4) {
			html += '<td><span class="jail-tag jail-tag-banned">BAN済</span></td>';
		} else {
			html += '<td onclick="event.stopPropagation();">'
				+ '<button class="btn-ban btn-sm"'
				+ ' onclick="this.closest(\'tr\').querySelector(\'input[type=checkbox]\').checked=true;'
				+ 'this.closest(\'tr\').querySelector(\'input[type=checkbox]\').dispatchEvent(new Event(\'change\',{bubbles:true}));">BAN追加</button></td>';
		}
		html += '</tr>';
	}
	html += '</tbody></table></form>';
	content.innerHTML = html;
	autoInitCardFromDataset(content.closest('section.card'), { total: filtered.length });
	initBulkBan('nc4xx-detail', content);
	setupCardFilter(content.querySelector('.thead-filter-row'), content);
	restoreFilterState(content, getViewFilter(content, 'detail'));
}

// 期間切り替え（一覧ビューを再取得して再描画）
function nc4xxChangeDays(content, days) {
	content._nc4xxDays = days;
	content.innerHTML  = '<p class="section-loading">読み込み中...</p>';
	fetch(getAppBase() + '/?api=nc4xx_access&days=' + days)
		.then(function(r) { return r.json(); })
		.then(function(data) {
			var records = data.records || [];
			if (records.length === 0) {
				content.innerHTML = '<p class="empty">Nextcloud 4xxアクセス記録はありません</p>';
				return;
			}
			content._nc4xxData  = records;
			content._nc4xxTotal = data.total || 0;
			content._nc4xxFlags = data.flags || {};
			content._nc4xxDays  = days;
			renderNc4xxDetail(content, null);
		})
		.catch(function() {
			content.innerHTML = '<p class="section-error">データ取得エラー</p>';
		});
}

// =============================================================================
// ユーザー管理カード（sec-user-mgmt）
// =============================================================================

function renderUserMgmt(content, data) {
	var users = (data && data.users) || [];

	var html = '<div class="authz-section">';

	if (users.length === 0) {
		html += '<p style="padding:8px 0;color:#777">ユーザーなし</p>';
	} else {
		html += '<table class="log-table">'
			+ '<thead>'
			+ '<tr><th>#</th><th>ユーザー</th><th>ロール</th><th>画面アクセス</th><th>2FA</th><th>ロック</th><th></th></tr>'
			+ '<tr class="thead-filter-row">'
			+ '<th></th>'
			+ '<th><input type="text" class="filter-input" data-filter="user" placeholder="ユーザー絞り込み"></th>'
			+ '<th><select class="filter-select" data-filter="role"><option value="">全ロール</option>'
			+ '<option value="vendor_staff">vendor_staff</option>'
			+ '<option value="tenant_admin">tenant_admin</option>'
			+ '<option value="tenant_user">tenant_user</option>'
			+ '</select></th>'
			+ '<th></th><th></th><th></th><th></th>'
			+ '</tr>'
			+ '</thead><tbody>';

		for (var i = 0; i < users.length; i++) {
			var u = users[i];
			var roleCls = u.role === 'vendor_staff' ? 'authz-role-vendor'
				: u.role === 'tenant_admin' ? 'authz-role-admin'
				: 'authz-role-user';
			var roleLabel = u.role === 'vendor_staff' ? 'vendor_staff'
				: u.role === 'tenant_admin' ? 'tenant_admin'
				: 'tenant_user';

			var screensHtml = '';
			var screens = u.access_screens || [];
			for (var si = 0; si < screens.length; si++) {
				screensHtml += '<span class="authz-screen-badge">' + escapeHtml(screens[si]) + '</span>';
			}

			var totpHtml = (u.authn_status && u.authn_status.totp_enabled)
				? '<span class="result-badge badge-2fa-enabled">有効</span>'
				: '<span class="result-badge badge-2fa-disabled">無効</span>';

			var lockHtml = (u.authn_status && u.authn_status.locked)
				? '<span class="result-badge badge-lock-locked">ロック中</span>'
				: '<span class="result-badge badge-lock-normal">通常</span>';

			var disabledNote = u.disabled ? ' <span class="result-badge badge-disabled">無効化</span>' : '';

			html += '<tr data-user="' + escapeHtml(u.username) + '" data-role="' + escapeHtml(u.role) + '">'
				+ '<td><strong>' + escapeHtml(u.username) + '</strong>'
				+ (u.name ? ' <span class="typo-sub-weak">(' + escapeHtml(u.name) + ')</span>' : '')
				+ disabledNote + '</td>'
				+ '<td><span class="' + roleCls + ' authz-role-badge authz-role-editable" data-username="' + escapeHtml(u.username) + '">' + escapeHtml(roleLabel) + '</span></td>'
				+ '<td class="authz-screens-cell" data-username="' + escapeHtml(u.username) + '">' + screensHtml + '</td>'
				+ '<td>' + totpHtml + '</td>'
				+ '<td>' + lockHtml + '</td>'
				+ '<td>'
				+ '<button type="button" class="btn-primary btn-sm authz-edit-btn" data-username="' + escapeHtml(u.username) + '">編集</button>'
				+ ' <button type="button" class="btn-danger btn-sm authz-delete-btn" data-username="' + escapeHtml(u.username) + '" data-role="' + escapeHtml(u.role) + '">削除</button>'
				+ '</td>'
				+ '</tr>';
		}
		html += '</tbody>'
			+ '<tfoot>'
			+ '<tr class="authz-add-row"><td colspan="6">'
			+ '<button type="button" class="btn-primary btn-sm authz-add-user-btn">+ ユーザー追加</button>'
			+ '</td></tr>'
			+ '</tfoot>';
		html += '</table>';
	}

	html += '</div>';

	content.innerHTML = html;

	userMgmtLoadCatalogAndInitEvents(content, data);
	autoInitCardFromDataset(content.closest('section.card'), { total: users.length });

	var filterBar = content.querySelector('.thead-filter-row');
	if (filterBar) setupCardFilter(filterBar, content);
}

function userMgmtLoadCatalogAndInitEvents(container, usersData) {
	fetch(getAppBase() + '/?api=user_mgmt_catalog')
		.then(function(r) { return r.json(); })
		.then(function(catalog) {
			userMgmtInitEvents(container, usersData, catalog);
		})
		.catch(function() {
			userMgmtInitEvents(container, usersData, null);
		});
}

function userMgmtInitEvents(container, usersData, catalog) {
	// 最新の usersData / catalog を container に保持する。
	// renderUserMgmt は同じ content 要素に innerHTML を差し替えて再描画するため、
	// click リスナーを毎回 addEventListener すると累積してしまい、
	// authzOpenCreatePanel 内の toggle ロジック (既存パネルがあれば閉じる) と重なって
	// 「ユーザー追加 → 再度 + ユーザー追加が無反応」という症状が出る。
	container._userMgmtState = { usersData: usersData, catalog: catalog };
	if (container._userMgmtClickAttached) return;
	container._userMgmtClickAttached = true;

	container.addEventListener('click', function(e) {
		var state = container._userMgmtState || {};
		var curUsersData = state.usersData;
		var curCatalog = state.catalog;

		var editBtn = e.target.closest && e.target.closest('button.authz-edit-btn');
		if (editBtn) {
			var username = editBtn.getAttribute('data-username') || '';
			var users = (curUsersData && curUsersData.users) || [];
			var user = null;
			for (var i = 0; i < users.length; i++) {
				if (users[i].username === username) { user = users[i]; break; }
			}
			if (user) authzOpenEditPanel(container, user, curCatalog, curUsersData);
			return;
		}

		var delBtn = e.target.closest && e.target.closest('button.authz-delete-btn');
		if (delBtn) {
			var delUsername = delBtn.getAttribute('data-username') || '';
			var delRole = delBtn.getAttribute('data-role') || '';
			authzDeleteUser(container, delUsername, delRole, curUsersData);
			return;
		}

		var addBtn = e.target.closest && e.target.closest('button.authz-add-user-btn');
		if (addBtn) {
			authzOpenCreatePanel(container, curCatalog);
		}
	});
}

function authzDeleteUser(container, username, role, usersData) {
	var users = (usersData && usersData.users) || [];
	var vendorCount = users.filter(function(u) { return u.role === 'vendor_staff'; }).length;
	if (role === 'vendor_staff' && vendorCount <= 1) {
		alert('vendor_staff は最低1名必要なため削除できません。');
		return;
	}
	if (!confirm(username + ' を削除してよろしいですか？\nこの操作は取り消せません。')) return;

	fetch(getAppBase() + '/?api=user_mgmt_delete', {
		method: 'POST',
		credentials: 'same-origin',
		headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
		body: JSON.stringify({ username: username })
	})
		.then(function(r) { return r.json(); })
		.then(function(d) {
			if (d.ok) {
				var secAuthz = getMonitorCardId('USER_MGMT', 'sec-user-mgmt');
				loadSection(getMonitorCardAPI(secAuthz, 'user_mgmt'), secAuthz + '-content', renderUserMgmt);
			} else {
				alert('削除失敗: ' + (d.message || '不明なエラー'));
			}
		})
		.catch(function(e) {
			alert('削除失敗: ' + e);
		});
}

function authzOpenEditPanel(container, user, catalog, usersData) {
	var prevUser = '';
	container.querySelectorAll('tr.authz-edit-panel-row').forEach(function(panelRow) {
		if (!prevUser) {
			var panel = panelRow.querySelector('.authz-edit-panel');
			if (panel) prevUser = panel.getAttribute('data-panel-user') || '';
		}
		panelRow.remove();
	});
	if (prevUser === user.username) return;

	var row = container.querySelector('tr[data-user="' + user.username + '"]');
	if (!row) return;

	var roles = catalog ? catalog.roles : [
		{ id: 'vendor_staff', default_screens: ['monitor'] },
		{ id: 'tenant_admin', default_screens: ['monitor'] },
		{ id: 'tenant_user', default_screens: ['monitor'] }
	];
	var allScreens = catalog ? catalog.screens.map(function(s) { return s.id; }) : ['monitor'];
	var allActions = catalog ? catalog.actions : [];

	function defaultScreensFor(roleId) {
		for (var i = 0; i < roles.length; i++) {
			if (roles[i].id === roleId) return roles[i].default_screens || [];
		}
		return [];
	}

	var currentScreens = user.access_screens || defaultScreensFor(user.role);
	var currentPolicy = user.policy || {};
	// actions_user.toml の deny リスト（追加禁止）。チェック外しで deny、チェックは role 既定値を尊重。
	var currentDenySet = {};
	var currentDenyList = (currentPolicy && currentPolicy.deny) || [];
	for (var di = 0; di < currentDenyList.length; di++) {
		currentDenySet[currentDenyList[di]] = true;
	}
	var currentHideCards = (currentPolicy && currentPolicy.hide_cards) || [];
	var currentHideChildCards = (currentPolicy && currentPolicy.hide_child_cards) || {};

	function renderActionLabelHtml(act) {
		var title = (act && act.label) ? act.label : act.id;
		var parts = [];
		if (act && act.feature) parts.push('機能: ' + act.feature);
		if (act && act.card_labels && act.card_labels.length > 0) parts.push('カード: ' + act.card_labels.join(' / '));
		if (act && act.child_card_labels && act.child_card_labels.length > 0) parts.push('子カード: ' + act.child_card_labels.join(' / '));
		var html = '<span class="authz-action-text"><span class="authz-action-name">' + escapeHtml(title) + '</span>';
		if (parts.length > 0) html += '<span class="authz-action-meta">' + escapeHtml(parts.join(' ｜ ')) + '</span>';
		html += '</span>';
		return html;
	}

	var panelHtml = '<tr class="authz-edit-panel-row"><td colspan="6"><div class="authz-edit-panel" data-panel-user="' + escapeHtml(user.username) + '">';
	panelHtml += '<div class="authz-panel-header"><strong class="authz-panel-title">' + escapeHtml(user.username) + ' の権限設定</strong>'
		+ '<button type="button" class="btn-secondary btn-sm authz-panel-close">閉じる</button></div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">ロール（属性軸）</div>';
	panelHtml += '<select class="filter-select authz-role-select" id="authz-role-' + escapeHtml(user.username) + '">';
	var roleOptions = [
		{ value: 'vendor_staff', label: 'vendor_staff（ベンダー運用者）' },
		{ value: 'tenant_admin', label: 'tenant_admin（テナント管理者）' },
		{ value: 'tenant_user', label: 'tenant_user（テナント利用者）' }
	];
	for (var ri = 0; ri < roleOptions.length; ri++) {
		var ro = roleOptions[ri];
		panelHtml += '<option value="' + ro.value + '"' + (user.role === ro.value ? ' selected' : '') + '>' + ro.label + '</option>';
	}
	panelHtml += '</select>';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">画面アクセス（access_screens）</div>';
	panelHtml += '<div class="authz-screens-checkboxes">';
	for (var sci = 0; sci < allScreens.length; sci++) {
		var sc = allScreens[sci];
		var checked = currentScreens.indexOf(sc) >= 0 ? ' checked' : '';
		panelHtml += '<label class="authz-check-label"><input type="checkbox" class="authz-screen-check" value="' + escapeHtml(sc) + '"' + checked + '> ' + escapeHtml(sc) + '</label>';
	}
	panelHtml += '</div>';
	panelHtml += '<button type="button" class="btn-secondary btn-sm authz-screens-reset" data-username="' + escapeHtml(user.username) + '" style="margin-top:6px">ロール既定に戻す</button>';
	panelHtml += '</div>';

	if (allActions.length > 0) {
		var destructiveActions = allActions.filter(function(a) { return a.destructive; });
		var readonlyActions = allActions.filter(function(a) { return !a.destructive; });

		panelHtml += '<div class="authz-panel-section authz-panel-collapsible">';
		panelHtml += '<div class="authz-panel-label authz-collapsible-toggle">アクション制御（詳細）<span class="authz-toggle-icon">▶</span></div>';
		panelHtml += '<div class="authz-collapsible-body" style="display:none">';

		// チェック外し = actions_user.toml の deny（追加禁止）。
		//     チェックのまま = role/tenant 既定値を尊重（復活はできない）。
		if (destructiveActions.length > 0) {
			panelHtml += '<div class="authz-action-group-label">破壊的アクション（チェック外しでこのユーザーに対し禁止）</div>';
			panelHtml += '<div class="authz-action-checks">';
			for (var ai = 0; ai < destructiveActions.length; ai++) {
				var act = destructiveActions[ai];
				var actChecked = currentDenySet[act.id] ? '' : ' checked';
				panelHtml += '<label class="authz-check-label authz-action-label"><input type="checkbox" class="authz-action-check" value="' + escapeHtml(act.id) + '"'
					+ actChecked + '> ' + renderActionLabelHtml(act) + '</label>';
			}
			panelHtml += '</div>';
		}
		if (readonlyActions.length > 0) {
			panelHtml += '<div class="authz-action-group-label">読み取り系アクション（チェック外しでこのユーザーに対し禁止）</div>';
			panelHtml += '<div class="authz-action-checks">';
			for (var rj = 0; rj < readonlyActions.length; rj++) {
				var ract = readonlyActions[rj];
				var ractChecked = currentDenySet[ract.id] ? '' : ' checked';
				panelHtml += '<label class="authz-check-label authz-action-label"><input type="checkbox" class="authz-action-check" value="' + escapeHtml(ract.id) + '"'
					+ ractChecked + '> ' + renderActionLabelHtml(ract) + '</label>';
			}
			panelHtml += '</div>';
		}
		panelHtml += '</div></div>';
	}

	panelHtml += '<div class="authz-panel-section authz-authn-status">';
	panelHtml += '<div class="authz-panel-label">認証状態（参照のみ）</div>';
	var authn = user.authn_status || {};
	panelHtml += '<div class="authz-authn-row">';
	panelHtml += '2FA: ' + (authn.totp_enabled
		? '<span class="result-badge badge-2fa-enabled">有効</span>'
		: '<span class="result-badge badge-2fa-disabled">無効</span>');
	panelHtml += '　ロック: ' + (authn.locked
		? '<span class="result-badge badge-lock-locked">ロック中</span> <a class="btn-warning btn-sm" href="' + getAppBase() + '/admin/users" target="_blank">解除</a>'
		: '<span class="result-badge badge-lock-normal">通常</span>');
	panelHtml += '</div>';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-actions">'
		+ '<button type="button" class="btn-primary btn-sm authz-save-btn" data-username="' + escapeHtml(user.username) + '">保存</button>'
		+ '<button type="button" class="btn-warning btn-sm authz-reset-btn" data-username="' + escapeHtml(user.username) + '">ロール既定にリセット</button>'
		+ '<span class="authz-msg"></span>'
		+ '</div>';

	panelHtml += '</div></td></tr>';

	row.insertAdjacentHTML('afterend', panelHtml);

	var panel = container.querySelector('.authz-edit-panel[data-panel-user="' + user.username + '"]');
	if (!panel) return;

	var closeBtn = panel.querySelector('.authz-panel-close');
	if (closeBtn) closeBtn.addEventListener('click', function() {
		var panelRow = panel.closest('tr.authz-edit-panel-row');
		if (panelRow) panelRow.remove();
		else panel.remove();
	});

	var roleSelect = panel.querySelector('.authz-role-select');
	if (roleSelect) {
		roleSelect.addEventListener('change', function() {
			var newDefaults = defaultScreensFor(roleSelect.value);
			panel.querySelectorAll('.authz-screen-check').forEach(function(cb) {
				cb.checked = newDefaults.indexOf(cb.value) >= 0;
			});
		});
	}

	var screensResetBtn = panel.querySelector('.authz-screens-reset');
	if (screensResetBtn) {
		screensResetBtn.addEventListener('click', function() {
			var sel = panel.querySelector('.authz-role-select');
			var roleId = sel ? sel.value : user.role;
			var defaults = defaultScreensFor(roleId);
			panel.querySelectorAll('.authz-screen-check').forEach(function(cb) {
				cb.checked = defaults.indexOf(cb.value) >= 0;
			});
		});
	}

	var toggle = panel.querySelector('.authz-collapsible-toggle');
	if (toggle) {
		toggle.addEventListener('click', function() {
			var body = panel.querySelector('.authz-collapsible-body');
			var icon = panel.querySelector('.authz-toggle-icon');
			if (!body) return;
			var isHidden = body.style.display === 'none';
			body.style.display = isHidden ? '' : 'none';
			if (icon) icon.textContent = isHidden ? '▼' : '▶';
		});
	}

	var saveBtn = panel.querySelector('.authz-save-btn');
	if (saveBtn) {
		saveBtn.addEventListener('click', function() {
			var sel = panel.querySelector('.authz-role-select');
			var role = sel ? sel.value : user.role;

			var screens = [];
			panel.querySelectorAll('.authz-screen-check').forEach(function(cb) {
				if (cb.checked) screens.push(cb.value);
			});

			// チェック外しのアクションのみ deny リストに入れる（actions_user.toml）。
			var deny = [];
			panel.querySelectorAll('.authz-action-check').forEach(function(cb) {
				if (!cb.checked) deny.push(cb.value);
			});

			var payload = {
				username: user.username,
				role: role,
				access_screens: screens,
				policy: {
					deny: deny,
					hide_cards: currentHideCards,
					hide_child_cards: currentHideChildCards
				}
			};

			var msg = panel.querySelector('.authz-msg');
			saveBtn.disabled = true;
			if (msg) msg.textContent = '保存中...';

			fetch(getAppBase() + '/?api=user_mgmt_save', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
				body: JSON.stringify(payload)
			})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				if (msg) {
					msg.textContent = d.message || (d.ok ? '保存しました' : 'エラー');
					msg.className = 'authz-msg ' + (d.ok ? 'authz-msg-ok' : 'authz-msg-err');
				}
				if (d.ok) {
					authzUpdateRow(container, user.username, role, screens);
				}
			})
			.catch(function(e) {
				if (msg) { msg.textContent = 'エラー: ' + e; msg.className = 'authz-msg authz-msg-err'; }
			})
			.finally(function() { saveBtn.disabled = false; });
		});
	}

	var resetBtn = panel.querySelector('.authz-reset-btn');
	if (resetBtn) {
		resetBtn.addEventListener('click', function() {
			if (!confirm(user.username + ' の権限をロール既定値にリセットしますか？')) return;
			var msg = panel.querySelector('.authz-msg');
			resetBtn.disabled = true;
			if (msg) msg.textContent = 'リセット中...';

			fetch(getAppBase() + '/?api=user_mgmt_reset', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
				body: JSON.stringify({ username: user.username })
			})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				if (msg) {
					msg.textContent = d.message || (d.ok ? 'リセットしました' : 'エラー');
					msg.className = 'authz-msg ' + (d.ok ? 'authz-msg-ok' : 'authz-msg-err');
				}
				if (d.ok) {
					var secAuthz = getMonitorCardId('USER_MGMT', 'sec-user-mgmt');
					loadSection(getMonitorCardAPI(secAuthz, 'user_mgmt'), secAuthz + '-content', renderUserMgmt);
				}
			})
			.catch(function(e) {
				if (msg) { msg.textContent = 'エラー: ' + e; msg.className = 'authz-msg authz-msg-err'; }
			})
			.finally(function() { resetBtn.disabled = false; });
		});
	}
}

function authzOpenCreatePanel(container, catalog) {
	var existing = container.querySelector('.authz-create-panel-row');
	if (existing) { existing.remove(); return; }
	container.querySelectorAll('tr.authz-edit-panel-row').forEach(function(r) { r.remove(); });

	var roles = catalog ? catalog.roles : [
		{ id: 'vendor_staff', default_screens: ['monitor'] },
		{ id: 'tenant_admin', default_screens: ['monitor'] },
		{ id: 'tenant_user', default_screens: ['monitor'] }
	];
	var allScreens = catalog ? catalog.screens.map(function(s) { return s.id; }) : ['monitor'];

	function defaultScreensFor(roleId) {
		for (var i = 0; i < roles.length; i++) {
			if (roles[i].id === roleId) return roles[i].default_screens || [];
		}
		return [];
	}

	var roleOptions = [
		{ value: 'vendor_staff', label: 'vendor_staff（ベンダー運用者）' },
		{ value: 'tenant_admin', label: 'tenant_admin（テナント管理者）' },
		{ value: 'tenant_user', label: 'tenant_user（テナント利用者）' }
	];
	var defaultRole = 'tenant_user';
	var defaultScreens = defaultScreensFor(defaultRole);

	var roleSelectHtml = '<select class="filter-select authz-role-select" id="authz-create-role">';
	for (var ri = 0; ri < roleOptions.length; ri++) {
		var ro = roleOptions[ri];
		roleSelectHtml += '<option value="' + ro.value + '"' + (ro.value === defaultRole ? ' selected' : '') + '>' + ro.label + '</option>';
	}
	roleSelectHtml += '</select>';

	var screensHtml = '';
	for (var sci = 0; sci < allScreens.length; sci++) {
		var sc = allScreens[sci];
		var checked = defaultScreens.indexOf(sc) >= 0 ? ' checked' : '';
		screensHtml += '<label class="authz-check-label"><input type="checkbox" class="authz-screen-check" value="' + escapeHtml(sc) + '"' + checked + '> ' + escapeHtml(sc) + '</label>';
	}

	var panelHtml = '<tr class="authz-create-panel-row"><td colspan="6"><div class="authz-edit-panel authz-create-panel">';
	panelHtml += '<div class="authz-panel-header"><strong class="authz-panel-title">新規ユーザーの追加</strong>'
		+ '<button type="button" class="btn-secondary btn-sm authz-panel-close">閉じる</button></div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">ユーザー名 <span class="authz-required">*</span></div>';
	panelHtml += '<input type="text" class="filter-input authz-create-username" placeholder="username（英数字・記号）" style="width:240px">';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">表示名</div>';
	panelHtml += '<input type="text" class="filter-input authz-create-name" placeholder="表示名（省略可）" style="width:240px">';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">パスワード <span class="authz-required">*</span></div>';
	panelHtml += '<input type="password" class="filter-input authz-create-password" placeholder="パスワード" style="width:240px">';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">ロール</div>';
	panelHtml += roleSelectHtml;
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-section">';
	panelHtml += '<div class="authz-panel-label">画面アクセス（access_screens）</div>';
	panelHtml += '<div class="authz-screens-checkboxes">' + screensHtml + '</div>';
	panelHtml += '</div>';

	panelHtml += '<div class="authz-panel-actions">'
		+ '<button type="button" class="btn-primary btn-sm authz-create-save-btn">作成</button>'
		+ '<span class="authz-msg"></span>'
		+ '</div>';
	panelHtml += '</div></td></tr>';

	var addRow = container.querySelector('tr.authz-add-row');
	if (addRow) {
		addRow.insertAdjacentHTML('beforebegin', panelHtml);
	} else {
		var tbody = container.querySelector('tbody');
		if (tbody) tbody.insertAdjacentHTML('afterend', panelHtml);
	}

	var panel = container.querySelector('.authz-create-panel');
	if (!panel) return;

	var closeBtn = panel.querySelector('.authz-panel-close');
	if (closeBtn) closeBtn.addEventListener('click', function() {
		panel.closest('tr.authz-create-panel-row').remove();
	});

	var roleSelect = panel.querySelector('.authz-role-select');
	if (roleSelect) {
		roleSelect.addEventListener('change', function() {
			var newDefaults = defaultScreensFor(roleSelect.value);
			panel.querySelectorAll('.authz-screen-check').forEach(function(cb) {
				cb.checked = newDefaults.indexOf(cb.value) >= 0;
			});
		});
	}

	var saveBtn = panel.querySelector('.authz-create-save-btn');
	if (saveBtn) {
		saveBtn.addEventListener('click', function() {
			var usernameInput = panel.querySelector('.authz-create-username');
			var nameInput = panel.querySelector('.authz-create-name');
			var passwordInput = panel.querySelector('.authz-create-password');
			var sel = panel.querySelector('.authz-role-select');
			var msg = panel.querySelector('.authz-msg');

			var username = usernameInput ? usernameInput.value.trim() : '';
			var name = nameInput ? nameInput.value.trim() : '';
			var password = passwordInput ? passwordInput.value : '';
			var role = sel ? sel.value : defaultRole;

			if (!username) {
				if (msg) { msg.textContent = 'ユーザー名を入力してください'; msg.className = 'authz-msg authz-msg-err'; }
				return;
			}
			if (!password) {
				if (msg) { msg.textContent = 'パスワードを入力してください'; msg.className = 'authz-msg authz-msg-err'; }
				return;
			}

			var screens = [];
			panel.querySelectorAll('.authz-screen-check').forEach(function(cb) {
				if (cb.checked) screens.push(cb.value);
			});

			var payload = { username: username, name: name, role: role, password: password, access_screens: screens };
			saveBtn.disabled = true;
			if (msg) msg.textContent = '作成中...';

			fetch(getAppBase() + '/?api=user_mgmt_create', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
				body: JSON.stringify(payload)
			})
			.then(function(r) { return r.json(); })
			.then(function(d) {
				if (msg) {
					msg.textContent = d.message || (d.ok ? '作成しました' : 'エラー');
					msg.className = 'authz-msg ' + (d.ok ? 'authz-msg-ok' : 'authz-msg-err');
				}
				if (d.ok) {
					var secAuthz = getMonitorCardId('USER_MGMT', 'sec-user-mgmt');
					loadSection(getMonitorCardAPI(secAuthz, 'user_mgmt'), secAuthz + '-content', renderUserMgmt);
				} else {
					saveBtn.disabled = false;
				}
			})
			.catch(function(e) {
				if (msg) { msg.textContent = 'エラー: ' + e; msg.className = 'authz-msg authz-msg-err'; }
				saveBtn.disabled = false;
			});
		});
	}
}

function authzUpdateRow(container, username, newRole, newScreens) {
	var row = container.querySelector('tr[data-user="' + username + '"]');
	if (!row) return;

	row.setAttribute('data-role', newRole);

	var roleCls = newRole === 'vendor_staff' ? 'authz-role-vendor'
		: newRole === 'tenant_admin' ? 'authz-role-admin'
		: 'authz-role-user';
	var roleBadge = row.querySelector('.authz-role-badge');
	if (roleBadge) {
		roleBadge.className = roleCls + ' authz-role-badge authz-role-editable';
		roleBadge.textContent = newRole;
	}

	var screensCell = row.querySelector('.authz-screens-cell');
	if (screensCell) {
		var sh = '';
		for (var i = 0; i < newScreens.length; i++) {
			sh += '<span class="authz-screen-badge">' + escapeHtml(newScreens[i]) + '</span>';
		}
		screensCell.innerHTML = sh;
	}
}

// ---- バックアップ実行 ----

function runBackupNow(btn) {
	if (btn) btn.disabled = true;
	fetch(monitorApiURL('backup_run'), {
		method: 'POST',
		credentials: 'same-origin',
		headers: { 'X-Requested-With': 'XMLHttpRequest' }
	})
		.then(function(r) { return r.json(); })
		.then(function(d) {
			alert(d.message || (d.ok ? 'バックアップが完了しました' : 'バックアップに失敗しました'));
		})
		.catch(function(e) { alert('エラー: ' + e); })
		.finally(function() { if (btn) btn.disabled = false; });
}

// ---- createFilterHeaderRow ----
// テーブルヘッダーのフィルター行生成ユーティリティ
// filterDefs: [
//   { type: 'input', dataFilter: 'proc', placeholder: 'プロセス名' },
//   { type: 'select', dataFilter: 'result', options: [{ value: '', label: '全て' }, ...] },
//   { type: 'count', colSpan: 3 }
// ]
// → <tr class="thead-filter-row">...</tr> を返す
function createFilterHeaderRow(filterDefs) {
	var row = document.createElement('tr');
	row.className = 'thead-filter-row';

	if (!Array.isArray(filterDefs)) {
		filterDefs = [];
	}

	filterDefs.forEach(function(def) {
		var th = document.createElement('th');
		if (def.colSpan) th.colSpan = def.colSpan;
		if (def.colClass) th.className = def.colClass;

		if (def.type === 'input') {
			var input = document.createElement('input');
			input.type = 'text';
			input.className = 'filter-input';
			input.setAttribute('data-filter', def.dataFilter);
			input.setAttribute('name', def.name || ('filter_' + String(def.dataFilter || 'value')));
			if (def.placeholder) input.placeholder = def.placeholder;
			input.setAttribute('autocapitalize', 'off');
			input.setAttribute('spellcheck', 'false');
			input.setAttribute('data-form-type', 'other');
			input.setAttribute('data-lpignore', 'true');
			input.setAttribute('data-1p-ignore', 'true');
			if (def.autocomplete === false || typeof def.autocomplete === 'undefined') {
				input.setAttribute('autocomplete', 'off');
			} else if (def.autocomplete) {
				input.setAttribute('autocomplete', def.autocomplete);
			}
			th.appendChild(input);
		} else if (def.type === 'select') {
			var select = document.createElement('select');
			select.className = 'filter-select';
			select.setAttribute('data-filter', def.dataFilter);
			if (def.dataFilterPartial) {
				select.setAttribute('data-filter-partial', def.dataFilterPartial);
			}

			if (Array.isArray(def.options)) {
				def.options.forEach(function(opt) {
					var optEl = document.createElement('option');
					optEl.value = opt.value || '';
					optEl.textContent = opt.label || '';
					select.appendChild(optEl);
				});
			}

			applyNoPasswordManagerAttrs(select);
			th.appendChild(select);
		} else if (def.type === 'count') {
			var span = document.createElement('span');
			span.className = 'filter-count';
			th.appendChild(span);
		} else if (def.type === 'checkbox') {
			// 空の <th> （checkbox列用）
		} else if (def.type === 'custom') {
			// カスタムHTMLコンテンツを直接設定
			if (def.content) {
				th.innerHTML = def.content;
			}
		} else if (def.type === 'empty') {
			// 空の <th> （スペーサー用）
		}

		row.appendChild(th);
	});

	return row;
}

// ========================================
// CPU / MEM Top カード（monitor + server_detail 共通）
// ========================================

function fmtBytes(b) {
	if (b == null || b === 0) return '0 B';
	var u = ['B','KB','MB','GB','TB'];
	var i = 0;
	while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
	return (i === 0 ? b : b.toFixed(1)) + ' ' + u[i];
}

function renderCPUTop(el, d) {
	if (!d || !d.top_cpu || d.top_cpu.length === 0) { el.innerHTML = '<p>データなし</p>'; return; }
	var html = '<table class="log-table"><thead>';
	html += '<tr><th>プロセス</th><th>PID</th><th class="col-count">CPU%</th><th class="col-count">MEM%</th><th class="col-count">メモリ</th></tr>';
	html += '</thead><tbody>';
	d.top_cpu.forEach(function(p) {
		html += '<tr data-proc="' + escHtml(p.command) + '">';
		html += '<td style="color:#3498db">' + escHtml(p.command) + '</td><td>' + escHtml(p.pid) + '</td>';
		html += '<td class="col-count" style="color:#e67e22;font-weight:600">' + escHtml(p.cpu) + '</td>';
		html += '<td class="col-count">' + escHtml(p.mem) + '</td>';
		html += '<td class="col-count">' + fmtBytes(p.rss) + '</td></tr>';
	});
	html += '</tbody></table>';
	el.innerHTML = html;
	var thead = el.querySelector('thead');
	if (thead) {
		var filterRow = createFilterHeaderRow([
			{ type: 'input', dataFilter: 'proc', placeholder: 'プロセス名絞り込み' },
			{ type: 'count', colSpan: 4 }
		]);
		thead.appendChild(filterRow);
	}
	setupCardFilter(el.querySelector('.thead-filter-row'), el);
	autoInitCardFromDataset(el.closest('section.card'), { total: d.top_cpu.length });
	addRowNumbers(el);
}

function renderMemTop(el, d) {
	if (!d || !d.top_mem || d.top_mem.length === 0) { el.innerHTML = '<p>データなし</p>'; return; }
	var html = '<table class="log-table"><thead>';
	html += '<tr><th>プロセス</th><th>PID</th><th class="col-count">CPU%</th><th class="col-count">MEM%</th><th class="col-count">メモリ</th></tr>';
	html += '</thead><tbody>';
	d.top_mem.forEach(function(p) {
		html += '<tr data-proc="' + escHtml(p.command) + '">';
		html += '<td style="color:#3498db">' + escHtml(p.command) + '</td><td>' + escHtml(p.pid) + '</td>';
		html += '<td class="col-count">' + escHtml(p.cpu) + '</td>';
		html += '<td class="col-count" style="color:#3498db;font-weight:600">' + escHtml(p.mem) + '</td>';
		html += '<td class="col-count">' + fmtBytes(p.rss) + '</td></tr>';
	});
	html += '</tbody></table>';
	el.innerHTML = html;
	var thead = el.querySelector('thead');
	if (thead) {
		var filterRow = createFilterHeaderRow([
			{ type: 'input', dataFilter: 'proc', placeholder: 'プロセス名絞り込み' },
			{ type: 'count', colSpan: 4 }
		]);
		thead.appendChild(filterRow);
	}
	setupCardFilter(el.querySelector('.thead-filter-row'), el);
	autoInitCardFromDataset(el.closest('section.card'), { total: d.top_mem.length });
	addRowNumbers(el);
}
