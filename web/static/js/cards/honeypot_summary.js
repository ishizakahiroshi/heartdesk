// heartdesk カード: ハニーポット概要 (sec-honeypot-summary)
// Phase 2b (C3): monitor_page.js から切り出したカード単位モジュール。
// 依存: shared.js の escHtml / HP_TRIGGER_LABELS、card_runtime.js の CardRegistry。

(function() {
	'use strict';

	function renderHoneypotSummary(el, d) {
		var s = d && d.summary ? d.summary : d;
		if (!s || s.count_30d == null) { el.innerHTML = '<p>データなし</p>'; return; }
		var html = '<div class="hp-summary-grid">';
		html += '<div class="hp-stat-box"><span class="hp-stat-val">' + (s.count_24h||0) + '</span><span class="hp-stat-label">24時間</span></div>';
		html += '<div class="hp-stat-box"><span class="hp-stat-val">' + (s.count_7d||0) + '</span><span class="hp-stat-label">7日間</span></div>';
		html += '<div class="hp-stat-box"><span class="hp-stat-val">' + (s.count_30d||0) + '</span><span class="hp-stat-label">30日間</span></div>';
		html += '<div class="hp-stat-box"><span class="hp-stat-val">' + (s.unique_ips_24h||0) + '</span><span class="hp-stat-label">ユニークIP (24h)</span></div>';
		html += '<div class="hp-stat-box"><span class="hp-stat-val">' + (s.new_ips_today||0) + '</span><span class="hp-stat-label">新規IP (今日)</span></div>';
		html += '</div>';
		var triggers = s.top_triggers || [];
		if (triggers.length) {
			html += '<div class="hp-trigger-list">';
			var total = 0;
			for (var ti = 0; ti < triggers.length; ti++) total += triggers[ti].count;
			for (var ti = 0; ti < triggers.length; ti++) {
				var t = triggers[ti];
				var pct = total > 0 ? Math.round(t.count / total * 100) : 0;
				var label = HP_TRIGGER_LABELS[t.trigger] || t.trigger;
				html += '<div class="hp-trigger-row">'
					+ '<span class="hp-trigger-name">' + escHtml(label) + '</span>'
					+ '<div class="hp-trigger-bar-wrap"><div class="hp-trigger-bar" style="width:' + pct + '%"></div></div>'
					+ '<span class="hp-trigger-count">' + t.count + '</span>'
					+ '</div>';
			}
			html += '</div>';
		}
		el.innerHTML = html;
	}

	window.renderHoneypotSummary = renderHoneypotSummary;

	CardRegistry.register('HoneypotSummary', {
		cardKey: 'HONEYPOT_SUMMARY',
		fallbackId: 'sec-honeypot-summary',
		apiFallback: 'honeypot_all',
		render: function(el, d) { renderHoneypotSummary(el, d); }
	});
})();
