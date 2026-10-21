// heartdesk カード: SSL 証明書状態 (sec-ssl)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'sec-ssl';

	// ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== "undefined" && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? "" : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	// ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el, agentID) {
		window.loadJsonCard(el, 'ssl', render, { agentID: agentID });
	}

	function daysClass(days) {
		if (days <= 7) return 'svc-down';
		if (days <= 30) return 'svc-warn';
		return 'svc-ok';
	}

	function leClass(cls) {
		if (cls === 'danger') return 'svc-down';
		if (cls === 'warning') return 'svc-warn';
		return 'svc-ok';
	}

	function render(el, data) {
		if (!data || data.unavailable) {
			el.innerHTML = '<p class="empty">このエージェントでは SSL 情報を取得できません</p>';
			return;
		}

		var html = '<div class="svc-grid">';

		// 有効期限
		if (data.ssl_expiry) {
			html += '<div class="svc-box ' + daysClass(data.ssl_days) + '">'
				+ '<div class="svc-row"><span class="svc-dot"></span><span class="svc-name">証明書有効期限</span></div>'
				+ '<span class="svc-st">' + esc(data.ssl_expiry) + '</span>'
				+ '</div>';
		}

		// 残日数
		if (data.ssl_expiry) {
			html += '<div class="svc-box ' + daysClass(data.ssl_days) + '">'
				+ '<div class="svc-row"><span class="svc-dot"></span><span class="svc-name">残り日数</span></div>'
				+ '<span class="svc-st">' + data.ssl_days + ' 日</span>'
				+ '</div>';
		}

		// 更新推奨日
		if (data.ssl_renewal_date) {
			html += '<div class="svc-box svc-ok">'
				+ '<div class="svc-row"><span class="svc-dot"></span><span class="svc-name">更新推奨日</span></div>'
				+ '<span class="svc-st">' + esc(data.ssl_renewal_date) + '</span>'
				+ '</div>';
		}

		// Let's Encrypt 状態
		if (data.le_status) {
			html += '<div class="svc-box ' + leClass(data.le_status_class) + '">'
				+ '<div class="svc-row"><span class="svc-dot"></span><span class="svc-name">Let\'s Encrypt</span></div>'
				+ '<span class="svc-st">' + esc(data.le_status) + '</span>'
				+ '</div>';
		}

		html += '</div>';

		// 次回トリガー / 最終更新
		if (data.le_last_date) {
			html += '<p class="stat-sub" style="margin-top:8px;">' + esc(data.le_last_date) + '</p>';
		}

		el.innerHTML = html;
	}

	CardRegistry.register('SSL', {
		cardKey:    'SSL',
		fallbackId: CARD_ID,
		apiFallback: 'ssl',
		wrap: function(el, data, meta) {
			var agentID = meta && meta.agentID ? meta.agentID : '';
			if (data && typeof data.ssl_days !== 'undefined') {
				render(el, data);
			} else {
				load(el, agentID);
			}
		},
		// monitor / server_detail 両画面で読み込む（server_detail のスピナー固定対策）。
		// backend GetSSL は agentID 指定で agent の ssl collector を返すため両画面で動作する。
		screens: '*'
	});
})();
