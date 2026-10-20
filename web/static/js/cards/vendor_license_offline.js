// heartdesk カード: オフラインライセンス発行 (vendor-license-offline)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-license-offline';

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	// C9-C4: ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_license_offline', render, { includeAgent: false });
	}

	function render(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}
		var agents = (data && data.agents) || [];
		var expiryDays = (data && data.expiry_days) || 365;
		var graceDays  = (data && data.grace_days)  || 7;
		var maxAgents  = (data && data.max_agents)  || 1;

		var agentOpts = '<option value="">Agent IDを入力 or 選択...</option>';
		for (var i = 0; i < agents.length; i++) {
			agentOpts += '<option value="' + esc(agents[i]) + '">' + esc(agents[i]) + '</option>';
		}

		el.innerHTML = '<div class="vlo-form">'
			+ '<div class="vlm-form-row">'
			+ '<label>Agent ID</label>'
			+ '<select id="vlo-agent" class="filter-select"><option value="">入力してください</option>' + agentOpts + '</select>'
			+ '<input id="vlo-agent-custom" type="text" class="filter-input" placeholder="または直接入力" style="margin-top:4px">'
			+ '</div>'
			+ '<div class="vlm-form-row">'
			+ '<label>有効期限（日）</label>'
			+ '<input id="vlo-expiry" type="number" class="filter-input" value="' + expiryDays + '" min="1" max="3650">'
			+ '</div>'
			+ '<div class="vlm-form-row">'
			+ '<label>猶予期間（日）</label>'
			+ '<input id="vlo-grace" type="number" class="filter-input" value="' + graceDays + '" min="0" max="90">'
			+ '</div>'
			+ '<div class="vlm-form-row">'
			+ '<label>最大 Agent 数</label>'
			+ '<input id="vlo-max" type="number" class="filter-input" value="' + maxAgents + '" min="1" max="100">'
			+ '</div>'
			+ '<div class="vlm-form-actions">'
			+ '<button type="button" id="vlo-generate-btn" class="btn-primary btn-sm">オフラインライセンス発行</button>'
			+ '</div>'
			+ '<div id="vlo-result"></div>'
			+ '</div>';

		var btn = el.querySelector('#vlo-generate-btn');
		if (btn) {
			btn.addEventListener('click', function() {
				var selectEl = el.querySelector('#vlo-agent');
				var customEl = el.querySelector('#vlo-agent-custom');
				var agentID  = (customEl && customEl.value.trim()) || (selectEl && selectEl.value) || '';
				if (!agentID) { showResult(el, false, 'agent_id を入力してください'); return; }

				var expiryEl = el.querySelector('#vlo-expiry');
				var graceEl  = el.querySelector('#vlo-grace');
				var maxEl    = el.querySelector('#vlo-max');

				btn.disabled = true;
				var body = new URLSearchParams({
					agent_id:    agentID,
					expiry_days: (expiryEl ? expiryEl.value : '365'),
					grace_days:  (graceEl  ? graceEl.value  : '7'),
					max_agents:  (maxEl    ? maxEl.value    : '1')
				}).toString();

				fetch(base() + '/?api=vendor_license_offline_generate', {
					method: 'POST',
					headers: {
						'X-Requested-With': 'XMLHttpRequest',
						'Content-Type': 'application/x-www-form-urlencoded'
					},
					body: body
				})
					.then(function(r) { return r.json(); })
					.then(function(res) {
						btn.disabled = false;
						if (res.ok && res.data) {
							triggerDownload(res);
							showResult(el, true, res.message || '発行しました（ダウンロードを開始します）');
						} else {
							showResult(el, false, res.message || '発行に失敗しました');
						}
					})
					.catch(function(e) {
						btn.disabled = false;
						showResult(el, false, e.message);
					});
			});
		}
	}

	function showResult(el, ok, msg) {
		var r = el.querySelector('#vlo-result');
		if (!r) return;
		r.innerHTML = '<p class="' + (ok ? 'vlm-result-ok' : 'error') + '">' + esc(msg) + '</p>';
	}

	function triggerDownload(res) {
		var binary = atob(res.data);
		var bytes  = new Uint8Array(binary.length);
		for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
		var blob = new Blob([bytes], {type: 'application/json'});
		var url  = URL.createObjectURL(blob);
		var a    = document.createElement('a');
		a.href = url;
		a.download = res.filename || 'license.hdlic';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	CardRegistry.register('VendorLicenseOffline', {
		cardKey:    'VENDOR_LICENSE_OFFLINE',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_license_offline',
		wrap: function(el, data) {
			if (data && data.agents) {
				render(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
