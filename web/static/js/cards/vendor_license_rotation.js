// heartdesk カード: 署名鍵ローテーション (vendor-license-rotation)
// 依存: shared.js の escHtml / getAppBase、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var CARD_ID = 'vendor-license-rotation';

	// ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	// ローカル doFetch を撤去し共通 loadJsonCard に統一。
	function load(el) {
		window.loadJsonCard(el, 'vendor_license_rotation', render, { includeAgent: false });
	}

	function render(el, data) {
		if (data && data.error) {
			el.innerHTML = '<p class="section-error">' + esc(data.error) + '</p>';
			return;
		}
		var activeKID = (data && data.active_kid) || '';
		var keys      = (data && data.keys) || [];

		var html = '';

		// 現在の鍵状態テーブル
		html += '<p class="vlr-active-label">現在の active_kid: <code class="mono">' + esc(activeKID || '（未設定）') + '</code></p>';
		if (keys.length) {
			var rows = '';
			for (var i = 0; i < keys.length; i++) {
				var k = keys[i];
				var stateClass = 'vlr-state-' + (k.state || 'unknown');
				var isActive   = k.kid === activeKID;
				rows += '<tr' + (isActive ? ' class="vlr-row-active"' : '') + '>'
					+ '<td class="mono">' + esc(k.kid) + (isActive ? ' <span class="vlr-active-mark">★</span>' : '') + '</td>'
					+ '<td><span class="vlr-state ' + stateClass + '">' + esc(k.state || 'unknown') + '</span></td>'
					+ '<td class="mono">' + esc(k.fingerprint || '-') + '</td>'
					+ '<td class="mono">' + esc(k.retired_at || '-') + '</td>'
					+ '</tr>';
			}
			html += '<div class="table-scroll"><table class="log-table vlr-table">'
				+ '<thead><tr><th>KID</th><th>状態</th><th>フィンガープリント</th><th>退役日時</th></tr></thead>'
				+ '<tbody>' + rows + '</tbody>'
				+ '</table></div>';
		} else {
			html += '<p class="empty">署名鍵が設定されていません（secrets.toml の [vendor_license.signing_keys] を確認してください）</p>';
		}

		// 新鍵生成
		html += '<div class="vlr-section">'
			+ '<h4 class="vlr-section-title">新しい署名鍵を生成</h4>'
			+ '<p class="vlr-hint">生成後に表示される情報を secrets.toml に追記してください。</p>'
			+ '<button type="button" id="vlr-gen-btn" class="btn-primary btn-sm">新鍵ペアを生成</button>'
			+ '<div id="vlr-gen-result"></div>'
			+ '</div>';

		// activate / retire の手順説明
		html += '<div class="vlr-section">'
			+ '<h4 class="vlr-section-title">active_kid の切替（手動）</h4>'
			+ '<p class="vlr-hint">secrets.toml を以下のように編集して Monitor を再起動してください。</p>'
			+ '<pre class="vlr-code">[vendor_license]\nactive_kid = "&lt;新しいkid&gt;"\n\n[vendor_license.signing_keys.&lt;新しいkid&gt;]\nstate = "active"\n\n[vendor_license.signing_keys.&lt;旧kid&gt;]\nstate = "valid"</pre>'
			+ '</div>'
			+ '<div class="vlr-section">'
			+ '<h4 class="vlr-section-title">旧鍵の退役（手動）</h4>'
			+ '<p class="vlr-hint">全 Agent が新しい KID の JWT に移行済みであることを確認してから実行してください。retired 後は該当 KID で署名された JWT の検証が拒否されます。</p>'
			+ '<pre class="vlr-code">[vendor_license.signing_keys.&lt;退役するkid&gt;]\nstate = "retired"\nretired_at = "2026-01-01T00:00:00+09:00"</pre>'
			+ '</div>';

		el.innerHTML = html;

		var genBtn = el.querySelector('#vlr-gen-btn');
		if (genBtn) {
			genBtn.addEventListener('click', function() {
				genBtn.disabled = true;
				fetch(base() + '/?api=vendor_license_rotation_generate', {
					method: 'POST',
					headers: {
						'X-Requested-With': 'XMLHttpRequest',
						'Content-Type': 'application/x-www-form-urlencoded'
					},
					body: ''
				})
					.then(function(r) { return r.json(); })
					.then(function(res) {
						genBtn.disabled = false;
						showGenResult(el, res);
					})
					.catch(function(e) {
						genBtn.disabled = false;
						var r = el.querySelector('#vlr-gen-result');
						if (r) r.innerHTML = '<p class="section-error">' + esc(e.message) + '</p>';
					});
			});
		}
	}

	function showGenResult(el, res) {
		var r = el.querySelector('#vlr-gen-result');
		if (!r) return;
		if (!res.ok) {
			r.innerHTML = '<p class="section-error">' + esc(res.message || '生成に失敗しました') + '</p>';
			return;
		}
		var kid      = res.kid || '';
		var pubB64   = res.pub_b64 || '';
		var privB64  = res.priv_b64 || '';
		var tomlSnip = '[vendor_license.signing_keys.' + kid + ']\n'
			+ 'private_key_b64 = "' + privB64 + '"\n'
			+ 'public_key_b64  = "' + pubB64  + '"\n'
			+ 'state           = "valid"';
		r.innerHTML = '<div class="vlr-gen-result">'
			+ '<p class="vlm-result-ok">✔ 鍵を生成しました（kid=' + esc(kid) + '）</p>'
			+ '<p class="vlr-hint">以下を secrets.toml に追記してください（秘密鍵は一度だけ表示されます）：</p>'
			+ '<pre class="vlr-code" id="vlr-toml-snip">' + esc(tomlSnip) + '</pre>'
			+ '<button type="button" id="vlr-copy-toml" class="btn-secondary btn-sm" style="margin-top:4px">コピー</button>'
			+ '</div>';
		var copyBtn = r.querySelector('#vlr-copy-toml');
		if (copyBtn) {
			copyBtn.addEventListener('click', function() {
				if (navigator.clipboard) {
					navigator.clipboard.writeText(tomlSnip).then(function() { copyBtn.textContent = 'コピーしました'; });
				} else {
					var ta = document.createElement('textarea');
					ta.value = tomlSnip;
					document.body.appendChild(ta);
					ta.select();
					document.execCommand('copy');
					document.body.removeChild(ta);
					copyBtn.textContent = 'コピーしました';
				}
			});
		}
	}

	CardRegistry.register('VendorLicenseRotation', {
		cardKey:    'VENDOR_LICENSE_ROTATION',
		fallbackId: CARD_ID,
		apiFallback: 'vendor_license_rotation',
		wrap: function(el, data) {
			if (data && data.keys) {
				render(el, data);
			} else {
				load(el);
			}
		},
		screens: 'monitor'
	});
})();
