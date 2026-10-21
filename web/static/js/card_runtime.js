// heartdesk カードランタイム: CardRegistry
// 各カードの loadSection 呼び出しを宣言的に登録し、
// DOMContentLoaded で一括実行するための土台。
//
// 利用例:
//   CardRegistry.register('BanHeatmap', {
//     cardKey: 'BAN_HEATMAP',        // HD_CARD_IDS のキー
//     fallbackId: 'sec-ban-heatmap', // HD_CARD_IDS に無い場合のフォールバック
//     apiFallback: 'ban_heatmap',    // HD_CARD_APIS に無い場合のフォールバック
//     render: renderBanHeatmap,      // function(el, data)
//     screens: '*',                  // 'monitor' / 'server_detail' / '*'（省略時は '*'）
//     wrap: function(el, data) { ... } // 任意。render の代わりに呼ばれるカスタム loadSection ハンドラ
//   });
//
//   CardRegistry.autoLoadAll();      // DOMContentLoaded で呼び出す
//
// 非依存: loadSection / getMonitorCardId / getMonitorCardAPI は shared.js 側で定義済み。
// 非依存: HD_CARD_IDS / HD_CARD_APIS は layout.html で先行定義済み。

(function(global) {
	'use strict';

	var entries = [];

	function currentScreen() {
		// server_detail 画面では HD_AGENT_ID が非空文字で先行注入されている。
		// monitor 画面では空文字（layout.html 経由 or monitor_page.js のガード）。
		if (typeof global.HD_AGENT_ID !== 'undefined' && global.HD_AGENT_ID) {
			return 'server_detail';
		}
		return 'monitor';
	}

	function matchesScreen(screens, screen) {
		if (!screens || screens === '*') return true;
		if (typeof screens === 'string') return screens === screen;
		if (Array.isArray(screens)) return screens.indexOf(screen) >= 0;
		return true;
	}

	function resolveCardId(entry) {
		if (entry.cardKey && typeof getMonitorCardId === 'function') {
			return getMonitorCardId(entry.cardKey, entry.fallbackId || '');
		}
		return entry.fallbackId || '';
	}

	function resolveApi(entry, cardId) {
		if (typeof getMonitorCardAPI === 'function') {
			return getMonitorCardAPI(cardId, entry.apiFallback || '');
		}
		return entry.apiFallback || '';
	}

	function register(rendererName, spec) {
		if (!spec || typeof spec !== 'object') return;
		if (!spec.render && !spec.wrap) {
			// どちらもない登録はスキップ（呼び出し側の定義ミス検知用）
			console.warn('[CardRegistry] "' + rendererName + '" には render または wrap が必要です');
			return;
		}
		entries.push({
			name: rendererName,
			cardKey: spec.cardKey || '',
			fallbackId: spec.fallbackId || '',
			apiFallback: spec.apiFallback || '',
			// sectionId を直接指定したい場合（例: async-backups のような固定ルート要素）は
			// sectionId を渡す。未指定の場合は cardId + '-content' を組み立てる。
			sectionId: spec.sectionId || '',
			render: spec.render || null,
			wrap: spec.wrap || null,
			screens: spec.screens || '*'
		});
	}

	function autoLoadAll() {
		if (typeof loadSection !== 'function') {
			console.error('[CardRegistry] loadSection が未定義です（shared.js の読み込み順を確認してください）');
			return;
		}
		var screen = currentScreen();
		for (var i = 0; i < entries.length; i++) {
			var e = entries[i];
			if (!matchesScreen(e.screens, screen)) continue;
			var cardId = resolveCardId(e);
			if (!cardId && !e.sectionId) continue;
			var api = resolveApi(e, cardId);
			var contentId = e.sectionId || (cardId + '-content');
			var handler = e.wrap || e.render;
			loadSection(api, contentId, handler);
		}
	}

	function list() {
		// デバッグ用: 登録済みエントリを読み取り専用でコピーして返す
		return entries.slice();
	}

	function clear() {
		// テスト/ホットリロード用途
		entries.length = 0;
	}

	global.CardRegistry = {
		register: register,
		autoLoadAll: autoLoadAll,
		list: list,
		clear: clear
	};
})(window);
