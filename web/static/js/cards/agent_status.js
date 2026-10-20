// SAB カード: Agent 死活監視 (sec-agent-status)
// メモ列のロード・インライン編集を担当。
// Goテンプレートで静的描画されるカードのため、CardRegistry.wrap は使わず
// DOMContentLoaded で直接初期化する。
// 依存: shared.js の monitorApiURL / getAppBase。

(function() {
	'use strict';

	// -------------------------------------------------------------------------
	// MonitorAPIBase の構築
	// IH_APP_BASE = MonitorBase (/monitor or /sab/monitor 等)
	// MonitorAPIBase = /api/monitor or /sab/api/monitor
	// -------------------------------------------------------------------------

	function agentMemoApiBase() {
		var base = (typeof IH_APP_BASE !== 'undefined' && IH_APP_BASE) ? IH_APP_BASE : '';
		return base.replace(/\/monitor$/, '/api/monitor');
	}

	// -------------------------------------------------------------------------
	// POST ヘルパー（JSON body、fetchラッパーがCSRF自動付与）
	// -------------------------------------------------------------------------

	function agentMemoPost(agentID, memo, onOK, onErr) {
		// 配線済みの dispatchAction 経路（?api=agent_memo_save）へ POST する。
		// この経路は RequireScreen ミドルウェアで CSRF 検証され、グローバル fetch ラッパーが
		// X-CSRF-Token / X-Requested-With を自動付与する。旧 /api/monitor/agent-memo は
		// mux に未登録のため使わない。
		var url = monitorApiURL('agent_memo_save', false);
		fetch(url, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Requested-With': 'XMLHttpRequest'
			},
			body: JSON.stringify({ agent_id: agentID, memo: memo })
		})
		.then(function(r) { return r.json(); })
		.then(function(d) {
			if (d.status === 'ok' || d.ok) { onOK(d); }
			else { onErr(d.message || '保存に失敗しました'); }
		})
		.catch(function(e) { onErr('通信エラー: ' + e); });
	}

	// -------------------------------------------------------------------------
	// メモ一覧を取得してセルに反映
	// -------------------------------------------------------------------------

	function loadMemos(section) {
		var url = monitorApiURL('agent_memo', false);
		fetch(url)
		.then(function(r) { return r.json(); })
		.then(function(memos) {
			if (!memos || typeof memos !== 'object') return;
			var cells = section.querySelectorAll('.agent-memo-cell[data-agent-id]');
			cells.forEach(function(cell) {
				var id = cell.getAttribute('data-agent-id');
				if (id && memos[id]) {
					cell.textContent = memos[id];
				}
			});
		})
		.catch(function() {
			// メモ取得失敗は無視（セルが空のままになる）
		});
	}

	// -------------------------------------------------------------------------
	// インライン編集
	// -------------------------------------------------------------------------

	function initMemoEdit(cell) {
		if (cell.querySelector('input')) return; // 二重起動防止
		var agentID = cell.getAttribute('data-agent-id');
		if (!agentID) return;
		var current = cell.textContent;

		var input = document.createElement('input');
		input.type = 'text';
		input.value = current;
		input.className = 'filter-input agent-memo-input';
		input.style.width = '100%';
		input.style.minWidth = '6em';
		cell.textContent = '';
		cell.appendChild(input);
		input.focus();
		input.select();

		var committed = false;

		function commit() {
			if (committed) return;
			committed = true;
			var newVal = input.value;
			if (newVal === current) {
				cell.textContent = current;
				return;
			}
			cell.textContent = newVal + ' …';
			agentMemoPost(agentID, newVal,
				function() {
					cell.textContent = newVal;
				},
				function(msg) {
					cell.textContent = current;
					alert('メモの保存に失敗しました: ' + msg);
				}
			);
		}

		input.addEventListener('blur', commit);
		input.addEventListener('keydown', function(ev) {
			if (ev.key === 'Enter') { ev.preventDefault(); input.blur(); }
			if (ev.key === 'Escape') {
				committed = true;
				cell.textContent = current;
			}
		});
	}

	// -------------------------------------------------------------------------
	// カード初期化
	// -------------------------------------------------------------------------

	function initAgentStatusCard() {
		var cardId = (typeof getMonitorCardId === 'function')
			? getMonitorCardId('AGENT_STATUS', 'sec-agent-status')
			: 'sec-agent-status';
		var section = document.getElementById(cardId);
		if (!section) return;

		// メモをロード
		loadMemos(section);

		// 二重バインド防止
		if (section.dataset.agentMemoBound) return;
		section.dataset.agentMemoBound = '1';

		// イベント委譲：.agent-memo-cell クリックでインライン編集
		section.addEventListener('click', function(e) {
			var cell = e.target.closest && e.target.closest('.agent-memo-cell[data-agent-id]');
			if (cell && section.contains(cell)) {
				initMemoEdit(cell);
			}
		});
	}

	// -------------------------------------------------------------------------
	// DOMContentLoaded で初期化
	// -------------------------------------------------------------------------

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initAgentStatusCard);
	} else {
		initAgentStatusCard();
	}

})();
