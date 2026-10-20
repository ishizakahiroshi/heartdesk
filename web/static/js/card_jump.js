// =============================================================================
// card_jump.js — 画面右下に「前のカードへ▲ / 次のカードへ▼」フローティングボタン
//   - ビューポート固定、スクロール追従
//   - 現在のスクロール位置を基準に直近の前後 .card の先頭へスムーススクロール
// =============================================================================
(function() {
	'use strict';

	function getCards() {
		// 折りたたみ済みカードもジャンプ先として有効
		return Array.prototype.slice.call(document.querySelectorAll('section.card[id]'));
	}

	// 現在のスクロール位置を基準に「前の行 / 次の行」の先頭カードを返す
	// 横並びカード（同じ Y 座標の行）は1つの行として扱う
	function findPrevNext() {
		var cards = getCards();
		if (!cards.length) return { prev: null, next: null };
		var anchor = window.scrollY + 80; // ヘッダ分のオフセット
		var ROW_THRESHOLD = 20; // px。これ以内のtop差は同じ行とみなす

		// 各カードの絶対 top
		var tops = cards.map(function(c) {
			return c.getBoundingClientRect().top + window.scrollY;
		});

		// 現在の行の代表 top（anchor 以下で最大のもの）
		var currentTop = -Infinity;
		for (var i = 0; i < tops.length; i++) {
			if (tops[i] <= anchor + 5 && tops[i] > currentTop) currentTop = tops[i];
		}
		if (currentTop === -Infinity) {
			// anchor より上にカードがない → next は最初のカード
			return { prev: null, next: cards[0] };
		}

		// prev = currentTop より ROW_THRESHOLD 以上小さい top のうち最大、それを持つ最初のカード
		// next = currentTop より ROW_THRESHOLD 以上大きい top のうち最小、それを持つ最初のカード
		var prevTop = -Infinity, nextTop = Infinity;
		for (var j = 0; j < tops.length; j++) {
			if (tops[j] < currentTop - ROW_THRESHOLD && tops[j] > prevTop) prevTop = tops[j];
			if (tops[j] > currentTop + ROW_THRESHOLD && tops[j] < nextTop) nextTop = tops[j];
		}
		function firstCardAt(t) {
			for (var k = 0; k < tops.length; k++) {
				if (Math.abs(tops[k] - t) < 1) return cards[k];
			}
			return null;
		}
		return {
			prev: prevTop === -Infinity ? null : firstCardAt(prevTop),
			next: nextTop === Infinity ? null : firstCardAt(nextTop)
		};
	}

	function scrollToCard(card) {
		if (!card) return;
		var top = card.getBoundingClientRect().top + window.scrollY - 60;
		window.scrollTo({ top: top, behavior: 'smooth' });
	}

	function build() {
		if (document.getElementById('card-jump-nav')) return;
		var wrap = document.createElement('div');
		wrap.id = 'card-jump-nav';
		wrap.innerHTML =
			'<button type="button" class="btn-card-jump" data-dir="prev" title="上のカードに移動">▲ 上のカードに移動</button>' +
			'<button type="button" class="btn-card-jump" data-dir="next" title="下のカードに移動">▼ 下のカードに移動</button>';
		document.body.appendChild(wrap);

		wrap.addEventListener('click', function(ev) {
			var btn = ev.target.closest('.btn-card-jump');
			if (!btn) return;
			var pn = findPrevNext();
			scrollToCard(btn.dataset.dir === 'prev' ? pn.prev : pn.next);
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', build);
	} else {
		build();
	}
})();
