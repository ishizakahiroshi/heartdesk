// heartdesk / Server Detail 共通画面スクリプト
// monitor.html 内の <script> をそのまま移設した版。
// 両画面で利用するため、server_detail.html 固有の HD_AGENT_ID / HD_AGENT_TYPE
// はインラインスクリプトで先行定義されている前提。monitor.html 側では未定義なので
// 以下でガードしておく。
if (typeof window.HD_AGENT_ID === 'undefined') window.HD_AGENT_ID = '';
if (typeof window.HD_AGENT_TYPE === 'undefined') window.HD_AGENT_TYPE = '';

// リソースグラフタブ切り替え（カード更新後も動作するようグローバル関数で定義）
function rgTabClick(btn) {
	var bar = btn.closest('.rg-tab-bar');
	if (!bar) return;
	bar.querySelectorAll('.rg-tab').forEach(function(t) { t.classList.remove('rg-tab-active'); });
	btn.classList.add('rg-tab-active');
	var target = btn.getAttribute('data-rg-tab');
	var card = btn.closest('section.card');
	var h24 = card && card.querySelector('#rg-panel-h24');
	var d7  = card && card.querySelector('#rg-panel-d7');
	if (h24) h24.style.display = target === 'h24' ? '' : 'none';
	if (d7)  d7.style.display  = target === 'd7'  ? '' : 'none';
}

document.addEventListener('DOMContentLoaded', function() {
	CardRegistry.autoLoadAll();

	// R2カード更新: card:refreshed イベントで fetchR2Metrics() を呼ぶ（PHP版 onCardRefreshed と同等）
	var secR2 = (typeof getMonitorCardId === 'function') ? getMonitorCardId('R2', 'sec-r2') : 'sec-r2';
	document.addEventListener('card:refreshed', function(e) {
		if (e.detail && e.detail.cardId === secR2) {
			if (typeof fetchR2Metrics === 'function') fetchR2Metrics();
		}
	});
});

