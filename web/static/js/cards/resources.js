(function() {
	'use strict';

	function resourcesWrap(el, data) {
		renderResources(el, data);
		loadSection('ssl', 'async-ssl', renderSsl);
		var diskUrl = getAppBase() + '/?api=disk' + (IH_AGENT_ID ? '&agent=' + encodeURIComponent(IH_AGENT_ID) : '');
		fetch(diskUrl).then(function(r) { return r.json(); }).then(function(d) {
			renderDiskResources(d);
			var dbListEl = document.getElementById('db-list-display');
			if (dbListEl && d.db_list && d.db_list.length > 0) {
				var dbHtml = '<span class="db-info-label">バックアップ対象DB:</span>';
				for (var i = 0; i < d.db_list.length; i++) {
					dbHtml += ' <code>' + escHtml(d.db_list[i].name) + '</code>';
					dbHtml += '<span class="typo-sub-weak"> (' + escHtml(String(d.db_list[i].size)) + ' MB)</span>';
				}
				dbListEl.innerHTML = dbHtml;
			}
		}).catch(function() {});
	}

	CardRegistry.register('Resources', {
		cardKey: 'RESOURCES',
		fallbackId: 'sec-resources',
		apiFallback: 'resources',
		wrap: resourcesWrap
	});
})();
