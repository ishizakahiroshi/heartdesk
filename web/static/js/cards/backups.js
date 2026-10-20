(function() {
	'use strict';

	CardRegistry.register('Backups', {
		cardKey: 'DATABASE',
		fallbackId: 'sec-database',
		apiFallback: 'backups',
		render: function(el, data) { renderBackups(el, data); }
	});
})();
