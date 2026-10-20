(function() {
	'use strict';

	CardRegistry.register('NcStorage', {
		cardKey: 'NC_STORAGE',
		fallbackId: 'sec-nc-storage',
		apiFallback: 'nc_storage',
		render: function(el, data) { renderNcStorageCard(el, data, null); }
	});
})();
