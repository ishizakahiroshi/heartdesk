(function() {
	'use strict';

	CardRegistry.register('Nc4xxAccess', {
		cardKey: 'NC4XX_ACCESS',
		fallbackId: 'sec-nc4xx-access',
		apiFallback: 'nc4xx_access',
		render: function(el, data) { renderNC4xxAccess(el, data); }
	});
})();
