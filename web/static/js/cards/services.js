(function() {
	'use strict';

	CardRegistry.register('Services', {
		cardKey: 'SERVICES',
		fallbackId: 'sec-services',
		apiFallback: 'services',
		render: function(el, data) { renderServices(el, data); }
	});
})();
