(function() {
	'use strict';

	CardRegistry.register('HoneypotAccess', {
		cardKey: 'HONEYPOT_ACCESS',
		fallbackId: 'sec-honeypot-access',
		apiFallback: 'honeypot_all',
		render: function(el, data) { renderHoneypotAccess(el, data); }
	});
})();
