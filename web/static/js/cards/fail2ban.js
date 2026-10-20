(function() {
	'use strict';

	CardRegistry.register('Fail2ban', {
		cardKey: 'FAIL2BAN',
		fallbackId: 'sec-fail2ban',
		apiFallback: 'fail2ban',
		render: function(el, data) { renderFail2ban(el, data); }
	});
})();
