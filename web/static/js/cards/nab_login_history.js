(function() {
	'use strict';

	CardRegistry.register('NabLoginHistory', {
		cardKey: 'SAB_LOGIN_HISTORY',
		fallbackId: 'sec-nab-login-history',
		apiFallback: 'nginx_login_histories',
		render: function(el, data) { renderNabLoginHistory(el, data && data.nab ? data.nab : data); }
	});
})();
