(function() {
	'use strict';

	CardRegistry.register('PmaLoginHistory', {
		cardKey: 'PHPMYADMIN_LOGIN_HISTORY',
		fallbackId: 'sec-phpmyadmin-login-history',
		apiFallback: 'nginx_login_histories',
		render: function(el, data) { renderPhpmyadminLoginHistory(el, data && data.phpmyadmin ? data.phpmyadmin : data); }
	});
})();
