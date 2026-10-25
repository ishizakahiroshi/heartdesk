(function() {
	'use strict';

	CardRegistry.register('LoginHistory', {
		cardKey: 'HEARTDESK_LOGIN_HISTORY',
		fallbackId: 'sec-login-history',
		apiFallback: 'nginx_login_histories',
		render: function(el, data) { var key = (typeof HD_IDENTITY !== 'undefined' && HD_IDENTITY.LoginHistorySourceKey) || 'heartdesk'; renderAppLoginHistory(el, data && data[key] ? data[key] : data); }
	});
})();
