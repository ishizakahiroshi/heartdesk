(function() {
	'use strict';

	CardRegistry.register('LoginHistory', {
		cardKey: 'HEARTDESK_LOGIN_HISTORY',
		fallbackId: 'sec-login-history',
		apiFallback: 'nginx_login_histories',
		render: function(el, data) { renderAppLoginHistory(el, data && data.heartdesk ? data.heartdesk : data); }
	});
})();
