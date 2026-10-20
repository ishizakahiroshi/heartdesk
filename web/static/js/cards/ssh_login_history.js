(function() {
	'use strict';

	CardRegistry.register('SSHLoginHistory', {
		cardKey: 'SSH_LOGIN_HISTORY',
		fallbackId: 'sec-ssh-login-history',
		apiFallback: 'ssh_login_history',
		render: function(el, data) { renderSshLoginHistory(el, data); }
	});
})();
