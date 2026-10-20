(function() {
	'use strict';

	CardRegistry.register('UserMgmt', {
		cardKey: 'USER_MGMT',
		fallbackId: 'sec-user-mgmt',
		apiFallback: 'user_mgmt',
		render: function(el, data) { renderUserMgmt(el, data); }
	});
})();
