(function() {
	'use strict';

	CardRegistry.register('IPMgmt', {
		cardKey: 'IP_MGMT',
		fallbackId: 'sec-ip-mgmt',
		apiFallback: 'ip_mgmt',
		render: function(el, data) { renderIPMgmt(el, data); }
	});
})();
