(function() {
	'use strict';

	CardRegistry.register('NcLogin', {
		cardKey: 'NC_LOGIN',
		fallbackId: 'sec-nc-login',
		apiFallback: 'nc_login',
		render: function(el, data) { renderNcLogin(el, data); }
	});
})();
