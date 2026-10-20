(function() {
	'use strict';

	CardRegistry.register('MemTop', {
		cardKey: 'MEM_TOP',
		fallbackId: 'sec-mem-top',
		apiFallback: 'processes',
		render: function(el, data) { renderMemTop(el, data); }
	});
})();
