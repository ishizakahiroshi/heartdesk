(function() {
	'use strict';

	CardRegistry.register('CPUTop', {
		cardKey: 'CPU_TOP',
		fallbackId: 'sec-cpu-top',
		apiFallback: 'processes',
		render: function(el, data) { renderCPUTop(el, data); }
	});
})();
