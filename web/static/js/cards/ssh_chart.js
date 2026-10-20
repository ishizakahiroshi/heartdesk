(function() {
	'use strict';

	CardRegistry.register('SSHChart', {
		cardKey: 'SSH_CHART',
		fallbackId: 'sec-ssh-chart',
		apiFallback: 'ssh_chart',
		render: function(el, data) { renderSSHChart(el, data); }
	});
})();
