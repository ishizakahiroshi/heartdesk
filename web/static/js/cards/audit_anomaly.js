(function() {
	'use strict';

	CardRegistry.register('AuditAnomaly', {
		cardKey: 'AUDIT_ANOMALY',
		fallbackId: 'sec-audit-anomaly',
		apiFallback: 'audit_anomaly',
		render: function(el, data) { renderAuditAnomaly(el, data); }
	});
})();
