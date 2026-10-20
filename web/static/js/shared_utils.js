// shared_utils.js - pure/shared frontend helpers loaded before shared.js

function formatBytes(bytes) {
	if (bytes === 0) return '0 B';
	var k = 1024;
	var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	var i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatCount(value) {
	var num = Number(String(value).replace(/,/g, ''));
	if (!isFinite(num)) return String(value);
	return Math.round(num).toLocaleString('ja-JP');
}

function formatDateTime(dt) {
	var w = ['日', '月', '火', '水', '木', '金', '土'][dt.getDay()];
	var y = dt.getFullYear();
	var m = ('0' + (dt.getMonth() + 1)).slice(-2);
	var d = ('0' + dt.getDate()).slice(-2);
	var hh = ('0' + dt.getHours()).slice(-2);
	var mm = ('0' + dt.getMinutes()).slice(-2);
	var ss = ('0' + dt.getSeconds()).slice(-2);
	return y + '-' + m + '-' + d + '(' + w + ') ' + hh + ':' + mm + ':' + ss;
}

function formatDisplayDateTime(value, emptyText) {
	var fallback = (typeof emptyText === 'string') ? emptyText : '';
	if (value === null || value === undefined) return fallback;
	if (value instanceof Date) return formatDateTime(value);
	var s = String(value).trim();
	if (!s) return fallback;
	s = s.replace(/^\[|\]$/g, '');
	if (/[Zz]$|[+\-]\d{2}:\d{2}$/.test(s)) {
		var dtTz = new Date(s);
		if (!isNaN(dtTz.getTime())) return formatDateTime(dtTz);
	}
	var m = s.match(/(\d{4})[-\/](\d{2})[-\/](\d{2})[T\s]+(\d{2}):(\d{2})(?::(\d{2}))?/);
	if (m) {
		var y = parseInt(m[1], 10);
		var mo = parseInt(m[2], 10);
		var d = parseInt(m[3], 10);
		var w = ['日', '月', '火', '水', '木', '金', '土'][new Date(y, mo - 1, d).getDay()];
		return m[1] + '-' + m[2] + '-' + m[3] + '(' + w + ') ' + m[4] + ':' + m[5] + ':' + (m[6] || '00');
	}
	var mDate = s.match(/^(\d{4})[-\/](\d{2})[-\/](\d{2})$/);
	if (mDate) {
		var yDate = parseInt(mDate[1], 10);
		var moDate = parseInt(mDate[2], 10);
		var dDate = parseInt(mDate[3], 10);
		var wDate = ['日', '月', '火', '水', '木', '金', '土'][new Date(yDate, moDate - 1, dDate).getDay()];
		return mDate[1] + '-' + mDate[2] + '-' + mDate[3] + '(' + wDate + ')';
	}
	var m2 = s.match(/(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+[+\-]\d{4})?/);
	if (m2) {
		var mm = {
			Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
			Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12'
		};
		var mo2 = mm[m2[2]];
		if (mo2) {
			var dd = ('0' + parseInt(m2[1], 10)).slice(-2);
			var y2 = parseInt(m2[3], 10);
			var w2 = ['日', '月', '火', '水', '木', '金', '土'][new Date(y2, parseInt(mo2, 10) - 1, parseInt(dd, 10)).getDay()];
			return m2[3] + '-' + mo2 + '-' + dd + '(' + w2 + ') ' + m2[4] + ':' + m2[5] + ':' + m2[6];
		}
	}
	return s;
}

function getCsrfToken() {
	var el = document.querySelector('input[name="csrf_token"]');
	if (el && el.value) return el.value;
	if (typeof CSRF_TOKEN !== 'undefined' && CSRF_TOKEN) return CSRF_TOKEN;
	return '';
}

var HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(str) {
	if (str == null) return '';
	return String(str).replace(/[&<>"']/g, function(c) { return HTML_ESCAPE_MAP[c]; });
}

function escapeAttr(str) {
	return escapeHtml(str);
}

function escapeJsString(str) {
	if (str == null) return '';
	return String(str)
		.replace(/\\/g, '\\\\')
		.replace(/'/g, "\\'")
		.replace(/"/g, '\\"')
		.replace(/\n/g, '\\n')
		.replace(/\r/g, '\\r')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029')
		.replace(/<\/(script)/gi, '<\\/$1');
}

if (typeof window !== 'undefined') {
	window.formatBytes = formatBytes;
	window.formatCount = formatCount;
	window.formatDateTime = formatDateTime;
	window.formatDisplayDateTime = formatDisplayDateTime;
	window.getCsrfToken = getCsrfToken;
	window.escHtml = escapeHtml;
	window.escapeHtml = escapeHtml;
	window.escapeAttr = escapeAttr;
	window.escapeJsString = escapeJsString;
}
