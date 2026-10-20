// SAB カード: リソースメトリクスグラフ (sec-resource-graph)
// 依存: shared.js の escHtml / getAppBase / IH_AGENT_ID、card_runtime.js の CardRegistry

(function() {
	'use strict';

	var RANGES = ['30min', '1h', '6h', '1d', '1W', '1M', '6M', '1Y'];
	var RANGE_LABELS = {
		'30min': '30分', '1h': '1時間', '6h': '6時間', '1d': '1日',
		'1W': '1週', '1M': '1月', '6M': '6ヶ月', '1Y': '1年'
	};
	// ダークテーマ向け折れ線色
	var COLORS = ['#4fc3f7', '#81c784', '#ffb74d', '#e57373', '#ba68c8',
	              '#4dd0e1', '#aed581', '#ff8a65', '#f48fb1', '#80cbc4'];

	var currentRange = '1d';
	var currentAgentID = null;

	// C9-C1: ローカル esc は廃止し正準 escHtml に統一。
	var esc = (typeof window !== 'undefined' && window.escHtml) ? window.escHtml : function(s) { return String(s == null ? '' : s); };

	function base() {
		return typeof getAppBase === 'function' ? getAppBase() : '/monitor';
	}

	function fmtBytes(v) {
		if (v == null) return '-';
		if (v < 1024) return v.toFixed(0) + ' B';
		if (v < 1048576) return (v / 1024).toFixed(1) + ' KB';
		if (v < 1073741824) return (v / 1048576).toFixed(1) + ' MB';
		return (v / 1073741824).toFixed(2) + ' GB';
	}

	function fmtVal(v, unit) {
		if (v == null) return '-';
		switch (unit) {
			case '%':    return v.toFixed(1) + '%';
			case 'bytes': return fmtBytes(v);
			case 'B/s':  return fmtBytes(v) + '/s';
			default:     return v.toFixed(2);
		}
	}

	function timeTick(t) {
		var d = new Date(t);
		var h = ('0' + d.getHours()).slice(-2);
		var m = ('0' + d.getMinutes()).slice(-2);
		var mon = ('0' + (d.getMonth() + 1)).slice(-2);
		var day = ('0' + d.getDate()).slice(-2);
		if (h === '00' && m === '00') return mon + '/' + day;
		return h + ':' + m;
	}

	// ツールチップ用のフル日時表記（年は省略、月日 + 時分秒）
	function tipTime(t) {
		var d = new Date(t);
		var mon = ('0' + (d.getMonth() + 1)).slice(-2);
		var day = ('0' + d.getDate()).slice(-2);
		var h = ('0' + d.getHours()).slice(-2);
		var m = ('0' + d.getMinutes()).slice(-2);
		var s = ('0' + d.getSeconds()).slice(-2);
		return mon + '/' + day + ' ' + h + ':' + m + ':' + s;
	}

	// buildSVG は { html, meta } を返す。meta はホバー描画のためのジオメトリ。
	function buildSVG(lines, unit) {
		var W = 680, H = 130;
		var padL = 58, padR = 8, padT = 6, padB = 22;
		var cW = W - padL - padR;
		var cH = H - padT - padB;

		// 全ポイントから Y 軸範囲を計算
		var allV = [];
		lines.forEach(function(l) {
			l.points.forEach(function(p) { if (p.v != null) allV.push(p.v); });
		});
		if (allV.length === 0) return { html: '<p class="empty" style="padding:4px 0">データなし</p>', meta: null };

		var minV = Math.min.apply(null, allV);
		var maxV = Math.max.apply(null, allV);
		if (unit === '%') { minV = 0; maxV = Math.max(100, maxV); }
		if (minV === maxV) maxV = minV + 1;

		var n = lines[0].points.length;
		function xp(i) { return padL + (n === 1 ? cW / 2 : i * cW / (n - 1)); }
		function yp(v) { return padT + cH - (v - minV) / (maxV - minV) * cH; }

		var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;overflow:visible" aria-hidden="true">';

		// Y グリッド（5本）
		for (var yi = 0; yi <= 4; yi++) {
			var yv = minV + (maxV - minV) * yi / 4;
			var ypx = yp(yv);
			svg += '<line x1="' + padL + '" y1="' + ypx + '" x2="' + (padL + cW) + '" y2="' + ypx
			     + '" stroke="#2a2a2a" stroke-width="1"/>';
			svg += '<text x="' + (padL - 3) + '" y="' + (ypx + 4) + '" text-anchor="end" '
			     + 'font-size="9" fill="#666">' + fmtVal(yv, unit) + '</text>';
		}

		// X 軸ラベル（最大 8 本）
		var step = Math.max(1, Math.floor(n / 8));
		for (var xi = 0; xi < n; xi += step) {
			svg += '<text x="' + xp(xi) + '" y="' + (padT + cH + 14) + '" text-anchor="middle" '
			     + 'font-size="9" fill="#555">' + timeTick(lines[0].points[xi].t) + '</text>';
		}

		// 折れ線
		lines.forEach(function(line, li) {
			var color = COLORS[li % COLORS.length];
			var d = '';
			var move = true;
			line.points.forEach(function(p, pi) {
				if (p.v == null) { move = true; return; }
				var cmd = move ? 'M' : 'L';
				d += cmd + ' ' + xp(pi).toFixed(1) + ' ' + yp(p.v).toFixed(1) + ' ';
				move = false;
			});
			if (d) {
				svg += '<path d="' + d + '" fill="none" stroke="' + color
				     + '" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>';
			}
		});

		svg += '</svg>';
		return {
			html: svg,
			meta: {
				lines: lines, unit: unit,
				W: W, H: H, padL: padL, padT: padT, cW: cW, cH: cH,
				n: n, minV: minV, maxV: maxV
			}
		};
	}

	// SVG にマウスオーバー時の縦ガイド線・各系列の値マーカー・ツールチップを付与する。
	function attachHover(wrap, meta) {
		var svg = wrap.querySelector('svg');
		if (!svg || !meta) return;
		var W = meta.W, padL = meta.padL, padT = meta.padT,
		    cW = meta.cW, cH = meta.cH, n = meta.n,
		    minV = meta.minV, maxV = meta.maxV, lines = meta.lines, unit = meta.unit;

		function xp(i) { return padL + (n === 1 ? cW / 2 : i * cW / (n - 1)); }
		function yp(v) { return padT + cH - (v - minV) / (maxV - minV) * cH; }

		var NS = 'http://www.w3.org/2000/svg';
		var g = document.createElementNS(NS, 'g');
		g.style.display = 'none';
		g.style.pointerEvents = 'none';
		var vline = document.createElementNS(NS, 'line');
		vline.setAttribute('y1', padT);
		vline.setAttribute('y2', padT + cH);
		vline.setAttribute('stroke', '#90a4ae');
		vline.setAttribute('stroke-width', '1');
		vline.setAttribute('stroke-dasharray', '3 3');
		g.appendChild(vline);
		var dots = lines.map(function(l, li) {
			var c = document.createElementNS(NS, 'circle');
			c.setAttribute('r', '3.5');
			c.setAttribute('fill', COLORS[li % COLORS.length]);
			c.setAttribute('stroke', '#141a22');
			c.setAttribute('stroke-width', '1');
			g.appendChild(c);
			return c;
		});
		svg.appendChild(g);

		var tip = document.createElement('div');
		tip.className = 'rg-tooltip';
		tip.style.display = 'none';
		wrap.appendChild(tip);

		function hide() { g.style.display = 'none'; tip.style.display = 'none'; }

		function move(e) {
			var rect = svg.getBoundingClientRect();
			if (!rect.width) return;
			var sx = (e.clientX - rect.left) / rect.width * W;
			var i = n === 1 ? 0 : Math.round((sx - padL) / (cW || 1) * (n - 1));
			if (i < 0) i = 0;
			if (i > n - 1) i = n - 1;
			var gx = xp(i);
			vline.setAttribute('x1', gx);
			vline.setAttribute('x2', gx);
			var rows = '';
			lines.forEach(function(l, li) {
				var p = l.points[i];
				var v = p ? p.v : null;
				if (v == null) {
					dots[li].style.display = 'none';
				} else {
					dots[li].style.display = '';
					dots[li].setAttribute('cx', gx);
					dots[li].setAttribute('cy', yp(v));
				}
				rows += '<div class="rg-tip-row"><span class="rg-tip-dot" style="background:'
				      + COLORS[li % COLORS.length] + '"></span>'
				      + esc(l.label) + ': <b>' + (v == null ? '-' : fmtVal(v, unit)) + '</b></div>';
			});
			g.style.display = '';

			var t = lines[0].points[i] ? lines[0].points[i].t : '';
			tip.innerHTML = '<div class="rg-tip-time">' + esc(tipTime(t)) + '</div>' + rows;
			tip.style.display = 'block';

			// ツールチップをガイド線付近に配置。右端で見切れる場合は左側へ反転。
			var wrapRect = wrap.getBoundingClientRect();
			var guidePx = rect.left + (gx / W) * rect.width - wrapRect.left + wrap.scrollLeft;
			var px = guidePx + 12;
			if (px + tip.offsetWidth > wrap.clientWidth + wrap.scrollLeft) {
				px = guidePx - tip.offsetWidth - 12;
			}
			if (px < wrap.scrollLeft) px = wrap.scrollLeft + 2;
			tip.style.left = px + 'px';
		}

		svg.addEventListener('mousemove', move);
		svg.addEventListener('mouseleave', hide);
	}

	function render(el, data) {
		if (!data || data.empty) {
			el.innerHTML = '<p class="empty">データ収集中です。しばらくお待ちください。</p>';
			return;
		}

		var html = '<div class="rg-range-bar">';
		RANGES.forEach(function(r) {
			var cls = 'rg-range-btn' + (r === currentRange ? ' rg-range-active' : '');
			html += '<button class="' + cls + '" data-range="' + r + '">' + RANGE_LABELS[r] + '</button>';
		});
		html += '</div>';
		html += '<div class="rg-gentime">生成: ' + esc(data.generated_at || '') + '</div>';

		var metas = [];
		data.series.forEach(function(s, si) {
			html += '<div class="rg-series">';
			html += '<div class="rg-series-hd">' + esc(s.label);
			if (s.unit) html += ' <span class="rg-unit">(' + esc(s.unit) + ')</span>';
			html += '</div>';
			// 凡例
			html += '<div class="rg-legend">';
			s.lines.forEach(function(l, li) {
				html += '<span class="rg-legend-item">'
				      + '<span class="rg-legend-dot" style="background:' + COLORS[li % COLORS.length] + '"></span>'
				      + esc(l.label) + '</span>';
			});
			html += '</div>';
			// SVG チャート
			var chart = buildSVG(s.lines, s.unit);
			metas[si] = chart.meta;
			html += '<div class="rg-chart-wrap" data-rg-idx="' + si + '">' + chart.html + '</div>';
			html += '</div>';
		});

		if (data.warnings && data.warnings.length) {
			html += '<div class="rg-warnings">';
			data.warnings.forEach(function(w) { html += '<p class="rg-warn">' + esc(w) + '</p>'; });
			html += '</div>';
		}

		el.innerHTML = html;

		// 各チャートにホバー（縦ガイド線 + 値ツールチップ）を付与
		el.querySelectorAll('.rg-chart-wrap[data-rg-idx]').forEach(function(wrap) {
			var idx = parseInt(wrap.getAttribute('data-rg-idx'), 10);
			attachHover(wrap, metas[idx]);
		});

		el.querySelectorAll('.rg-range-btn').forEach(function(btn) {
			btn.addEventListener('click', function() {
				currentRange = btn.getAttribute('data-range');
				fetchData(el, currentAgentID);
			});
		});
	}

	// C9-C4: ローカル doFetch を fetchData に改名し、エラー class を section-error に統一。
	// range クエリ付き API のため loadJsonCard ではなく専用 fetch を維持する。
	function fetchData(el, agentID) {
		currentAgentID = agentID;
		el.innerHTML = '<p class="section-loading">読み込み中...</p>';
		var url = base() + '/?api=resource_graph&range=' + encodeURIComponent(currentRange);
		if (agentID) url += '&agent=' + encodeURIComponent(agentID);
		fetch(url)
			.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
			.then(function(data) { render(el, data); })
			.catch(function(e) { el.innerHTML = '<p class="section-error">読み込みに失敗しました: ' + esc(e.message) + '</p>'; });
	}

	CardRegistry.register('ResourceGraph', {
		cardKey: 'RESOURCE_GRAPH',
		fallbackId: 'sec-resource-graph',
		apiFallback: 'resource_graph',
		render: function(el, data) { render(el, data); },
		init: function(el, agentID) { fetchData(el, agentID); }
	});
})();
