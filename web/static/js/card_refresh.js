// =============================================================================
// card_refresh.js — カード単位の更新ボタン注入と個別更新
//   - injectRefreshButtons(): 全 section.card[id] にボタン注入
//   - refreshCard(cardId, btn): /card?card=xxx を fetch → innerHTML 差し替え
//                               → 'card:refreshed' CustomEvent 発火
// =============================================================================
(function() {
	'use strict';

	// section.card[id] のうち更新ボタンを注入しないもの
	var EXCLUDED_IDS = {
		'action-result': 1,
		'repair-msg': 1,
		'maint-msg': 1,
		'update-msg': 1,
		'sec-realtime-monitor': 1
	};

	var DISABLED_CARD_PICKER_EXCLUDED_IDS = {
		'action-result': 1,
		'repair-msg': 1,
		'maint-msg': 1,
		'update-msg': 1
	};

	// section.id ('sec-xxx') → /card?card= 用ID へのマップ
	// (ハイフン → アンダースコア + 'sec-' プレフィクス除去)
	function cardIdFromSectionId(sid) {
		return sid.replace(/^sec-/, '').replace(/-/g, '_');
	}

	function normalizeHeaderActionsOrder(headerActions) {
		if (!headerActions) return;
		var children = Array.prototype.slice.call(headerActions.children);
		children.forEach(function(el, idx) {
			if (!el || el.nodeType !== 1) return;
			if (!el.getAttribute('data-header-order')) {
				var order = '20';
				if (el.classList.contains('btn-card-refresh')) {
					order = '40';
				} else if (el.matches('.export-btn, .export-btn-footer, .modal-download-btn')) {
					order = '30';
				} else if (el.hasAttribute('data-refresh-insert-after')) {
					order = '15';
				}
				el.setAttribute('data-header-order', order);
			}
			el.setAttribute('data-header-sort-index', String(idx));
		});
		children.sort(function(a, b) {
			var oa = parseInt(a.getAttribute('data-header-order') || '99', 10);
			var ob = parseInt(b.getAttribute('data-header-order') || '99', 10);
			if (oa !== ob) return oa - ob;
			var ia = parseInt(a.getAttribute('data-header-sort-index') || '0', 10);
			var ib = parseInt(b.getAttribute('data-header-sort-index') || '0', 10);
			return ia - ib;
		});
		children.forEach(function(el) {
			el.removeAttribute('data-header-sort-index');
			headerActions.appendChild(el);
		});
	}

	function injectRefreshButtons() {
		var cards = document.querySelectorAll('section.card[id]');
		cards.forEach(function(card) {
			if (EXCLUDED_IDS[card.id]) return;
			if (card.classList.contains('action-result')) return;
			if (card.dataset.cardNoRefresh === '1') return;
			// 既に注入済みなら何もしない (db-info-actions 等の代替配置先も含めて全探索)
			if (card.querySelector('.btn-card-refresh')) return;

			var btn = document.createElement('button');
			btn.type = 'button';
			btn.className = 'btn-card-refresh';
			btn.title = 'このカードを更新';
			btn.setAttribute('aria-label', 'このカードを更新');
			btn.setAttribute('data-header-order', '40');
			btn.textContent = '更新';
			btn.addEventListener('click', function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				refreshCard(card.id, btn);
			});

			// 配置先の優先順:
			//   1) .card-header > .card-header-actions（標準ヘッダ持ちカード）
			//   2) その他の *-actions コンテナ（db-info-actions 等）
			//   3) section 直下に絶対配置（CSS側で右上固定）
			var headerActions = card.querySelector(':scope > .card-header .card-header-actions')
				|| card.querySelector('.card-header-actions');
			var altActions = headerActions ? null
				: card.querySelector('[class$="-actions"], [class*="-actions "]');
			if (headerActions) {
				// data-header-order 属性が存在するカードは initCardHeaderActions がソートを担う
				var hasOrderedItems = headerActions.querySelector('[data-header-order]');
				if (hasOrderedItems) {
					headerActions.appendChild(btn);
				} else {
					var refreshAnchor = headerActions.querySelector('[data-refresh-insert-after]');
					if (refreshAnchor && refreshAnchor.parentNode === headerActions) {
						headerActions.insertBefore(btn, refreshAnchor.nextSibling);
					} else {
						var exportBtns = headerActions.querySelectorAll('.export-btn, .export-btn-footer, .modal-download-btn');
						var insertAfter = exportBtns.length ? exportBtns[exportBtns.length - 1] : null;
						if (insertAfter && insertAfter.parentNode === headerActions) {
							headerActions.insertBefore(btn, insertAfter.nextSibling);
						} else {
							headerActions.insertBefore(btn, headerActions.firstChild);
						}
					}
				}
				normalizeHeaderActionsOrder(headerActions);
			} else if (altActions) {
				altActions.insertBefore(btn, altActions.firstChild);
			} else {
				btn.classList.add('btn-card-refresh-floating');
				card.appendChild(btn);
			}

			// カード内に section-loading があれば初期ロード中 → ボタンも更新中状態にする
			if (card.querySelector('.section-loading')) {
				btn.classList.add('spinning');
				btn.disabled = true;
				btn.textContent = '更新中…';
				observeLoadingDone(card, btn);
			}
		});
	}

	var disabledCardPicker = {
		selected: {},
		manuallyClosed: false,
		panel: null,
		modal: null,
		copyBtn: null,
		textArea: null
	};

	function canUseDisabledCardPicker() {
		// disabled_cards の手動列挙は廃止し capability ベースへ移行したため、UI は停止している。
		return false;
	}

	function displayAgentID() {
		return (typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) ? String(HD_AGENT_ID) : '';
	}

	function displayAgentType() {
		return (typeof HD_AGENT_TYPE !== 'undefined' && HD_AGENT_TYPE) ? String(HD_AGENT_TYPE) : '';
	}

	// HTML エスケープは shared.js の正準 escHtml に統一する。
	var escHtml = (typeof window !== 'undefined' && typeof window.escHtml === 'function')
		? window.escHtml
		: function(s) { return String(s == null ? '' : s); };

	function getCardLabel(card) {
		var h2 = card.querySelector(':scope > .card-header h2')
			|| card.querySelector(':scope > h2');
		if (!h2) return card.id;
		var clone = h2.cloneNode(true);
		clone.querySelectorAll('.card-parent-group, .collapse-hint').forEach(function(el) {
			if (el.parentNode) el.parentNode.removeChild(el);
		});
		return (clone.textContent || card.id).replace(/\s+/g, ' ').trim() || card.id;
	}

	function getPickerCards() {
		return Array.prototype.slice.call(document.querySelectorAll('section.card[id^="sec-"]')).filter(function(card) {
			if (DISABLED_CARD_PICKER_EXCLUDED_IDS[card.id]) return false;
			return !!card.querySelector('.disabled-card-picker-input');
		});
	}

	function sortedSelectedCards() {
		var out = [];
		Object.keys(disabledCardPicker.selected).forEach(function(id) {
			var item = disabledCardPicker.selected[id];
			if (item) out.push(item);
		});
		out.sort(function(a, b) {
			if (a.order !== b.order) return a.order - b.order;
			return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
		});
		return out;
	}

	function ensureDisabledCardPanel() {
		if (disabledCardPicker.panel) return disabledCardPicker.panel;
		var panel = document.createElement('aside');
		panel.className = 'disabled-card-candidate-panel';
		panel.setAttribute('aria-live', 'polite');
		panel.innerHTML = ''
			+ '<div class="disabled-card-candidate-head">'
			+ '  <div><div class="disabled-card-candidate-title">disabled_cards候補</div>'
			+ '  <div class="disabled-card-candidate-count" data-disabled-card-count>選択中 0件</div></div>'
			+ '  <button type="button" class="disabled-card-candidate-close" data-disabled-card-panel-close aria-label="閉じる">&times;</button>'
			+ '</div>'
			+ '<div class="disabled-card-candidate-actions">'
			+ '  <button type="button" class="btn-secondary btn-sm" data-disabled-card-all-on>全てON</button>'
			+ '  <button type="button" class="btn-secondary btn-sm" data-disabled-card-all-off>全てOFF</button>'
			+ '</div>'
			+ '<div class="disabled-card-candidate-list" data-disabled-card-list></div>'
			+ '<button type="button" class="btn-primary btn-sm disabled-card-candidate-output" data-disabled-card-output>TOML出力</button>';
		document.body.appendChild(panel);
		disabledCardPicker.panel = panel;

		panel.addEventListener('click', function(ev) {
			var closeBtn = ev.target.closest('[data-disabled-card-panel-close]');
			if (closeBtn) {
				disabledCardPicker.manuallyClosed = true;
				renderDisabledCardPanel();
				return;
			}
			if (ev.target.closest('[data-disabled-card-all-on]')) {
				setAllDisabledCardChecks(true);
				return;
			}
			if (ev.target.closest('[data-disabled-card-all-off]')) {
				setAllDisabledCardChecks(false);
				return;
			}
			var removeBtn = ev.target.closest('[data-disabled-card-remove]');
			if (removeBtn) {
				setCardChecked(removeBtn.getAttribute('data-disabled-card-remove'), false);
				return;
			}
			if (ev.target.closest('[data-disabled-card-output]')) {
				openDisabledCardTomlModal();
			}
		});
		return panel;
	}

	function ensureDisabledCardModal() {
		if (disabledCardPicker.modal) return disabledCardPicker.modal;
		var modal = document.createElement('div');
		modal.id = 'disabled-card-toml-modal';
		modal.className = 'modal-overlay';
		modal.style.display = 'none';
		modal.setAttribute('role', 'dialog');
		modal.setAttribute('aria-modal', 'true');
		modal.setAttribute('aria-labelledby', 'disabled-card-toml-title');
		modal.innerHTML = ''
			+ '<div class="modal-content modal-content-wide">'
			+ '  <div class="modal-header">'
			+ '    <h3 id="disabled-card-toml-title">カード非表示TOML</h3>'
			+ '    <div class="modal-header-actions">'
			+ '      <button type="button" class="btn-primary btn-sm" data-disabled-card-copy>コピー</button>'
			+ '      <button type="button" class="modal-close" data-disabled-card-modal-close aria-label="閉じる">&times;</button>'
			+ '    </div>'
			+ '  </div>'
			+ '  <div class="modal-body">'
			+ '    <div class="disabled-card-toml-meta">'
			+ '      <span data-disabled-card-modal-agent></span>'
			+ '      <span data-disabled-card-modal-type></span>'
			+ '      <span data-disabled-card-modal-count></span>'
			+ '    </div>'
			+ '    <textarea class="disabled-card-toml-text" data-disabled-card-toml readonly spellcheck="false"></textarea>'
			+ '    <p class="disabled-card-toml-note">反映は config/config.toml に貼り付け後、TOML転送とサービス再起動で行います。復活は disabled_cards から対象カードIDを削除します。</p>'
			+ '  </div>'
			+ '</div>';
		document.body.appendChild(modal);
		disabledCardPicker.modal = modal;
		disabledCardPicker.copyBtn = modal.querySelector('[data-disabled-card-copy]');
		disabledCardPicker.textArea = modal.querySelector('[data-disabled-card-toml]');

		modal.addEventListener('click', function(ev) {
			if (ev.target === modal || ev.target.closest('[data-disabled-card-modal-close]')) {
				closeDisabledCardTomlModal();
				return;
			}
			if (ev.target.closest('[data-disabled-card-copy]')) {
				copyDisabledCardToml();
			}
		});
		return modal;
	}

	function renderDisabledCardPanel() {
		var panel = ensureDisabledCardPanel();
		var selected = sortedSelectedCards();
		var visible = selected.length > 0 && !disabledCardPicker.manuallyClosed;
		panel.classList.toggle('is-visible', visible);
		if (document.body) {
			document.body.classList.toggle('disabled-card-picker-active', visible);
		}
		var countEl = panel.querySelector('[data-disabled-card-count]');
		if (countEl) countEl.textContent = '選択中 ' + selected.length + '件';
		var list = panel.querySelector('[data-disabled-card-list]');
		if (!list) return;
		if (!selected.length) {
			list.innerHTML = '';
			return;
		}
		list.innerHTML = selected.map(function(item) {
			return '<div class="disabled-card-candidate-item">'
				+ '<div><div class="disabled-card-candidate-name">' + escHtml(item.label) + '</div>'
				+ '<div class="disabled-card-candidate-id">' + escHtml(item.id) + '</div></div>'
				+ '<button type="button" class="disabled-card-candidate-remove" data-disabled-card-remove="' + escHtml(item.id) + '">外す</button>'
				+ '</div>';
		}).join('');
	}

	function setCardChecked(cardId, checked) {
		if (!cardId) return;
		var card = document.getElementById(cardId);
		var input = card && card.querySelector('.disabled-card-picker-input');
		if (input) input.checked = !!checked;
		if (checked && card) {
			disabledCardPicker.selected[cardId] = {
				id: cardId,
				label: getCardLabel(card),
				order: Array.prototype.indexOf.call(document.querySelectorAll('section.card[id^="sec-"]'), card)
			};
			disabledCardPicker.manuallyClosed = false;
		} else {
			delete disabledCardPicker.selected[cardId];
		}
		if (Object.keys(disabledCardPicker.selected).length === 0) {
			disabledCardPicker.manuallyClosed = false;
		}
		renderDisabledCardPanel();
	}

	function setAllDisabledCardChecks(checked) {
		getPickerCards().forEach(function(card) {
			var input = card.querySelector('.disabled-card-picker-input');
			if (input) input.checked = !!checked;
			if (checked) {
				disabledCardPicker.selected[card.id] = {
					id: card.id,
					label: getCardLabel(card),
					order: Array.prototype.indexOf.call(document.querySelectorAll('section.card[id^="sec-"]'), card)
				};
			} else {
				delete disabledCardPicker.selected[card.id];
			}
		});
		disabledCardPicker.manuallyClosed = false;
		renderDisabledCardPanel();
	}

	function buildDisabledCardsToml() {
		var selected = sortedSelectedCards();
		var agentID = displayAgentID();
		var agentType = displayAgentType();
		var lines = [];
		lines.push('# ===== heartdesk disabled_cards paste start =====');
		lines.push('# 貼り付け先:');
		lines.push('#   config/config.toml の [agent."' + agentID + '"] セクション内');
		lines.push('#');
		lines.push('# 対象サーバー:');
		lines.push('#   agent_id   = "' + agentID + '"');
		if (agentType) lines.push('#   agent_type = "' + agentType + '"');
		lines.push('#');
		lines.push('# 用途:');
		lines.push('#   このサーバーでは取得できないカードを非表示にします。');
		lines.push('#   ユーザー個別の非表示は cards_user.toml、テナント方針の非表示は cards_tenants.toml を使います。');
		lines.push('#');
		lines.push('# 注意:');
		lines.push('#   既存の disabled_cards がある場合は、このブロックで置き換えてください。');
		lines.push('#   同じ理由で同じカードIDを cards_tenants.toml / cards_user.toml に重複して書かないでください。');
		lines.push('#   復活したい場合は、disabled_cards から対象カードIDを削除してください。');
		lines.push('disabled_cards = [');
		selected.forEach(function(item) {
			lines.push('  "' + item.id + '", # ' + item.label);
		});
		lines.push(']');
		lines.push('# ===== heartdesk disabled_cards paste end =====');
		return lines.join('\n');
	}

	function openDisabledCardTomlModal() {
		var selected = sortedSelectedCards();
		if (!selected.length) return;
		var modal = ensureDisabledCardModal();
		var agentEl = modal.querySelector('[data-disabled-card-modal-agent]');
		var typeEl = modal.querySelector('[data-disabled-card-modal-type]');
		var countEl = modal.querySelector('[data-disabled-card-modal-count]');
		if (agentEl) agentEl.textContent = 'agent: ' + displayAgentID();
		if (typeEl) typeEl.textContent = 'type: ' + (displayAgentType() || '-');
		if (countEl) countEl.textContent = 'cards: ' + selected.length;
		if (disabledCardPicker.textArea) {
			disabledCardPicker.textArea.value = buildDisabledCardsToml();
		}
		if (disabledCardPicker.copyBtn) disabledCardPicker.copyBtn.textContent = 'コピー';
		modal.style.display = 'flex';
		if (disabledCardPicker.textArea) {
			disabledCardPicker.textArea.focus();
			disabledCardPicker.textArea.select();
		}
	}

	function closeDisabledCardTomlModal() {
		if (disabledCardPicker.modal) disabledCardPicker.modal.style.display = 'none';
	}

	function copyDisabledCardToml() {
		var text = disabledCardPicker.textArea ? disabledCardPicker.textArea.value : buildDisabledCardsToml();
		var btn = disabledCardPicker.copyBtn;
		var done = function() {
			if (!btn) return;
			var orig = btn.textContent;
			btn.textContent = 'コピー済み';
			setTimeout(function() { btn.textContent = orig || 'コピー'; }, 1200);
		};
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).then(done).catch(function() {
				if (disabledCardPicker.textArea) disabledCardPicker.textArea.select();
			});
		} else if (disabledCardPicker.textArea) {
			disabledCardPicker.textArea.select();
			try {
				document.execCommand('copy');
				done();
			} catch (e) {}
		}
	}

	function injectDisabledCardPickers(root) {
		if (!canUseDisabledCardPicker()) return;
		ensureDisabledCardPanel();
		var target = root || document;
		target.querySelectorAll('section.card[id^="sec-"]').forEach(function(card) {
			if (DISABLED_CARD_PICKER_EXCLUDED_IDS[card.id]) return;
			var header = card.querySelector(':scope > .card-header')
				|| card.querySelector(':scope > h2.section-toggle');
			if (!header || header.querySelector('.disabled-card-picker')) return;
			var label = document.createElement('label');
			label.className = 'disabled-card-picker';
			label.setAttribute('data-tip', 'このカードをサーバー取得不可カード候補に入れます。設定は変更せず、あとで disabled_cards 用TOMLを出力します。');
			label.innerHTML = '<input type="checkbox" class="disabled-card-picker-input" aria-label="disabled_cards用TOMLの候補に入れる">';
			var input = label.querySelector('input');
			if (disabledCardPicker.selected[card.id]) input.checked = true;
			label.addEventListener('click', function(ev) { ev.stopPropagation(); });
			input.addEventListener('click', function(ev) { ev.stopPropagation(); });
			input.addEventListener('change', function() {
				setCardChecked(card.id, input.checked);
			});
			var toggle = header.querySelector(':scope > .toggle-icon');
			if (toggle) {
				header.insertBefore(label, toggle);
			} else {
				header.insertBefore(label, header.firstChild);
			}
		});
		renderDisabledCardPanel();
	}

	// section-loading が消えたらボタンを通常状態に戻す
	function observeLoadingDone(card, btn) {
		var observer = new MutationObserver(function() {
			if (!card.querySelector('.section-loading')) {
				observer.disconnect();
				btn.classList.remove('spinning');
				btn.disabled = false;
				btn.textContent = '更新';
			}
		});
		observer.observe(card, { childList: true, subtree: true });
	}

	function refreshCard(cardId, btn) {
		var card = document.getElementById(cardId);
		if (!card) return;

		// 折りたたまれていたら展開（更新したのに見えない問題を防ぐ）
		if (card.classList.contains('collapsed')) {
			card.classList.remove('collapsed');
			try {
				var key = (typeof HD_COLLAPSE_KEY !== 'undefined' && HD_COLLAPSE_KEY) ? HD_COLLAPSE_KEY : 'heartdesk.collapsed.v1';
				var raw = localStorage.getItem(key);
				var arr = raw ? JSON.parse(raw) : [];
				if (Array.isArray(arr)) {
					arr = arr.filter(function(id) { return id !== cardId; });
					localStorage.setItem(key, JSON.stringify(arr));
				}
			} catch (e) {}
		}

		// async-contentカード（loadSection系）の場合は _refreshConfig を使って再fetch
		if (card._refreshConfig) {
			var rc = card._refreshConfig;
			if (btn) { btn.classList.remove('error'); btn.classList.add('spinning'); btn.disabled = true; btn.textContent = '更新中…'; }
			var url = getAppBase() + '/?api=' + encodeURIComponent(rc.apiName);
			if (rc.extraParams) url += '&' + rc.extraParams;
			if (typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) {
				url += '&agent=' + encodeURIComponent(HD_AGENT_ID);
			}
			fetch(url, { credentials: 'same-origin' })
				.then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
				.then(function(data) {
					var section = document.getElementById(rc.sectionId);
					if (section) {
						var contentEl = section.classList.contains('async-content') ? section : section.querySelector('.async-content');
						if (contentEl) rc.renderFn(contentEl, data);
					}
					if (typeof touchLastUpdated === 'function') touchLastUpdated();
					if (btn) { btn.classList.remove('spinning', 'error'); btn.disabled = false; btn.textContent = '更新'; }
				})
				.catch(function(err) {
					console.error('[card_refresh] async-content failed:', cardId, err);
					if (btn) {
						btn.classList.add('error');
						btn.textContent = '失敗';
						setTimeout(function() { btn.classList.remove('error'); btn.textContent = '更新'; btn.disabled = false; }, 1500);
					}
				});
			return;
		}

		var apiId = cardIdFromSectionId(cardId);
		var base = (typeof HD_APP_BASE !== 'undefined' && HD_APP_BASE) ? HD_APP_BASE : '/monitor';
		var url = base + '/card?card=' + encodeURIComponent(apiId);
		if (typeof HD_AGENT_ID !== 'undefined' && HD_AGENT_ID) {
			url += '&agent=' + encodeURIComponent(HD_AGENT_ID);
		}

		if (btn) {
			btn.classList.remove('error');
			btn.classList.add('spinning');
			btn.disabled = true;
			btn.textContent = '更新中…';
		}

		fetch(url, { credentials: 'same-origin' })
			.then(function(r) {
				if (!r.ok) throw new Error('HTTP ' + r.status);
				return r.text();
			})
			.then(function(html) {
				var tmp = document.createElement('div');
				tmp.innerHTML = html;
				var newCard = tmp.firstElementChild;
				if (newCard && card.parentNode) {
					card.parentNode.replaceChild(newCard, card);
					card = newCard;
				}
				// 注入ボタンが消えるので再注入
				if (typeof window.applyCardGroupLabels === 'function') {
					window.applyCardGroupLabels(card.parentNode || document);
				}
				injectRefreshButtons();
				injectDisabledCardPickers(card.parentNode || document);
				initExportButtons();
				// カード固有の再初期化を任せるイベント発火
				card.dispatchEvent(new CustomEvent('card:refreshed', {
					bubbles: true,
					detail: { cardId: cardId, apiId: apiId }
				}));
				if (typeof window.touchLastUpdated === 'function') {
					window.touchLastUpdated();
				}
			})
			.catch(function(err) {
				console.error('[card_refresh] failed:', cardId, err);
				if (btn) {
					btn.classList.add('error');
					btn.textContent = '失敗';
					setTimeout(function() {
						btn.classList.remove('error');
						btn.textContent = '更新';
					}, 1500);
				}
			})
			.then(function() {
				if (btn) {
					btn.classList.remove('spinning');
					btn.disabled = false;
					if (!btn.classList.contains('error')) {
						btn.textContent = '更新';
					}
				}
			});
	}

	// --- DLボタンのローディング状態 ---
	function initExportButtons() {
		var links = document.querySelectorAll('.export-btn');
		links.forEach(function(link) {
			if (link.dataset.exportBound) return;
			link.dataset.exportBound = '1';
			link.addEventListener('click', function(ev) {
				ev.preventDefault();
				if (link.classList.contains('spinning')) return;
				var href = link.href;
				if (!href) return;

				var origText = link.textContent;
				link.classList.add('spinning');
				link.textContent = 'DL中…';
				link.style.pointerEvents = 'none';

				fetch(href, { credentials: 'same-origin' })
					.then(function(r) {
						if (!r.ok) throw new Error('HTTP ' + r.status);
						var disposition = r.headers.get('Content-Disposition') || '';
						var match = disposition.match(/filename[*]?=(?:UTF-8''|"?)([^";]+)/i);
						var filename = match ? decodeURIComponent(match[1]) : 'download';
						return r.blob().then(function(blob) {
							return { blob: blob, filename: filename };
						});
					})
					.then(function(result) {
						var a = document.createElement('a');
						a.href = URL.createObjectURL(result.blob);
						a.download = result.filename;
						document.body.appendChild(a);
						a.click();
						document.body.removeChild(a);
						URL.revokeObjectURL(a.href);
					})
					.catch(function(err) {
						console.error('[export] failed:', href, err);
						link.classList.add('error');
						link.textContent = '失敗';
						setTimeout(function() {
							link.classList.remove('error');
						}, 1500);
					})
					.then(function() {
						link.classList.remove('spinning');
						link.style.pointerEvents = '';
						if (!link.classList.contains('error')) {
							link.textContent = origText;
						} else {
							setTimeout(function() {
								link.textContent = origText;
							}, 1500);
						}
					});
			});
		});
	}

	// =============================================================================
	// カード表示モード適用（policy.cards / policy.child_cards）
	// HD_CARD_VIEW_MODES       = { "sec-xxx": "summary" | "hidden" }
	// HD_CHILD_CARD_VIEW_MODES = { "sec-xxx": { "child-id": "summary" | "hidden" } }
	// =============================================================================

	function applyCardViewModes() {
		var modes = (typeof HD_CARD_VIEW_MODES !== 'undefined') ? HD_CARD_VIEW_MODES : {};
		var childModes = (typeof HD_CHILD_CARD_VIEW_MODES !== 'undefined') ? HD_CHILD_CARD_VIEW_MODES : {};

		// 親カード
		Object.keys(modes).forEach(function(cardId) {
			var mode = modes[cardId];
			var card = document.getElementById(cardId);
			if (!card) return;
			card.classList.remove('card-mode-summary', 'card-mode-hidden');
			if (mode === 'hidden') {
				card.classList.add('card-mode-hidden');
			} else if (mode === 'summary') {
				card.classList.add('card-mode-summary');
			}
		});

		// 子カード（data-child-card-id 属性を持つ要素に適用）
		Object.keys(childModes).forEach(function(parentId) {
			var parentCard = document.getElementById(parentId);
			if (!parentCard) return;
			var children = childModes[parentId];
			Object.keys(children).forEach(function(childId) {
				var mode = children[childId];
				var child = parentCard.querySelector('[data-child-card-id="' + childId + '"]');
				if (!child) return;
				child.classList.remove('card-mode-summary', 'card-mode-hidden');
				if (mode === 'hidden') {
					child.classList.add('card-mode-hidden');
				} else if (mode === 'summary') {
					child.classList.add('card-mode-summary');
				}
			});
		});
	}

	// グローバル公開
	window.injectRefreshButtons = injectRefreshButtons;
	window.refreshCard = refreshCard;
	window.initExportButtons = initExportButtons;
	window.applyCardViewModes = applyCardViewModes;
	window.injectDisabledCardPickers = injectDisabledCardPickers;

	// card:refreshed イベントでカードモードとTOML候補UIを再適用
	document.addEventListener('card:refreshed', function() {
		applyCardViewModes();
		injectDisabledCardPickers();
	});

	function initAll() {
		injectRefreshButtons();
		injectDisabledCardPickers();
		initExportButtons();
		applyCardViewModes();
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initAll);
	} else {
		initAll();
	}
})();
