// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
'require dom';

var callStatus = rpc.declare({ object: 'luci.easymesh', method: 'status', expect: { } });
var callPair = rpc.declare({ object: 'luci.easymesh', method: 'pair', params: [ 'timeout' ], expect: { } });
var callStop = rpc.declare({ object: 'luci.easymesh', method: 'pair_stop', expect: { } });
var callRestart = rpc.declare({ object: 'luci.easymesh', method: 'restart', expect: { } });

var STATE_TEXT = {
	idle: _('Not started'), running: _('Waiting for the main router (choose Add Mesh Device > WPS there)'),
	paired: _('Paired: connected to the mesh backhaul'), timeout: _('Timed out, nothing paired'),
	stopped: _('Stopped'), failed: _('Failed (see log)')
};

function fmtOp(op) {
	return (op || []).map(function(o) {
		return o[0] == 128 ? _('80 MHz block centre %d').format(o[1]) : _('channel %d').format(o[1]);
	}).join(', ');
}

function row(k, v) {
	return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td left', 'width': '33%' }, k), E('td', { 'class': 'td left' }, v) ]);
}

return view.extend({
	load: function() {
		return callStatus();
	},

	renderStatus: function(st) {
		var a = st.agent || {}, bh = a.backhaul || {}, rows = [];
		rows.push(row(_('Agent service'), st.running ? _('running') : _('stopped')));
		rows.push(row(_('EasyMesh controller'), a.controller || _('not connected')));
		rows.push(row(_('This node (1905 AL MAC)'), a.al || '-'));
		rows.push(row(_('Backhaul'), bh.connected
			? _('%s via %s, %d dBm, %d MHz').format(bh.bssid, bh.ifname, bh.signal, bh.freq)
			: _('not connected')));
		(a.radios || []).forEach(function(r) {
			rows.push(row('%s (%s)'.format(r.uci, r.band == '5g' ? _('5 GHz') : _('2.4 GHz')),
				'%s, %s'.format(r.state == 'done' ? _('configured by controller') : r.state, fmtOp(r.op))));
		});
		return E('table', { 'class': 'table' }, rows);
	},

	render: function(st) {
		var self = this;
		this.lastStatus = st;
		var stateEl = E('strong', { 'id': 'easymesh-pairstate' }, STATE_TEXT[st.pair_state] || st.pair_state);
		var logEl = E('pre', { 'id': 'easymesh-pairlog', 'style': 'max-height:15em;overflow:auto;white-space:pre-wrap' },
			(st.pair_log || []).join('\n') || _('No pairing run yet.'));

		poll.add(function() {
			return callStatus().then(function(s) {
				self.lastStatus = s;
				dom.content(document.getElementById('easymesh-status'), self.renderStatus(s));
				document.getElementById('easymesh-pairstate').textContent = STATE_TEXT[s.pair_state] || s.pair_state;
				document.getElementById('easymesh-pairlog').textContent = (s.pair_log || []).join('\n') || _('No pairing run yet.');
			});
		}, 3);

		return E('div', {}, [
			E('h2', {}, _('EasyMesh')),
			E('div', { 'class': 'cbi-map-descr' }, _('Joins this router to an EasyMesh network (for example a TP-Link EasyMesh router) as a mesh node. First time: press "Pair", then on the main router choose Add Mesh Device > Add By Pressing WPS Button within 5 minutes. After pairing it reconnects by itself.')),
			E('h3', {}, _('Status')),
			E('div', { 'id': 'easymesh-status' }, this.renderStatus(st)),
			E('h3', {}, _('Pairing')),
			E('p', {}, [ _('State') + ': ', stateEl ]),
			E('div', {}, [
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, function() {
					var bh = (self.lastStatus && self.lastStatus.agent && self.lastStatus.agent.backhaul) || {};
					if (bh.connected && !confirm(_('This node is already connected to the mesh. Pairing again disconnects the backhaul, and this page, until you choose Add Mesh Device > WPS on the main router. Continue?')))
						return;
					return callPair(300).then(function(r) {
						if (!r || !r.started) ui.addNotification(null, E('p', (r && r.error) || _('Could not start pairing')));
					});
				}) }, _('Pair with EasyMesh router (WPS)')), ' ',
				E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(this, function() {
					return callStop();
				}) }, _('Stop pairing')), ' ',
				E('button', { 'class': 'btn cbi-button', 'click': ui.createHandlerFn(this, function() {
					return callRestart();
				}) }, _('Restart agent'))
			]),
			E('h4', {}, _('Pairing log')),
			logEl
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
