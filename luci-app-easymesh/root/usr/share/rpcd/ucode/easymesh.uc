// SPDX-License-Identifier: GPL-2.0-only
// rpcd backend for luci-app-easymesh: agent status and the software pairing button.
'use strict';

import { readfile, writefile } from 'fs';

const DIR = '/tmp/easymesh';

function rd(p) {
	let d = readfile(p);
	return d != null ? trim(d) : null;
}

return {
	'luci.easymesh': {
		status: {
			call: function() {
				let agent = null;
				try { agent = json(readfile(DIR + '/status.json') ?? 'null'); } catch (e) { agent = null; }
				let log = readfile(DIR + '/pair.log');
				return {
					running: system('/etc/init.d/easymesh running >/dev/null 2>&1') == 0,
					agent,
					pair_state: rd(DIR + '/pair.state') ?? 'idle',
					pair_log: log ? slice(split(trim(log), '\n'), -15) : [],
					now: time(),
				};
			}
		},
		pair: {
			args: { timeout: 300 },
			call: function(req) {
				let t = +(req.args?.timeout ?? 300);
				if (t < 30 || t > 900) t = 300;
				if (rd(DIR + '/pair.state') == 'running')
					return { started: false, error: 'pairing is already running' };
				system(sprintf("mkdir -p %s; : > %s/pair.log; echo running > %s/pair.state; (/usr/sbin/easymesh-pair %d &) >/dev/null 2>&1",
				               DIR, DIR, DIR, t));
				return { started: true };
			}
		},
		pair_stop: {
			call: function() {
				writefile(DIR + '/pair.stop', '1');
				return { stopping: true };
			}
		},
		restart: {
			call: function() {
				system('/etc/init.d/easymesh restart >/dev/null 2>&1 &');
				return { restarting: true };
			}
		}
	}
};
