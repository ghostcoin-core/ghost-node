'use strict';
// `node --test install/faucet/` loads this folder as a module, which is this
// file, on Node.js versions that take the folder as a module rather than a
// folder to search for tests: it runs the faucet's tests. The faucet itself is
// faucet.js; install-faucet.sh does not install this file.

require('./faucet.test.js');
require('./queue.test.js');
