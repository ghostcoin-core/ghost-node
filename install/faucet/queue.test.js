'use strict';
// The faucet's queue, against a stand-in node whose transfers never reach a
// block and a sleep the test lets go by hand:  node --test install/faucet/

const test = require('node:test');
const assert = require('node:assert/strict');
const { TEST_NETWORK_CHAIN_ID, MAX_OUTSTANDING, MAX_PER_MINUTE, createFaucet } = require('./faucet.js');

const FROM = '0x' + '2b'.repeat(20);

const addressFor = (i) => '0x' + i.toString(16).padStart(40, '0');

// A node that takes every transfer and never puts one in a block. Every wait
// for a receipt stays asleep until `hurry()`, which lets them all run out.
function stalledSetup() {
  const node = { sent: [], sleepers: [], hurried: false };
  const rpc = async (method, params) => {
    switch (method) {
      case 'eth_chainId':
        return '0x' + TEST_NETWORK_CHAIN_ID.toString(16);
      case 'eth_getTransactionCount':
        return '0x' + node.sent.length.toString(16);
      case 'eth_gasPrice':
        return '0xa';
      case 'eth_sendRawTransaction':
        node.sent.push(params[0]);
        return '0x' + node.sent.length.toString(16).padStart(64, '0');
      case 'eth_getTransactionReceipt':
        return null;
    }
    throw new Error(`unexpected call ${method}`);
  };
  const sleep = () => (node.hurried ? Promise.resolve() : new Promise((done) => node.sleepers.push(done)));
  node.hurry = () => {
    node.hurried = true;
    for (const done of node.sleepers.splice(0)) done();
  };
  const signer = {
    address: FROM,
    signed: [],
    async signTransaction(tx) {
      signer.signed.push(tx);
      return 'signed:' + tx.to + ':' + tx.nonce;
    },
  };
  const faucet = createFaucet({ signer, rpc, now: () => 1_000_000, sleep });
  const ask = (address) => faucet.handle('POST', '/', JSON.stringify({ address }));
  return { node, signer, ask };
}

// Waits a bounded number of event loop turns for `condition`.
async function until(condition, what) {
  for (let turn = 0; turn < 1000; turn++) {
    if (condition()) return;
    await new Promise((done) => setImmediate(done));
  }
  assert.fail(`timed out waiting: ${what}`);
}

// The answer, or 'still waiting' when it does not come within a few turns.
async function promptly(answer) {
  let settled = 'still waiting';
  answer.then((value) => (settled = value));
  await until(() => settled !== 'still waiting', 'a prompt answer').catch(() => {});
  return settled;
}

test('a second transfer is sent while the first still waits for its receipt', async () => {
  const { node, signer, ask } = stalledSetup();
  let firstDone = false;
  const first = ask(addressFor(1)).then((answer) => {
    firstDone = true;
    return answer;
  });
  await until(() => node.sleepers.length === 1, 'the first transfer waiting for its receipt');
  const second = ask(addressFor(2));
  await until(() => node.sent.length === 2, 'the second transfer sent');
  assert.equal(firstDone, false, 'the first transfer is still waiting for its receipt');
  assert.deepEqual(
    signer.signed.map((tx) => [tx.to, BigInt(tx.nonce)]),
    [
      [addressFor(1), 0n],
      [addressFor(2), 1n],
    ],
    'each transfer took the next nonce',
  );
  node.hurry();
  assert.equal((await first).status, 502);
  assert.equal((await second).status, 502);
});

test(`a request past ${MAX_OUTSTANDING} outstanding transfers gets 503 at once and is not counted`, async () => {
  const { node, ask } = stalledSetup();
  const waiting = [];
  for (let i = 0; i < MAX_OUTSTANDING; i++) waiting.push(ask(addressFor(i)));
  await until(() => node.sleepers.length === MAX_OUTSTANDING, 'every transfer waiting for its receipt');

  const busy = await promptly(ask(addressFor(100)));
  assert.equal(busy.status, 503);
  assert.equal(busy.json.error, 'the faucet is busy; try again in a minute');
  for (let i = 101; i < 101 + MAX_PER_MINUTE; i++) assert.equal((await promptly(ask(addressFor(i)))).status, 503);
  assert.equal(node.sent.length, MAX_OUTSTANDING, 'nothing more was sent');

  // A receipt that never came keeps the address's minute: the transfer may still land.
  node.hurry();
  for (const answer of await Promise.all(waiting)) {
    assert.deepEqual(answer, { status: 502, json: { error: 'the transfer is not in a block yet' } });
  }
  assert.equal((await ask(addressFor(0))).status, 429);

  // The turned-away requests counted neither against their address nor the
  // minute's total: the rest of the 30 are served, then the faucet is busy.
  for (let i = 100; i < 100 + MAX_PER_MINUTE - MAX_OUTSTANDING; i++) {
    assert.equal((await ask(addressFor(i))).status, 502, `address ${i} was served`);
  }
  assert.equal(node.sent.length, MAX_PER_MINUTE);
  assert.equal((await ask(addressFor(500))).status, 503);
});
