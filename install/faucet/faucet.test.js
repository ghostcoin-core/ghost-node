'use strict';
// The faucet's own tests, with a stand-in node and signer and a clock the test
// moves by hand:  node --test install/faucet/

const test = require('node:test');
const assert = require('node:assert/strict');
const { TEST_NETWORK_CHAIN_ID, FAUCET_WEI, ONCE_EVERY_MS, MAX_PER_MINUTE, createFaucet, checkTestNetwork } = require('./faucet.js');

const ADDRESS = '0x' + '1a'.repeat(20);
const FROM = '0x' + '2b'.repeat(20);
const HASH = '0x' + 'cd'.repeat(32);

// A node on chain `chainId` that mines every transfer into the next block.
function fakeNode(chainId = TEST_NETWORK_CHAIN_ID) {
  const node = {
    chainId,
    calls: [],
    async rpc(method, params) {
      node.calls.push(method);
      switch (method) {
        case 'eth_chainId':
          return '0x' + node.chainId.toString(16);
        case 'eth_getTransactionCount':
          return '0x7';
        case 'eth_gasPrice':
          return '0xa';
        case 'eth_sendRawTransaction':
          assert.equal(params[0], '0xsignedtransfer');
          return HASH;
        case 'eth_getTransactionReceipt':
          return { blockNumber: '0x1', status: '0x1' };
      }
      throw new Error(`unexpected call ${method}`);
    },
  };
  return node;
}

// A signer that signs every transfer, or refuses while `fail` is set.
function fakeSigner() {
  const signer = {
    address: FROM,
    signed: [],
    fail: false,
    async signTransaction(tx) {
      if (signer.fail) throw new Error('the signer is not reachable');
      signer.signed.push(tx);
      return '0xsignedtransfer';
    },
  };
  return signer;
}

function setup(chainId) {
  const node = fakeNode(chainId);
  const signer = fakeSigner();
  const clock = { at: 1_000_000 };
  const faucet = createFaucet({ signer, rpc: node.rpc, now: () => clock.at, sleep: async () => {} });
  const ask = (address = ADDRESS) => faucet.handle('POST', '/', JSON.stringify({ address }));
  return { node, signer, clock, faucet, ask };
}

test('an address gets 10 test GHOST, then 429 within a minute, then again after a minute', async () => {
  const { signer, clock, ask } = setup();
  assert.deepEqual(await ask(), { status: 200, json: { transactionHash: HASH } });
  assert.equal(signer.signed.length, 1);
  assert.equal(signer.signed[0].to, ADDRESS);
  assert.equal(signer.signed[0].from, FROM);
  assert.equal(BigInt(signer.signed[0].value), FAUCET_WEI);

  clock.at += ONCE_EVERY_MS - 1;
  const again = await ask();
  assert.equal(again.status, 429);
  assert.match(again.json.error, /once a minute/);
  assert.equal((await ask(ADDRESS.toUpperCase().replace('0X', '0x'))).status, 429, 'the minute is per address, in any case');
  assert.equal(signer.signed.length, 1, 'nothing more was signed within the minute');

  // Another address is served within the minute.
  assert.equal((await ask('0x' + '3c'.repeat(20))).status, 200);

  clock.at += 1;
  assert.equal((await ask()).status, 200);
  assert.equal(signer.signed.length, 3);
});

test('a failed transfer lets the address ask again at once', async () => {
  const { signer, ask } = setup();
  signer.fail = true;
  const failed = await ask();
  assert.equal(failed.status, 502);
  assert.match(failed.json.error, /signer/);
  signer.fail = false;
  assert.deepEqual(await ask(), { status: 200, json: { transactionHash: HASH } });
  assert.equal(signer.signed.length, 1);
});

test('a transfer that failed in its block lets the address ask again at once', async () => {
  const node = fakeNode();
  let failing = true;
  const faucet = createFaucet({
    signer: fakeSigner(),
    rpc: async (method, params) => {
      if (method === 'eth_getTransactionReceipt' && failing) return { blockNumber: '0x1', status: '0x0' };
      return node.rpc(method, params);
    },
    now: () => 0,
    sleep: async () => {},
  });
  const body = JSON.stringify({ address: ADDRESS });
  const failed = await faucet.handle('POST', '/', body);
  assert.equal(failed.status, 502);
  assert.match(failed.json.error, /failed in its block/);
  failing = false;
  assert.equal((await faucet.handle('POST', '/', body)).status, 200);
});

test('checkTestNetwork accepts the public test network only', async () => {
  await checkTestNetwork(fakeNode().rpc);
  for (const chainId of [1n, 6777971n, 6777973n, 1337n]) {
    await assert.rejects(checkTestNetwork(fakeNode(chainId).rpc), /not the public test network/, `chain ${chainId}`);
  }
});

test('a node on another chain makes the faucet refuse to send, and nothing is signed', async () => {
  const { node, signer, ask } = setup(1n);
  const refused = await ask();
  assert.equal(refused.status, 502);
  assert.match(refused.json.error, /not the public test network/);
  assert.equal(signer.signed.length, 0);
  assert.ok(!node.calls.includes('eth_sendRawTransaction'), 'nothing was sent');

  // The check runs before every transfer, not only at start.
  node.chainId = TEST_NETWORK_CHAIN_ID;
  assert.equal((await ask()).status, 200);
  node.chainId = 5n;
  const other = '0x' + '4d'.repeat(20);
  assert.equal((await ask(other)).status, 502);
  assert.equal(signer.signed.length, 1);
});

test('a signer on another chain is refused by the same check', async () => {
  const signerRpc = async (method) => {
    assert.equal(method, 'eth_chainId');
    return '0x1';
  };
  await assert.rejects(checkTestNetwork(signerRpc), /not the public test network/);
});

test('a bad address gets 400 and nothing is signed', async () => {
  const { signer, faucet } = setup();
  for (const address of [null, 42, '', '0x1234', ADDRESS.slice(2), ADDRESS + '00', '0x' + 'zz'.repeat(20), ' ' + ADDRESS]) {
    const answer = await faucet.handle('POST', '/', JSON.stringify({ address }));
    assert.equal(answer.status, 400, `address ${address}`);
    assert.equal(answer.json.error, 'that is not a Ghost address');
  }
  for (const body of ['', 'not json', 'null', '[]', '{"to":"' + ADDRESS + '"}']) {
    assert.equal((await faucet.handle('POST', '/', body)).status, 400, `body ${body}`);
  }
  assert.equal(signer.signed.length, 0);
});

test('only POST to / or /faucet is served', async () => {
  const { signer, faucet } = setup();
  const body = JSON.stringify({ address: ADDRESS });
  assert.equal((await faucet.handle('GET', '/', '')).status, 405);
  assert.equal((await faucet.handle('POST', '/other', body)).status, 404);
  assert.equal((await faucet.handle('POST', '/faucet?x=1', body)).status, 200);
  assert.equal(signer.signed.length, 1);
});

test('at most 30 transfers a minute in all', async () => {
  const { signer, clock, ask } = setup();
  for (let i = 0; i < MAX_PER_MINUTE; i++) {
    assert.equal((await ask('0x' + i.toString(16).padStart(40, '0'))).status, 200);
  }
  const busy = await ask();
  assert.equal(busy.status, 503);
  assert.equal(signer.signed.length, MAX_PER_MINUTE);
  clock.at += ONCE_EVERY_MS;
  assert.equal((await ask()).status, 200);
});
