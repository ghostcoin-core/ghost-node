'use strict';
// The Ghost public test network faucet, beside this computer's Ghost node.
// POST {"address": "0x…"} and the node's mining account sends 10 test GHOST
// there, at most once a minute per address and 30 times a minute in all. It
// answers once the transfer is in a block: {"transactionHash": "0x…"}, or
// {"error": "…"} with 400, 404, 405, 413, 429, 502 or 503.
//
// It runs only on the public test network (chain 6777972): it checks the
// node's and the signer's chain id at start and before every transfer, and
// refuses to send on any other chain. It listens on 127.0.0.1 only; Tailscale
// Funnel publishes it at https://<host>/ghost-faucet. The public node keeps no
// unlocked account: each transfer is signed (Ghost's quantum-safe signature)
// by a separate signer geth that has no peers, no HTTP and no chain, and
// answers only on its own IPC socket (ghost-faucet-signer.service), then sent
// raw to the node.
//
//   node faucet.js   # env: GHOST_NODE_DIR (~/.ghost-node), FAUCET_SIGNER_IPC, FAUCET_PORT (8548)

const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const TEST_NETWORK_CHAIN_ID = 6777972n;
const FAUCET_WEI = 10n * 10n ** 18n;
const ONCE_EVERY_MS = 60_000;
const MAX_PER_MINUTE = 30;
// Transfers queued or waiting for a receipt at once; more are turned away.
const MAX_OUTSTANDING = 10;
const MAX_BODY_BYTES = 1024;
const RECEIPT_TRIES = 180;
const TRANSFER_GAS = 150_000;

// One JSON-RPC call to the node over HTTP.
function nodeRpc(url) {
  let id = 0;
  return async (method, params) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`the node answered HTTP ${response.status}`);
    const answer = await response.json();
    if (answer.error) throw new Error(String(answer.error.message || 'the node refused the call'));
    return answer.result;
  };
}

// One JSON-RPC call over a geth IPC socket.
function ipcRpc(socketPath) {
  let id = 0;
  return (method, params) =>
    new Promise((resolve, reject) => {
      const socket = net.createConnection(socketPath);
      let text = '';
      const timer = setTimeout(() => socket.destroy(new Error('the signer did not answer')), 15_000);
      socket.setEncoding('utf8');
      socket.on('connect', () => socket.write(JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params })));
      socket.on('data', (chunk) => {
        text += chunk;
        let answer;
        try {
          answer = JSON.parse(text);
        } catch {
          return;
        }
        clearTimeout(timer);
        socket.end();
        if (answer.error) reject(new Error(String(answer.error.message || 'the signer refused the call')));
        else resolve(answer.result);
      });
      socket.on('error', (error) => {
        clearTimeout(timer);
        reject(new Error(`the signer is not reachable: ${error.message}`));
      });
    });
}

async function checkTestNetwork(rpc) {
  const chainId = BigInt(await rpc('eth_chainId', []));
  if (chainId !== TEST_NETWORK_CHAIN_ID) {
    throw new Error(`the node is on chain ${chainId}, not the public test network`);
  }
}

// `signer.signTransaction(tx)` returns the raw signed transfer from
// `signer.address`; `rpc` is the node's JSON-RPC.
function createFaucet({ signer, rpc, now = Date.now, sleep = (ms) => new Promise((done) => setTimeout(done, ms)) }) {
  const lastSent = new Map();
  // Addresses with a transfer queued or in flight: one at a time per address.
  const pending = new Set();
  let recent = [];
  // Transfers queued to be sent or waiting for their receipt.
  let outstanding = 0;
  let submitting = Promise.resolve();

  // Signs and sends one transfer and returns its hash. Only this runs one at a
  // time, so each transfer takes the next pending nonce.
  async function submit(to) {
    await checkTestNetwork(rpc);
    const [nonce, gasPrice] = await Promise.all([
      rpc('eth_getTransactionCount', [signer.address, 'pending']),
      rpc('eth_gasPrice', []),
    ]);
    const raw = await signer.signTransaction({
      from: signer.address,
      to,
      value: '0x' + FAUCET_WEI.toString(16),
      nonce: '0x' + BigInt(nonce).toString(16),
      // Ghost's quantum-safe signature adds tens of thousands of intrinsic gas
      // (83,744 in all for this account) that eth_estimateGas leaves out;
      // unused gas is refunded, so the limit is set with room to spare.
      gas: '0x' + TRANSFER_GAS.toString(16),
      gasPrice: '0x' + ((BigInt(gasPrice) * 12n) / 10n).toString(16),
    });
    return rpc('eth_sendRawTransaction', [raw]);
  }

  // The receipt once the transfer is in a block, or null when it is not in one
  // after RECEIPT_TRIES tries. Several transfers may wait at once.
  async function inBlock(hash) {
    for (let tries = 0; tries < RECEIPT_TRIES; tries++) {
      const receipt = await rpc('eth_getTransactionReceipt', [hash]);
      if (receipt && receipt.blockNumber) return receipt;
      await sleep(1000);
    }
    return null;
  }

  async function handle(method, url, text) {
    const pathname = String(url || '/').split('?')[0];
    if (pathname !== '/' && pathname !== '/faucet') return { status: 404, json: { error: 'not found' } };
    if (method !== 'POST') return { status: 405, json: { error: 'POST an address to get 10 test GHOST' } };
    let address;
    try {
      address = JSON.parse(text).address;
    } catch {
      address = undefined;
    }
    if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
      return { status: 400, json: { error: 'that is not a Ghost address' } };
    }
    const key = address.toLowerCase();
    const at = now();
    const last = lastSent.get(key);
    if (pending.has(key) || (last !== undefined && at - last < ONCE_EVERY_MS)) {
      return { status: 429, json: { error: 'test GHOST goes to each address at most once a minute' } };
    }
    // A busy faucet turns the request away before it counts against the
    // address's minute or the minute's total.
    if (outstanding >= MAX_OUTSTANDING) {
      return { status: 503, json: { error: 'the faucet is busy; try again in a minute' } };
    }
    recent = recent.filter((t) => at - t < ONCE_EVERY_MS);
    if (recent.length >= MAX_PER_MINUTE) {
      return { status: 503, json: { error: 'the faucet is busy; try again in a minute' } };
    }
    for (const [k, t] of lastSent) if (at - t >= ONCE_EVERY_MS) lastSent.delete(k);
    lastSent.set(key, at);
    recent.push(at);
    pending.add(key);
    outstanding++;
    try {
      // The minute starts again when the transfer is sent, not when it was queued.
      const submitted = submitting.then(() => {
        lastSent.set(key, now());
        return submit(key);
      });
      submitting = submitted.catch(() => {});
      let transactionHash;
      try {
        transactionHash = await submitted;
      } catch (error) {
        // Nothing was sent: the address may ask again at once.
        lastSent.delete(key);
        return { status: 502, json: { error: error.message } };
      }
      // From here the transfer may land, so the address keeps its minute
      // unless its block shows it moved nothing.
      let receipt;
      try {
        receipt = await inBlock(transactionHash);
      } catch (error) {
        return { status: 502, json: { error: error.message } };
      }
      if (!receipt) return { status: 502, json: { error: 'the transfer is not in a block yet' } };
      if (BigInt(receipt.status) !== 1n) {
        lastSent.delete(key);
        return { status: 502, json: { error: 'the transfer failed in its block' } };
      }
      return { status: 200, json: { transactionHash } };
    } finally {
      outstanding--;
      pending.delete(key);
    }
  }

  return { handle };
}

module.exports = {
  TEST_NETWORK_CHAIN_ID,
  FAUCET_WEI,
  ONCE_EVERY_MS,
  MAX_PER_MINUTE,
  MAX_OUTSTANDING,
  createFaucet,
  checkTestNetwork,
};

async function main() {
  const nodeDir = process.env.GHOST_NODE_DIR || path.join(os.homedir(), '.ghost-node');
  const port = Number(process.env.FAUCET_PORT || 8548);
  const signerIpc = process.env.FAUCET_SIGNER_IPC || path.join(__dirname, 'signer', 'signer.ipc');
  const config = fs.readFileSync(path.join(nodeDir, 'config.toml'), 'utf8');
  const etherbase = /Etherbase\s*=\s*"(0x[0-9a-fA-F]{40})"/.exec(config);
  const httpPort = /HTTPPort\s*=\s*(\d+)/.exec(config);
  if (!etherbase) throw new Error('no Etherbase in the node config');
  const rpc = nodeRpc(`http://127.0.0.1:${httpPort ? httpPort[1] : 8545}`);
  await checkTestNetwork(rpc);
  const signerRpc = ipcRpc(signerIpc);
  // The signer signs for its own chain id, so it must be on the test network too.
  await checkTestNetwork(signerRpc);
  const from = etherbase[1].toLowerCase();
  const accounts = (await signerRpc('eth_accounts', [])).map((a) => a.toLowerCase());
  if (!accounts.includes(from)) throw new Error('the signer does not hold the Etherbase key');
  const signer = {
    address: from,
    async signTransaction(tx) {
      const signed = await signerRpc('eth_signTransaction', [tx]);
      if (!signed || !signed.tx || BigInt(signed.tx.chainId) !== TEST_NETWORK_CHAIN_ID) {
        throw new Error('the signer did not sign for the public test network');
      }
      return signed.raw;
    },
  };
  const faucet = createFaucet({ signer, rpc });
  const server = http.createServer((request, response) => {
    let text = '';
    let tooBig = false;
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      text += chunk;
      if (text.length > MAX_BODY_BYTES && !tooBig) {
        tooBig = true;
        response.writeHead(413, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ error: 'too large' }));
        request.destroy();
      }
    });
    request.on('end', async () => {
      if (tooBig) return;
      const { status, json } = await faucet.handle(request.method, request.url, text);
      process.stderr.write(`ghost-faucet: ${status} ${json.transactionHash || json.error}\n`);
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(json));
    });
  });
  server.requestTimeout = 300_000;
  server.listen(port, '127.0.0.1', () => process.stderr.write(`ghost-faucet: sending from ${from} on 127.0.0.1:${port}\n`));
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`ghost-faucet: ${error.message}\n`);
    process.exit(1);
  });
}
