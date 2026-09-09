// zkQuiver relayer: submits a visitor's proof bundle to PublicProofs on
// Robinhood Chain, paying gas from a funded relayer wallet.
//
// Safety model:
//   - RELAYER_PRIVATE_KEY lives ONLY in Netlify environment variables.
//   - Free preflight (eth_call): invalid proofs never cost gas.
//   - Per-IP and global daily caps (Netlify Blobs when available, with an
//     in-memory fallback), refuses below MIN_BALANCE_ETH.
//   - Only PublicProofs.submit is ever called, with a fixed gas limit.
//   - Always answers JSON, even on internal errors.
//   - GET returns a health report (never the key).
const { ethers } = require("ethers");

const RPC = process.env.RPC_URL || "https://rpc.testnet.chain.robinhood.com";
const PUBLIC_PROOFS = (process.env.PUBLIC_PROOFS_ADDRESS || "").trim();
const KEY = (process.env.RELAYER_PRIVATE_KEY || "").trim().replace(/^["']|["']$/g, "");
const PER_IP_PER_DAY = Number(process.env.RELAY_PER_IP_PER_DAY || 2);
const GLOBAL_PER_DAY = Number(process.env.RELAY_GLOBAL_PER_DAY || 300);
const MIN_BALANCE_ETH = process.env.RELAY_MIN_BALANCE_ETH || "0.0005";
const EXPLORER = process.env.EXPLORER_TX || "https://explorer.testnet.chain.robinhood.com/tx/";

const ABI = [
  "function check(bytes proof, bytes32 ctx) view returns (bool)",
  "function submit(bytes proof, bytes32 ctx, bytes32 tag) returns (uint256)",
];
const json = (status, body) => ({
  statusCode: status,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(body),
});

// ---- rate-limit store: Netlify Blobs (persistent), memory fallback ----
// Lambda-style handlers must hand the request to Blobs first
// (connectLambda) or getStore() throws "environment not configured",
// which is what made earlier deploys fall back to memory.
const mem = new Map();
let blobsReady = false, blobsError = null;
function initBlobs(event) {
  try {
    const { connectLambda } = require("@netlify/blobs");
    connectLambda(event);
    blobsReady = true;
  } catch (e) { blobsReady = false; blobsError = e.message; }
}
async function counter(key) {
  if (blobsReady) {
    try {
      const { getStore } = require("@netlify/blobs");
      const store = getStore("zkquiver-relay"); // default consistency: strong mode needs an edge config Lambda-style functions lack
      const v = await store.get(key);
      return { n: Number(v || 0), bump: async () => store.set(key, String(Number(v || 0) + 1)), backend: "blobs" };
    } catch (e) { blobsError = e.message; }
  }
  const n = mem.get(key) || 0;
  return { n, bump: async () => mem.set(key, n + 1), backend: "memory" };
}

exports.handler = async (event) => {
  try {
    initBlobs(event);
    const provider = new ethers.JsonRpcProvider(RPC);

    // ---- GET: health, never secrets ----
    if (event.httpMethod === "GET") {
      const out = { configured: Boolean(KEY && PUBLIC_PROOFS), publicProofs: PUBLIC_PROOFS || null, rpc: RPC };
      if (KEY) {
        const w = new ethers.Wallet(KEY.startsWith("0x") ? KEY : "0x" + KEY);
        out.relayer = w.address;
        try { out.balanceEth = ethers.formatEther(await provider.getBalance(w.address)); } catch (e) { out.balanceEth = "rpc error: " + e.message; }
      }
      const c = await counter("probe");
      out.rateLimitBackend = c.backend;
      if (c.backend !== "blobs") out.rateLimitNote = "persistent store unavailable: " + (blobsError || "unknown") + "; using per-instance memory";
      out.limits = { perIpPerDay: PER_IP_PER_DAY, globalPerDay: GLOBAL_PER_DAY };
      return json(200, out);
    }
    if (event.httpMethod !== "POST") return json(405, { error: "POST only" });
    if (!KEY || !PUBLIC_PROOFS) return json(503, { error: "relayer not configured (RELAYER_PRIVATE_KEY / PUBLIC_PROOFS_ADDRESS missing)" });

    let body; try { body = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "bad json" }); }
    const { proof, ctx, tag } = body;
    if (!/^0x[0-9a-f]{1472}$/i.test(proof || "")) return json(400, { error: "proof must be 736 bytes hex" });
    if (!/^0x[0-9a-f]{64}$/i.test(ctx || "")) return json(400, { error: "ctx must be bytes32" });
    const tagHex = /^0x[0-9a-f]{64}$/i.test(tag || "") ? tag : ethers.ZeroHash;

    // ---- rate limits ----
    const ip = (event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || event.headers["x-forwarded-for"] || "unknown").split(",")[0].trim();
    const day = new Date().toISOString().slice(0, 10);
    const ipC = await counter(`ip:${day}:${ip}`), gC = await counter(`global:${day}`);
    if (ipC.n >= PER_IP_PER_DAY) return json(429, { error: `limit reached: ${PER_IP_PER_DAY} free submissions per day. You can still record with your own wallet.` });
    if (gC.n >= GLOBAL_PER_DAY) return json(429, { error: "daily relayer budget exhausted; record with your own wallet or try tomorrow" });

    const wallet = new ethers.Wallet(KEY.startsWith("0x") ? KEY : "0x" + KEY, provider);
    const pub = new ethers.Contract(PUBLIC_PROOFS, ABI, wallet);

    const bal = await provider.getBalance(wallet.address);
    if (bal < ethers.parseEther(MIN_BALANCE_ETH)) return json(503, { error: "relayer wallet is low on gas; record with your own wallet" });

    // ---- free preflight ----
    let ok = false;
    try { ok = await pub.check(proof, ctx); } catch (e) { return json(502, { error: "preflight call failed: " + (e.shortMessage || e.message) }); }
    if (!ok) return json(422, { error: "proof rejected by the on-chain verifier (or already recorded)" });

    await ipC.bump(); await gC.bump();

    // ---- send, return immediately (no wait: stays under the function timeout) ----
    const tx = await pub.submit(proof, ctx, tagHex, { gasLimit: 900000 });
    return json(200, { txHash: tx.hash, explorer: EXPLORER + tx.hash, submitter: wallet.address, status: "submitted" });
  } catch (e) {
    return json(500, { error: "relayer error: " + (e.shortMessage || e.message || String(e)) });
  }
};
