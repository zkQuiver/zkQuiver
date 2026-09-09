// zkQuiver relayer: submits a visitor's proof bundle to PublicProofs on
// Robinhood Chain, paying gas from a funded relayer wallet.
//
// Safety model:
//   - RELAYER_PRIVATE_KEY lives ONLY in Netlify environment variables
//     (Site configuration > Environment variables), never in the repo.
//   - Preflight with a free eth_call: invalid proofs never cost gas.
//   - Per-IP limit and a global daily cap (Netlify Blobs) so the wallet
//     cannot be drained; refuses when balance drops below MIN_BALANCE_ETH.
//   - Only PublicProofs.submit is ever called, with a fixed gas limit.
const { ethers } = require("ethers");
const { getStore } = require("@netlify/blobs");

const RPC = process.env.RPC_URL || "https://rpc.testnet.chain.robinhood.com";
const PUBLIC_PROOFS = process.env.PUBLIC_PROOFS_ADDRESS;
const KEY = (process.env.RELAYER_PRIVATE_KEY || "").trim();
const PER_IP_PER_DAY = Number(process.env.RELAY_PER_IP_PER_DAY || 2);
const GLOBAL_PER_DAY = Number(process.env.RELAY_GLOBAL_PER_DAY || 300);
const MIN_BALANCE_ETH = process.env.RELAY_MIN_BALANCE_ETH || "0.001";
const EXPLORER = process.env.EXPLORER_TX || "https://explorer.testnet.chain.robinhood.com/tx/";

const ABI = [
  "function check(bytes proof, bytes32 ctx) view returns (bool)",
  "function submit(bytes proof, bytes32 ctx, bytes32 tag) returns (uint256)",
  "event ProofRecorded(uint256 indexed id, address indexed submitter, bytes32 indexed ctx, bytes32 tag, bytes32 bundleHash)",
];
const json = (status, body) => ({ statusCode: status, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "POST only" });
  if (!KEY || !PUBLIC_PROOFS) return json(503, { error: "relayer not configured" });

  let body; try { body = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "bad json" }); }
  const { proof, ctx, tag } = body;
  if (!/^0x[0-9a-f]{1472}$/i.test(proof || "")) return json(400, { error: "proof must be 736 bytes hex" });
  if (!/^0x[0-9a-f]{64}$/i.test(ctx || "")) return json(400, { error: "ctx must be bytes32" });
  const tagHex = /^0x[0-9a-f]{64}$/i.test(tag || "") ? tag : ethers.ZeroHash;

  // ---- rate limits (Netlify Blobs) ----
  const ip = (event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "unknown").split(",")[0].trim();
  const day = new Date().toISOString().slice(0, 10);
  const store = getStore("zkquiver-relay");
  const ipKey = `ip:${day}:${ip}`, gKey = `global:${day}`;
  const ipN = Number((await store.get(ipKey)) || 0), gN = Number((await store.get(gKey)) || 0);
  if (ipN >= PER_IP_PER_DAY) return json(429, { error: `limit reached: ${PER_IP_PER_DAY} free submissions per day. You can still submit with your own wallet.` });
  if (gN >= GLOBAL_PER_DAY) return json(429, { error: "daily relayer budget exhausted; submit with your own wallet or try tomorrow" });

  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(KEY.startsWith("0x") ? KEY : "0x" + KEY, provider);
  const pub = new ethers.Contract(PUBLIC_PROOFS, ABI, wallet);

  const bal = await provider.getBalance(wallet.address);
  if (bal < ethers.parseEther(MIN_BALANCE_ETH)) return json(503, { error: "relayer wallet is low on gas; submit with your own wallet" });

  // ---- free preflight: never pay for an invalid or duplicate proof ----
  if (!(await pub.check(proof, ctx))) return json(422, { error: "proof rejected by the on-chain verifier (or already recorded)" });

  await store.set(ipKey, String(ipN + 1)); await store.set(gKey, String(gN + 1));
  try {
    const tx = await pub.submit(proof, ctx, tagHex, { gasLimit: 900000 });
    const rc = await tx.wait();
    let id = null;
    for (const log of rc.logs) { try { const p = pub.interface.parseLog(log); if (p?.name === "ProofRecorded") id = p.args.id.toString(); } catch {} }
    return json(200, { txHash: rc.hash, id, explorer: EXPLORER + rc.hash, submitter: wallet.address });
  } catch (e) {
    return json(500, { error: "submission failed: " + (e.shortMessage || e.message) });
  }
};
