import express from "express";
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { ethers } from "ethers";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { proveBundle } = require("../../zk/prove.js");
const S = require("../../zk/sigma.js");
import {
  Artifact,
  canonicalize,
  proofHash,
  publicInputsHash,
  buildDsMessage,
  dsHash,
} from "./canonical.js";

/**
 * zkQuiver Orchestrator — artifact lifecycle service.
 * Endpoints: /artifact, /anchor, /prove, /proof/:artifact_id, /health.
 * Idempotency via Idempotency-Key header.
 */

const PORT = Number(process.env.PORT ?? 8080);
const RPC_URL = process.env.RPC_URL ?? "https://rpc.testnet.chain.robinhood.com";
const CONTRACT = process.env.PROOF_ANCHOR_ADDRESS ?? "";
const AGGREGATOR_KEY = (process.env.AGGREGATOR_PRIVATE_KEY ?? "").trim().replace(/^["']|["']$/g, "");
// Key material is never logged. Only the derived address is ever printed.
const SUBMITTER_KEY = process.env.SUBMITTER_PRIVATE_KEY ?? AGGREGATOR_KEY;
const ARTIFACT_DIR = process.env.ARTIFACT_DIR ?? "./data/artifacts";

const ABI = [
  "function anchorProof(bytes32 proofHash, bytes32 stateRootBefore, bytes32 stateRootAfter, uint64 startBlock, uint64 endBlock, uint64 seq, bytes aggregatorSig, bytes zkProof, bytes32 publicInputsHash)",
  "function lastSeq() view returns (uint64)",
  "function lastEndBlock() view returns (uint64)",
  "function computeDsHash(bytes32 proofHash, uint64 startBlock, uint64 endBlock, uint64 seq) view returns (bytes32)",
];

const provider = new ethers.JsonRpcProvider(RPC_URL);
const aggregatorWallet = AGGREGATOR_KEY ? new ethers.Wallet(AGGREGATOR_KEY) : null;
const submitterWallet = SUBMITTER_KEY ? new ethers.Wallet(SUBMITTER_KEY, provider) : null;
const contract = CONTRACT && submitterWallet ? new ethers.Contract(CONTRACT, ABI, submitterWallet) : null;

const idempotency = new Map<string, unknown>();
const artifactsById = new Map<string, Artifact>();

function idemKey(req: express.Request): string {
  const k = req.header("Idempotency-Key");
  if (!k) throw Object.assign(new Error("Idempotency-Key header required"), { status: 400 });
  return k;
}

function storeArtifact(artifact: Artifact): string {
  const d = new Date();
  const dir = path.join(
    ARTIFACT_DIR,
    String(d.getUTCFullYear()),
    String(d.getUTCMonth() + 1).padStart(2, "0"),
    String(d.getUTCDate()).padStart(2, "0")
  );
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${artifact.artifact_id}.json`);
  writeFileSync(file, canonicalize(artifact));
  return file;
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.post("/artifact", (req, res) => {
  try {
    const key = idemKey(req);
    if (idempotency.has(key)) return res.status(200).json(idempotency.get(key));

    const b = req.body ?? {};
    const hex32 = /^[0-9a-f]{64}$/;
    if (
      !Number.isInteger(b.start_block) || !Number.isInteger(b.end_block) ||
      b.end_block < b.start_block ||
      !hex32.test(b.state_root_before ?? "") || !hex32.test(b.state_root_after ?? "")
    ) {
      return res.status(400).json({ error: "invalid artifact format" });
    }

    const artifact: Artifact = {
      artifact_id: randomUUID().toLowerCase(),
      start_block: b.start_block,
      end_block: b.end_block,
      state_root_before: b.state_root_before,
      state_root_after: b.state_root_after,
      ...(b.public_inputs ? { public_inputs: b.public_inputs } : {}),
    };

    const ph = proofHash(artifact);
    const filePath = storeArtifact(artifact);
    artifactsById.set(artifact.artifact_id, artifact);

    const out = {
      artifact_id: artifact.artifact_id,
      proof_hash: ph,
      status: "canonicalized",
      file_path: filePath,
    };
    idempotency.set(key, out);
    res.status(201).json(out);
  } catch (e: any) {
    res.status(e.status ?? 500).json({ error: e.message });
  }
});

app.post("/anchor", async (req, res) => {
  try {
    const key = idemKey(req);
    if (idempotency.has(key)) return res.status(200).json(idempotency.get(key));
    if (!contract || !aggregatorWallet) {
      return res.status(500).json({ error: "contract or keys not configured" });
    }

    const artifact = artifactsById.get(req.body?.artifact_id);
    if (!artifact) return res.status(404).json({ error: "artifact not found" });

    const network = await provider.getNetwork();
    const lastSeq: bigint = await contract.lastSeq();
    const seq = lastSeq + 1n;

    const ph = proofHash(artifact);
    const ds = buildDsMessage({
      chainId: network.chainId,
      contractAddress: CONTRACT,
      proofHashHex: ph,
      startBlock: BigInt(artifact.start_block),
      endBlock: BigInt(artifact.end_block),
      seq,
    });
    const dh = dsHash(ds);

    // Sanity: local DS hash must match the contract's view function.
    const onchainDs: string = await contract.computeDsHash(
      "0x" + ph, artifact.start_block, artifact.end_block, seq
    );
    if (onchainDs.toLowerCase() !== "0x" + dh) {
      return res.status(500).json({ error: "DS conformance mismatch", local: dh, onchain: onchainDs });
    }

    // Aggregator signs the DS hash (EIP-191 personal message).
    const sig = await aggregatorWallet.signMessage(ethers.getBytes("0x" + dh));

    // Zero-knowledge bundle (sigma layer): commit to the roots, prove the
    // openings and the lineage link, bound to the public-inputs hash.
    const piHash = publicInputsHash(artifact);
    const hexToU8 = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
    const bundle = proveBundle(
      hexToU8(artifact.state_root_before),
      hexToU8(artifact.state_root_after),
      hexToU8(piHash)
    );
    // On-chain we anchor commitment digests, never the roots (privacy).
    const cDigest = (P: any) => ethers.keccak256(
      "0x" + P.x.toString(16).padStart(64, "0") + P.y.toString(16).padStart(64, "0"));

    const tx = await contract.anchorProof(
      "0x" + ph,
      cDigest(bundle.commitments.C_in),
      cDigest(bundle.commitments.C_out),
      artifact.start_block,
      artifact.end_block,
      seq,
      sig,
      bundle.hex,
      "0x" + piHash
    );
    const receipt = await tx.wait();

    const out = {
      txid: receipt.hash,
      seq: Number(seq),
      ds_hash: dh,
      status: "anchored",
      block_number: receipt.blockNumber,
    };
    idempotency.set(key, out);
    res.json(out);
  } catch (e: any) {
    res.status(e.status ?? 500).json({ error: e.message });
  }
});

app.post("/prove", async (req, res) => {
  // /artifact + /anchor in one call, with derived idempotency keys.
  try {
    const key = idemKey(req);
    if (idempotency.has(key)) return res.status(200).json(idempotency.get(key));
    const base = `http://127.0.0.1:${PORT}`;
    const hdr = (k: string) => ({ "Content-Type": "application/json", "Idempotency-Key": k });
    const a = await fetch(`${base}/artifact`, { method: "POST", headers: hdr(key + ":artifact"), body: JSON.stringify(req.body) });
    const aj: any = await a.json();
    if (!a.ok) return res.status(a.status).json(aj);
    const b = await fetch(`${base}/anchor`, { method: "POST", headers: hdr(key + ":anchor"), body: JSON.stringify({ artifact_id: aj.artifact_id }) });
    const bj: any = await b.json();
    if (!b.ok) return res.status(b.status).json(bj);
    const out = { ...aj, ...bj, status: "proved_and_anchored" };
    idempotency.set(key, out);
    res.json(out);
  } catch (e: any) {
    res.status(e.status ?? 500).json({ error: e.message });
  }
});

app.get("/proof/:artifact_id", (req, res) => {
  const artifact = artifactsById.get(req.params.artifact_id);
  if (!artifact) return res.status(404).json({ error: "not found" });
  res.json({ ...artifact, proof_hash: proofHash(artifact) });
});

app.get("/health", async (_req, res) => {
  res.json({ status: "healthy", version: "0.1.0", rpc_url: RPC_URL, contract: CONTRACT || null });
});

app.listen(PORT, () => {
  console.log(`zkQuiver orchestrator listening on :${PORT}`);
  if (aggregatorWallet) console.log(`aggregator address: ${aggregatorWallet.address}`); // address only, never the key
});
