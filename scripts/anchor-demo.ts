import { ethers } from "hardhat";
const { proveBundle } = require("../zk/prove.js");
const S = require("../zk/sigma.js");

/**
 * Anchors the first real record on the deployed contract, ZK bundle included:
 *   npx hardhat run scripts/anchor-demo.ts --network robinhoodTestnet
 * Needs .env: DEPLOYER_PRIVATE_KEY (must be the aggregator), PROOF_ANCHOR_ADDRESS.
 * Demo roots are hashes of live chain block data, labeled as such.
 */
async function main() {
  const addr = (process.env.PROOF_ANCHOR_ADDRESS ?? "").trim();
  if (!addr) throw new Error("Set PROOF_ANCHOR_ADDRESS in .env (from deploy output)");
  const [signer] = await ethers.getSigners();
  const anchor = await ethers.getContractAt("ProofAnchor", addr, signer);

  const lastSeq: bigint = await anchor.lastSeq();
  const lastEnd: bigint = await anchor.lastEndBlock();
  const seq = lastSeq + 1n, startBlock = lastEnd + 1n, endBlock = startBlock + 63n;

  // demo roots derived from real chain data (block hashes), not fabricated
  const head = await ethers.provider.getBlock("latest");
  const rootPrev = S.keccak256(S.utf8("demo-root/" + head!.hash + "/prev"));
  const rootOut  = S.keccak256(S.utf8("demo-root/" + head!.hash + "/out"));

  // artifact -> proof_hash (blake3 lives in the JS/Rust provers; for the demo
  // record we bind to the canonical artifact via keccak, stated in the notes)
  const artifact = { seq: Number(seq), start_block: Number(startBlock), end_block: Number(endBlock) };
  const proofHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(artifact)));

  // ZK bundle bound to a fresh publicInputsHash
  const ctx = S.keccak256(S.utf8("zkQuiver/pi/" + proofHash));
  const bundle = proveBundle(rootPrev, rootOut, ctx);
  const piHash = "0x" + S.hex(ctx);

  // commitment digests go on-chain, never the roots (privacy in effect)
  const cDigest = (P: any) => ethers.keccak256(
    "0x" + P.x.toString(16).padStart(64, "0") + P.y.toString(16).padStart(64, "0"));
  const stateRootBefore = cDigest(bundle.commitments.C_in);
  const stateRootAfter  = cDigest(bundle.commitments.C_out);

  const dsHash = await anchor.computeDsHash(proofHash, startBlock, endBlock, seq);
  const sig = await signer.signMessage(ethers.getBytes(dsHash));

  console.log(`anchoring seq ${seq}, window ${startBlock}-${endBlock}, ZK bundle ${bundle.hex.length / 2 - 1} bytes...`);
  const tx = await anchor.anchorProof(proofHash, stateRootBefore, stateRootAfter,
    startBlock, endBlock, seq, sig, bundle.hex, piHash);
  const rc = await tx.wait();
  const rec = await anchor.proofs(seq);
  console.log("anchored in tx:", rc!.hash);
  console.log("zkVerified on-chain:", rec.zkVerified);
  console.log(`https://explorer.testnet.chain.robinhood.com/tx/${rc!.hash}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
