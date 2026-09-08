import { ethers } from "ethers";
import pg from "pg";

/**
 * zkQuiver Indexer — syncs on-chain proof records to Postgres.
 *
 * Commitment levels track EVM block tags:
 *   0 -> "latest", 1 -> "safe", 2 -> "finalized"
 * Since Robinhood Chain is an Arbitrum-stack L2, "finalized" reflects
 * L1 (Ethereum) finality of the batch containing the transaction.
 */

const RPC_URL = process.env.RPC_URL ?? "https://rpc.testnet.chain.robinhood.com";
const CONTRACT = process.env.PROOF_ANCHOR_ADDRESS ?? "";
const DATABASE_URL = process.env.DATABASE_URL ?? "postgresql://postgres:postgres@localhost:5432/zkquiver";
const POLL_MS = Number(process.env.POLL_MS ?? 15_000);

const ABI = [
  "event ProofAnchored(uint64 indexed seq, bytes32 indexed proofHash, bytes32 dsHash, uint64 startBlock, uint64 endBlock, address submittedBy, bool zkVerified)",
  "event ValidatorRegistered(address indexed validator, uint64 lockTs)",
  "event ValidatorUnlocked(address indexed validator, uint64 unlockTs)",
];

const provider = new ethers.JsonRpcProvider(RPC_URL);
const contract = new ethers.Contract(CONTRACT, ABI, provider);
const db = new pg.Pool({ connectionString: DATABASE_URL });

async function loadCursor(): Promise<number> {
  const r = await db.query("SELECT last_block FROM indexer_state WHERE id = 1");
  return r.rows[0]?.last_block ?? 0;
}

async function saveCursor(block: number): Promise<void> {
  await db.query(
    `INSERT INTO indexer_state (id, last_block, last_scan_ts) VALUES (1, $1, now())
     ON CONFLICT (id) DO UPDATE SET last_block = $1, last_scan_ts = now()`,
    [block]
  );
}

async function scan(): Promise<void> {
  const from = (await loadCursor()) + 1;
  const to = await provider.getBlockNumber();
  if (to < from) return;

  const chunk = 5_000;
  for (let start = from; start <= to; start += chunk) {
    const end = Math.min(start + chunk - 1, to);
    const events = await contract.queryFilter(contract.filters.ProofAnchored(), start, end);
    for (const ev of events) {
      const log = ev as ethers.EventLog;
      const [seq, proofHash, dsHash, startBlock, endBlock, submittedBy, zkVerified] = log.args;
      await db.query(
        `INSERT INTO proofs (seq, proof_hash, ds_hash, start_block, end_block,
                             submitted_by, zk_verified, txid, block_number, commitment_level)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0)
         ON CONFLICT (seq) DO NOTHING`,
        [
          Number(seq),
          proofHash,
          dsHash,
          Number(startBlock),
          Number(endBlock),
          submittedBy,
          zkVerified,
          log.transactionHash,
          log.blockNumber,
        ]
      );
    }
    await saveCursor(end);
  }
}

/** Upgrade commitment levels: 0 (latest) -> 1 (safe) -> 2 (finalized). */
async function reconcileFinality(): Promise<void> {
  const [safe, finalized] = await Promise.all([
    provider.getBlock("safe").catch(() => null),
    provider.getBlock("finalized").catch(() => null),
  ]);
  if (safe) {
    await db.query(
      "UPDATE proofs SET commitment_level = 1 WHERE commitment_level < 1 AND block_number <= $1",
      [safe.number]
    );
  }
  if (finalized) {
    await db.query(
      "UPDATE proofs SET commitment_level = 2 WHERE commitment_level < 2 AND block_number <= $1",
      [finalized.number]
    );
  }
}

async function main(): Promise<void> {
  console.log(`zkQuiver indexer: ${CONTRACT} via ${RPC_URL}`);
  // Live subscription + polling fallback.
  contract.on("ProofAnchored", () => scan().catch(console.error));
  for (;;) {
    await scan().catch(console.error);
    await reconcileFinality().catch(console.error);
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
