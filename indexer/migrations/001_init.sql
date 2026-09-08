CREATE TABLE IF NOT EXISTS proofs (
  seq BIGINT PRIMARY KEY,
  proof_hash TEXT NOT NULL UNIQUE,
  ds_hash TEXT NOT NULL,
  start_block BIGINT NOT NULL,
  end_block BIGINT NOT NULL,
  submitted_by TEXT NOT NULL,
  zk_verified BOOLEAN NOT NULL DEFAULT FALSE,
  txid TEXT NOT NULL UNIQUE,
  block_number BIGINT NOT NULL,
  commitment_level SMALLINT NOT NULL CHECK (commitment_level IN (0, 1, 2)),
  ts TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_proofs_commitment ON proofs(commitment_level);
CREATE INDEX IF NOT EXISTS idx_proofs_block_range ON proofs(start_block, end_block);

CREATE TABLE IF NOT EXISTS validators (
  address TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('Active', 'Unlocked')),
  lock_ts TIMESTAMPTZ,
  unlock_ts TIMESTAMPTZ,
  num_accepts BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS indexer_state (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_block BIGINT NOT NULL DEFAULT 0,
  last_scan_ts TIMESTAMPTZ
);
