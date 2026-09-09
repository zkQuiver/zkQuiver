# SECURITY.md

## Key handling: what is where

| Secret | Lives in | Used by | Never appears in |
| --- | --- | --- | --- |
| `DEPLOYER_PRIVATE_KEY` (contract owner) | your `.env` only | deploy script, admin calls | code, git, zips, website, logs |
| `AGGREGATOR_PRIVATE_KEY` (signs DS messages) | your `.env` only | orchestrator, anchor script | code, git, zips, website, logs |
| Pedersen blinding factors | prover process memory | zk bundle generation | chain, website, logs |
| State roots (plaintext) | orchestrator artifacts dir | proof generation | chain (only commitment digests go on-chain) |

The website holds no secrets. Its on-chain verification is a read-only
`eth_call`; no wallet, no signature, no key.

## Rules

1. **Fresh wallets only.** Never use a wallet that holds real funds as the
   deployer or aggregator. Create new ones for this project.
2. **`.env` never leaves your machine.** It is git-ignored, excluded from
   every upload package, and the doctor refuses to proceed if it finds
   key-shaped strings anywhere else in the repo. Do not paste `.env` or
   any private key into chats, tickets, screenshots, or AI assistants,
   including the one that built this repo.
3. **Separate roles before launch.** Owner (can pause, rotate, set the
   verifier) and aggregator (signs every anchor) should be different keys.
   The owner key is used rarely: keep it cold (hardware wallet on
   mainnet). The aggregator key is hot: keep it on the machine that runs
   the orchestrator and nowhere else. Set `AGGREGATOR_ADDRESS` at deploy
   time to the hot wallet's address.
4. **Rotate, don't panic.** If the aggregator key is exposed:
   `setPaused(true)`, then `scheduleAggregatorRotation(newKey, seq)` and
   `finalizeAggregatorRotation()`. Because records are immutable, unique,
   and strictly sequenced, an attacker with the old key cannot rewrite or
   skip history; they could only append well-formed bad records until the
   pause, and the sequence number of every such record is visible.
5. **Scan before every upload.** `npm run doctor` scans the tree for
   64-hex-character strings outside `.env`; CI runs the same scan and
   fails the build if one is found.

## What the cryptography protects, and what it does not

- Pedersen commitments are perfectly hiding: an observer of the chain
  learns nothing about the committed state roots, even with unlimited
  compute. They are computationally binding under the discrete-log
  assumption on secp256k1.
- The NIZK proofs are honest-verifier zero-knowledge sigma protocols
  made non-interactive with Fiat-Shamir (keccak256, domain-separated).
  Transcripts reveal nothing about openings or blindings.
- The domain-separated signature binds each anchor to chain, contract,
  window, and sequence position; signatures cannot be replayed elsewhere.
- The on-chain verifier compares 160-bit point addresses (ecrecover
  trick). This is adequate for the testnet phase and is stated openly;
  a mainnet deployment should use a full-coordinate check or a
  precompile-backed curve.
- Not covered: correctness of the state transition itself. That is the
  zkVM tier on the roadmap and is stated as such everywhere claims are
  made.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Do not open a
public issue for anything exploitable.
