//! zkQuiver Prover.
//!
//! Responsibilities:
//!   1. Canonicalize the proof artifact to deterministic JSON (JCS rules)
//!   2. proof_hash = blake3(canonical_json)
//!   3. Construct the 98-byte DS message
//!      prefix(14) | chainId u64 BE | contract(20) | proofHash(32)
//!      | startBlock u64 BE | endBlock u64 BE | seq u64 BE
//!   4. ds_hash = keccak256(DS); sign EIP-191("\x19Ethereum Signed Message:\n32" + ds_hash)
//!      with the aggregator secp256k1 key
//!   5. Emit signed artifact JSON for the orchestrator
//!
//! STARK/SNARK generation is behind the `zkvm` feature — the intended
//! integration is SP1 or RISC Zero, whose proofs verify on-chain via
//! the IProofVerifier adapter.

#![forbid(unsafe_code)]

use clap::Parser;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::fs;

const DS_PREFIX: &[u8; 14] = b"zkRH/anchor/v1";

#[derive(Parser)]
struct Args {
    /// Input artifact JSON
    #[arg(long)]
    input: String,
    /// Output signed artifact JSON
    #[arg(long)]
    out: String,
    /// Aggregator private key hex (32 bytes, no 0x) — file path or literal
    #[arg(long)]
    agg_key: String,
    /// EVM chain id (Robinhood Chain testnet/mainnet)
    #[arg(long)]
    chain_id: u64,
    /// ProofAnchor contract address (0x…)
    #[arg(long)]
    contract: String,
    /// Monotonic sequence number
    #[arg(long)]
    seq: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let raw = fs::read_to_string(&args.input)?;
    let artifact: Value = serde_json::from_str(&raw)?;

    // 1–2. Canonicalize + hash
    let canonical = canonicalize(&artifact)?;
    let proof_hash = blake3::hash(canonical.as_bytes());

    let start_block = artifact["start_block"].as_u64().ok_or_else(|| anyhow::anyhow!("start_block"))?;
    let end_block = artifact["end_block"].as_u64().ok_or_else(|| anyhow::anyhow!("end_block"))?;

    // 3. DS message
    let contract_bytes = hex::decode(args.contract.trim_start_matches("0x"))?;
    anyhow::ensure!(contract_bytes.len() == 20, "contract address must be 20 bytes");

    let mut ds = Vec::with_capacity(98);
    ds.extend_from_slice(DS_PREFIX);
    ds.extend_from_slice(&args.chain_id.to_be_bytes());
    ds.extend_from_slice(&contract_bytes);
    ds.extend_from_slice(proof_hash.as_bytes());
    ds.extend_from_slice(&start_block.to_be_bytes());
    ds.extend_from_slice(&end_block.to_be_bytes());
    ds.extend_from_slice(&args.seq.to_be_bytes());
    anyhow::ensure!(ds.len() == 98, "DS length mismatch");

    let ds_hash: [u8; 32] = Keccak256::digest(&ds).into();

    // 4. EIP-191 sign
    let key_hex = fs::read_to_string(&args.agg_key).unwrap_or_else(|_| args.agg_key.clone());
    let key_bytes = hex::decode(key_hex.trim().trim_start_matches("0x"))?;
    let signing_key = SigningKey::from_slice(&key_bytes)?;

    let mut eip191 = Vec::new();
    eip191.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    eip191.extend_from_slice(&ds_hash);
    let digest: [u8; 32] = Keccak256::digest(&eip191).into();

    let (sig, rec_id): (Signature, RecoveryId) =
        signing_key.sign_prehash_recoverable(&digest)?;
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(27 + rec_id.to_byte()); // v = 27/28 (Ethereum convention)

    // 5. Emit
    let out = serde_json::json!({
        "artifact": artifact,
        "canonical": canonical,
        "proof_hash": hex::encode(proof_hash.as_bytes()),
        "ds_hash": hex::encode(ds_hash),
        "signature": hex::encode(&sig_bytes),
        "seq": args.seq,
        "chain_id": args.chain_id,
        "contract": args.contract,
    });
    fs::write(&args.out, serde_json::to_string_pretty(&out)?)?;
    println!("proof_hash: {}", hex::encode(proof_hash.as_bytes()));
    println!("ds_hash:    {}", hex::encode(ds_hash));
    Ok(())
}

/// JCS-style canonical JSON: sorted keys, no whitespace.
/// Must produce byte-identical output to orchestrator/src/canonical.ts
/// (enforced by the conformance test).
fn canonicalize(v: &Value) -> anyhow::Result<String> {
    Ok(match v {
        Value::Null | Value::Bool(_) => v.to_string(),
        Value::Number(n) => {
            anyhow::ensure!(n.is_u64() || n.is_i64(), "only integer numbers supported");
            n.to_string()
        }
        Value::String(_) => v.to_string(),
        Value::Array(items) => {
            let parts: Result<Vec<_>, _> = items.iter().map(canonicalize).collect();
            format!("[{}]", parts?.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let parts: Result<Vec<_>, anyhow::Error> = keys
                .iter()
                .map(|k| Ok(format!("{}:{}", serde_json::to_string(k)?, canonicalize(&map[*k])?)))
                .collect();
            format!("{{{}}}", parts?.join(","))
        }
    })
}
