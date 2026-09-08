import { blake3 } from "@noble/hashes/blake3";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * JSON Canonicalization (JCS-style):
 *  - map keys sorted lexicographically
 *  - no whitespace
 *  - hex fields lowercased (caller's responsibility on input)
 *  - numbers without scientific notation
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Number.isInteger(value)) return value.toString();
    // Avoid scientific notation for the ranges we use.
    return value.toString();
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new Error(`cannot canonicalize type: ${typeof value}`);
}

export interface Artifact {
  artifact_id: string;        // lowercase uuid v4
  start_block: number;
  end_block: number;
  state_root_before: string;  // hex32, lowercase, no 0x
  state_root_after: string;   // hex32, lowercase, no 0x
  // Public Inputs v2 (optional): C_in, C_out, H_B, S_in, S_out
  public_inputs?: {
    C_in: string;
    C_out: string;
    H_B: string;
    S_in: Array<{ account: string; value: string }>;
    S_out: Array<{ account: string; value: string }>;
  };
}

/** proof_hash = blake3(canonical_json_bytes), hex string without 0x */
export function proofHash(artifact: Artifact): string {
  const canonical = canonicalize(artifact);
  return bytesToHex(blake3(new TextEncoder().encode(canonical)));
}

/** pi_hash = blake3(canonical_json(PI set)) when PI v2 present */
export function publicInputsHash(artifact: Artifact): string {
  if (!artifact.public_inputs) return "00".repeat(32);
  const canonical = canonicalize(artifact.public_inputs);
  return bytesToHex(blake3(new TextEncoder().encode(canonical)));
}

export const DS_PREFIX = "zkRH/anchor/v1"; // 14 ASCII bytes

/**
 * DS message layout (98 bytes) — must byte-match ProofAnchor.computeDsHash:
 *   prefix(14) | chainId u64 BE | contract addr(20) | proofHash(32)
 *   | startBlock u64 BE | endBlock u64 BE | seq u64 BE
 * Note: abi.encodePacked serializes uint64 big-endian.
 */
export function buildDsMessage(params: {
  chainId: bigint;
  contractAddress: string; // 0x-prefixed
  proofHashHex: string;    // no 0x
  startBlock: bigint;
  endBlock: bigint;
  seq: bigint;
}): Uint8Array {
  const buf = new Uint8Array(98);
  let o = 0;
  buf.set(new TextEncoder().encode(DS_PREFIX), o); o += 14;
  writeU64BE(buf, o, params.chainId); o += 8;
  buf.set(hexToBytes(params.contractAddress.slice(2)), o); o += 20;
  buf.set(hexToBytes(params.proofHashHex), o); o += 32;
  writeU64BE(buf, o, params.startBlock); o += 8;
  writeU64BE(buf, o, params.endBlock); o += 8;
  writeU64BE(buf, o, params.seq); o += 8;
  if (o !== 98) throw new Error("DS length mismatch");
  return buf;
}

export function dsHash(ds: Uint8Array): string {
  return bytesToHex(keccak_256(ds));
}

function writeU64BE(buf: Uint8Array, offset: number, v: bigint): void {
  for (let i = 7; i >= 0; i--) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
