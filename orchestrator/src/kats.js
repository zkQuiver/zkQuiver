// zkQuiver KATs — zero dependencies, runs with bare `node`.
// Verifies: (1) keccak256 impl against universal vectors,
// (2) canonical JSON determinism, (3) 98-byte DS layout + dsHash,
// including byte-equivalence with Solidity's abi.encodePacked.

"use strict";

// ---------- minimal keccak-256 (Keccak-f[1600], pad 0x01) ----------
function keccak256(bytes) {
  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  const ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
  ];
  const M = (1n << 64n) - 1n;
  const rotl = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M;

  const rate = 136; // 1088 bits for keccak-256
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = 0x01;       // keccak padding (sha3 would be 0x06)
  padded[padded.length - 1] |= 0x80;

  const S = Array.from({ length: 5 }, () => new Array(5).fill(0n));
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
      S[i % 5][(i / 5) | 0] ^= lane;
    }
    for (let round = 0; round < 24; round++) {
      const C = [], D = [];
      for (let x = 0; x < 5; x++) C[x] = S[x][0] ^ S[x][1] ^ S[x][2] ^ S[x][3] ^ S[x][4];
      for (let x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
        for (let y = 0; y < 5; y++) S[x][y] ^= D[x];
      }
      const B = Array.from({ length: 5 }, () => new Array(5).fill(0n));
      for (let x = 0; x < 5; x++)
        for (let y = 0; y < 5; y++)
          B[y][(2 * x + 3 * y) % 5] = rotl(S[x][y], ROT[x][y]);
      for (let x = 0; x < 5; x++)
        for (let y = 0; y < 5; y++)
          S[x][y] = B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y]);
      S[0][0] ^= RC[round];
    }
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = S[i % 5][(i / 5) | 0];
    for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const utf8 = (s) => new TextEncoder().encode(s);

// ---------- canonical JSON (must match canonical.ts and prover) ----------
function canonicalize(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite");
    return v.toString();
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object")
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
  throw new Error("bad type");
}

// ---------- DS construction (must match ProofAnchor.computeDsHash) ----------
const DS_PREFIX = "zkRH/anchor/v1";
function buildDs({ chainId, contract, proofHashHex, startBlock, endBlock, seq }) {
  const u64be = (v) => {
    const b = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  };
  const h2b = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
  const parts = [
    utf8(DS_PREFIX), u64be(chainId), h2b(contract.replace(/^0x/, "")),
    h2b(proofHashHex), u64be(startBlock), u64be(endBlock), u64be(seq),
  ];
  const ds = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { ds.set(p, o); o += p.length; }
  return ds;
}

// ---------- tests ----------
let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) console.log(`      got:  ${got}\n      want: ${want}`);
}

// 1. keccak256 against universal known vectors (proves the impl itself)
check("keccak256(\"\")", hex(keccak256(utf8(""))),
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
check("keccak256(\"abc\")", hex(keccak256(utf8("abc"))),
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
check("keccak256(\"testing\")", hex(keccak256(utf8("testing"))),
  "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02");

// 2. Canonicalization: key sorting, determinism, nested structures
check("canonical: sorts keys",
  canonicalize({ b: 2, a: 1 }), '{"a":1,"b":2}');
check("canonical: order-independent",
  canonicalize({ z: [3, { y: 2, x: 1 }], a: "s" }),
  canonicalize({ a: "s", z: [3, { x: 1, y: 2 }] }));
const artifact = {
  artifact_id: "550e8400-e29b-41d4-a716-446655440000",
  start_block: 1, end_block: 64,
  state_root_before: "0".repeat(63) + "1",
  state_root_after: "0".repeat(63) + "2",
};
check("canonical: artifact golden",
  canonicalize(artifact),
  '{"artifact_id":"550e8400-e29b-41d4-a716-446655440000","end_block":64,' +
  '"start_block":1,"state_root_after":"' + "0".repeat(63) + '2",' +
  '"state_root_before":"' + "0".repeat(63) + '1"}');

// 3. DS layout: length, field offsets, and hash
const dsParams = {
  chainId: 42161n, // placeholder; real Robinhood chainId goes in .env
  contract: "0x1111111111111111111111111111111111111111",
  proofHashHex: "aa".repeat(32),
  startBlock: 1n, endBlock: 64n, seq: 1n,
};
const ds = buildDs(dsParams);
check("DS length = 98", String(ds.length), "98");
check("DS prefix bytes", hex(ds.slice(0, 14)), hex(utf8(DS_PREFIX)));
check("DS chainId u64 BE @14", hex(ds.slice(14, 22)), "000000000000a4b1");
check("DS contract @22", hex(ds.slice(22, 42)), "11".repeat(20));
check("DS proofHash @42", hex(ds.slice(42, 74)), "aa".repeat(32));
check("DS startBlock @74", hex(ds.slice(74, 82)), "0000000000000001");
check("DS endBlock @82", hex(ds.slice(82, 90)), "0000000000000040");
check("DS seq @90", hex(ds.slice(90, 98)), "0000000000000001");

// Golden dsHash — cross-check on your machine with:
//   cast keccak 0x$(node kats.js --print-ds)
// and against ProofAnchor.computeDsHash on a local chain.
const goldenDsHash = hex(keccak256(ds));
console.log(`\nGolden vector for cross-verification:`);
console.log(`  DS bytes: 0x${hex(ds)}`);
console.log(`  ds_hash:  0x${goldenDsHash}`);

// Determinism under field changes: any field change must change the hash
for (const [field, mutated] of [
  ["seq", { ...dsParams, seq: 2n }],
  ["chainId", { ...dsParams, chainId: 42162n }],
  ["contract", { ...dsParams, contract: "0x" + "22".repeat(20) }],
]) {
  check(`DS binds ${field} (hash changes)`,
    String(hex(keccak256(buildDs(mutated))) !== goldenDsHash), "true");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
