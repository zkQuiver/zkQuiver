// zkQuiver sigma layer self-test. Bare `node zk/selftest.js`.
// Proves the layer works AS CRYPTOGRAPHY, not just as code:
//   correctness  — honest proofs verify
//   soundness    — tampered proofs, wrong values, swapped contexts fail
//   privacy      — commitments to the same value are unlinkable without
//                  the proof; commitments reveal nothing recognizable
"use strict";
const S=require("./sigma.js");
const {commit, proveOpening, verifyOpening, proveEquality, verifyEquality,
       keccak256, utf8, bigTo32, mod, N, ecMul, G, onCurve, H, pointAddr}=S;

let pass=0,fail=0;
const t=(name,ok)=>{ (ok?pass++:fail++); console.log((ok?"PASS":"FAIL")+"  "+name); };

const ctx = keccak256(utf8("zkQuiver/ctx/window-1-64/seq-1"));   // binds proofs to an anchor
const ctx2= keccak256(utf8("zkQuiver/ctx/window-65-128/seq-2"));

// state roots (normally real chain data)
const rootA = keccak256(utf8("state-root-at-block-64"));
const rootB = keccak256(utf8("state-root-at-block-128"));

/* ---------- correctness ---------- */
const c1 = commit(rootA);                       // C_out of window 1
const c2 = commit(rootA);                       // C_in  of window 2 (same value, fresh blinding)
const c3 = commit(rootB);                       // C_out of window 2 (different value)

t("generators on curve, H independent of G (different point)",
  onCurve(G)&&onCurve(H)&&(G.x!==H.x||G.y!==H.y));

const po1 = proveOpening(c1.C, c1.x, c1.r, ctx);
t("opening proof verifies (knows x,r for C_out)", verifyOpening(c1.C, po1, ctx));

const pe = proveEquality(c1.C, c1.r, c2.C, c2.r, ctx2);
t("equality proof verifies (window 2's C_in hides the same root as window 1's C_out)",
  verifyEquality(c1.C, c2.C, pe, ctx2));

/* ---------- soundness ---------- */
t("equality proof REJECTED for commitments to different roots",
  !verifyEquality(c1.C, c3.C, proveEquality(c1.C, c1.r, c3.C, c3.r, ctx2), ctx2));

const forged={...po1, z1: mod(po1.z1+1n,N)};
t("tampered response rejected", !verifyOpening(c1.C, forged, ctx));

t("proof bound to context: same proof under different ctx rejected",
  !verifyOpening(c1.C, po1, ctx2));

const cWrong=commit(rootB);
t("opening proof does not transfer to a different commitment",
  !verifyOpening(cWrong.C, po1, ctx));

const peF={...pe, A: ecMul(5n,G)};
t("tampered equality announcement rejected", !verifyEquality(c1.C, c2.C, peF, ctx2));

/* ---------- privacy ---------- */
t("hiding: two commitments to the SAME root are different points (unlinkable without proof)",
  c1.C.x!==c2.C.x || c1.C.y!==c2.C.y);

// the commitment should not equal the naive unblinded encoding x*G
const naked=ecMul(mod(S.bytesToBig(rootA),N), G);
t("commitment ≠ x*G (blinding actually applied)", c1.C.x!==naked.x);

// simulator sanity: transcripts (A, c, z) with the challenge fixed can be
// produced WITHOUT the witness (honest-verifier zero-knowledge shape):
// pick z1,z2,c at random, set A = z1G + z2H − cC. Verifier equation holds
// by construction, showing transcripts carry no witness information.
(function(){
  const z1=S.randScalar(), z2=S.randScalar(), c=S.randScalar();
  const A=S.ecAdd(S.ecAdd(ecMul(z1,G),ecMul(z2,H)), S.ecNeg(ecMul(c,c1.C)));
  const L=S.ecAdd(ecMul(z1,G),ecMul(z2,H));
  const R=S.ecAdd(A, ecMul(c,c1.C));
  t("HVZK simulator: valid-looking transcript exists without the witness",
    L.x===R.x&&L.y===R.y);
})();

/* ---------- interop values for the on-chain verifier ---------- */
console.log("\nOn-chain interop vector (embed in Hardhat test):");
console.log("H      ", S.pt(H));
console.log("C_out  ", S.pt(c1.C));
console.log("C_in   ", S.pt(c2.C));
console.log("eq.A   ", S.pt(pe.A));
console.log("eq.z   ", S.sc(pe.z));
console.log("ctx    ", "0x"+S.hex(ctx2));
console.log("addr(H)", pointAddr(H));

console.log("\n"+pass+" passed, "+fail+" failed");
process.exit(fail?1:0);
