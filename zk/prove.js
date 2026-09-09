// zkQuiver sigma prover CLI + contract-logic mirror. Bare node, no deps.
//
//   node zk/prove.js <stateRootPrevHex32> <stateRootOutHex32> <ctxHex32>
//
// Emits a 23-word proof bundle (hex) ready for LineageVerifier.verify,
// where publicInputsHash = ctx. Commits to:
//   prevCout = Commit(rootPrev)   (previous window's outgoing root)
//   C_in     = Commit(rootPrev)   (this window's incoming root, fresh blinding)
//   C_out    = Commit(rootOut)
// and proves: opening of C_in, opening of C_out, equality(prevCout, C_in).
//
// Also exports verifyBundleJS(): an exact JS mirror of the Solidity
// verification path (same challenges, same helper points, same address
// checks) so the contract logic is testable without a chain.
"use strict";
const S = require("./sigma.js");
const { mod, N, P, G, H, ecAdd, ecMul, ecNeg, onCurve, pointAddr,
        commit, keccak256, bigTo32, hex } = S;

const w32 = v => bigTo32(typeof v === "bigint" ? v : BigInt(v));

function challengeOpen(C, A, ctx32){
  const buf = new Uint8Array(22 + 32*4 + 32);
  buf.set(S.utf8("zkQuiver/sigma/open/v1"), 0);
  buf.set(bigTo32(C.x),22); buf.set(bigTo32(C.y),54);
  buf.set(bigTo32(A.x),86); buf.set(bigTo32(A.y),118);
  buf.set(ctx32,150);
  return mod(S.bytesToBig(keccak256(buf)), N);
}
function challengeEq(C1, C2, A, ctx32){
  const buf = new Uint8Array(20 + 32*6 + 32);
  buf.set(S.utf8("zkQuiver/sigma/eq/v1"), 0);
  buf.set(bigTo32(C1.x),20); buf.set(bigTo32(C1.y),52);
  buf.set(bigTo32(C2.x),84); buf.set(bigTo32(C2.y),116);
  buf.set(bigTo32(A.x),148); buf.set(bigTo32(A.y),180);
  buf.set(ctx32,212);
  return mod(S.bytesToBig(keccak256(buf)), N);
}

/** Build the 23-word bundle for LineageVerifier. */
function proveBundle(rootPrev32, rootOut32, ctx32){
  const prev = commit(rootPrev32);
  const cin  = commit(rootPrev32);       // same value, fresh blinding
  const cout = commit(rootOut32);

  // openings (contract-compatible challenges: on C, A, ctx)
  function open(cm){
    const a=S.randScalar(), b=S.randScalar();
    const A=ecAdd(ecMul(a,G), ecMul(b,H));
    const c=challengeOpen(cm.C, A, ctx32);
    return { A, z1: mod(a+c*cm.x,N), z2: mod(b+c*cm.r,N),
             CC: ecMul(c, cm.C) };
  }
  const oi = open(cin), oo = open(cout);

  // equality(prevCout, C_in)
  const rho = mod(prev.r - cin.r, N);
  const k = S.randScalar();
  const Aeq = ecMul(k, H);
  const ceq = challengeEq(prev.C, cin.C, Aeq, ctx32);
  const zeq = mod(k + ceq*rho, N);
  const D = ecAdd(prev.C, ecNeg(cin.C));
  const CD = ecMul(ceq, D);

  const words = [
    cin.C.x, cin.C.y, cout.C.x, cout.C.y, prev.C.x, prev.C.y,
    oi.A.x, oi.A.y, oi.z1, oi.z2, oi.CC.x, oi.CC.y,
    oo.A.x, oo.A.y, oo.z1, oo.z2, oo.CC.x, oo.CC.y,
    Aeq.x, Aeq.y, zeq, CD.x, CD.y,
  ];
  const buf = new Uint8Array(23*32);
  words.forEach((v,i)=>buf.set(w32(v), i*32));
  return { hex: "0x"+hex(buf), words,
           commitments: { prevCout: prev.C, C_in: cin.C, C_out: cout.C },
           secrets: { note: "blindings held by prover; roots never revealed" } };
}

/** Exact JS mirror of LineageVerifier.verify (same checks, same order). */
function verifyBundleJS(words, ctx32){
  const pt=(i)=>({x:words[i], y:words[i+1]});
  const [Cin, Cout, Prev] = [pt(0), pt(2), pt(4)];
  const onc=[0,2,4,6,10,12,16,18,21].every(i=>onCurve(pt(i)));
  if(!onc) return false;

  function vOpen(C, Ai, z1i, CCi){
    const A=pt(Ai), z1=words[z1i], z2=words[z1i+1], CC=pt(CCi);
    const c=challengeOpen(C, A, ctx32);
    if(pointAddr(ecMul(c, C)) !== pointAddr(CC)) return false;
    const R=ecAdd(A, CC);
    return pointAddr(ecAdd(ecMul(z1,G), ecMul(z2,H))) === pointAddr(R);
  }
  if(!vOpen(Cin, 6, 8, 10)) return false;
  if(!vOpen(Cout, 12, 14, 16)) return false;

  const Aeq=pt(18), zeq=words[20], CD=pt(21);
  const c=challengeEq(Prev, Cin, Aeq, ctx32);
  const D=ecAdd(Prev, ecNeg(Cin));
  if(D===null) return false;
  if(pointAddr(ecMul(c,D)) !== pointAddr(CD)) return false;
  const R=ecAdd(Aeq, CD);
  return pointAddr(ecMul(zeq,H)) === pointAddr(R);
}

module.exports = { proveBundle, verifyBundleJS, challengeOpen, challengeEq };

if (require.main === module) {
  const [,, prevHex, outHex, ctxHex] = process.argv;
  const h2b = h => Uint8Array.from((h||"").replace(/^0x/,"").padStart(64,"0")
                   .match(/../g).map(x=>parseInt(x,16)));
  const rootPrev = prevHex ? h2b(prevHex) : keccak256(S.utf8("demo-root-prev"));
  const rootOut  = outHex  ? h2b(outHex)  : keccak256(S.utf8("demo-root-out"));
  const ctx      = ctxHex  ? h2b(ctxHex)  : keccak256(S.utf8("demo-ctx"));
  const b = proveBundle(rootPrev, rootOut, ctx);
  console.log(JSON.stringify({
    publicInputsHash: "0x"+hex(ctx),
    proof: b.hex,
    verifies_locally: verifyBundleJS(b.words, ctx),
  }, null, 2));
}
