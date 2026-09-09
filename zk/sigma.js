// zkQuiver sigma layer — zero-dependency zero-knowledge proofs.
//
// Primitives (all from scratch, bare Node, no packages):
//   - secp256k1 group arithmetic (BigInt)
//   - Pedersen commitments  C = x*G + r*H   (perfectly hiding,
//     computationally binding; H derived nothing-up-my-sleeve)
//   - NIZK proof of opening (Okamoto / Schnorr on two generators,
//     Fiat-Shamir with keccak256, domain-separated)
//   - NIZK equality proof (Chaum-Pedersen variant): two commitments
//     hide the SAME value, without revealing it
//
// zkQuiver use: state roots become hiding commitments; each anchor
// proves its commitments are well-formed, and consecutive windows'
// boundary commitments are linked in zero knowledge.
//
// Scope, stated plainly: these proofs give privacy of the committed
// roots and integrity of the commitment structure. They do NOT prove
// the state transition itself is correct — that is the zkVM tier.

"use strict";

/* ---------------- keccak-256 (same impl as kats.js) ---------------- */
function keccak256(bytes){
  const RC=[0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
  0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
  0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
  0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
  0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
  0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
  const ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]];
  const M=(1n<<64n)-1n; const rotl=(x,nn)=>((x<<BigInt(nn))|(x>>BigInt(64-nn)))&M;
  const rate=136;
  const padded=new Uint8Array(Math.ceil((bytes.length+1)/rate)*rate);
  padded.set(bytes); padded[bytes.length]=0x01; padded[padded.length-1]|=0x80;
  const S=Array.from({length:5},()=>new Array(5).fill(0n));
  for(let off=0;off<padded.length;off+=rate){
    for(let i=0;i<rate/8;i++){let lane=0n;
      for(let b=7;b>=0;b--)lane=(lane<<8n)|BigInt(padded[off+i*8+b]);
      S[i%5][(i/5)|0]^=lane;}
    for(let r=0;r<24;r++){
      const C=[],D=[];
      for(let x=0;x<5;x++)C[x]=S[x][0]^S[x][1]^S[x][2]^S[x][3]^S[x][4];
      for(let x=0;x<5;x++){D[x]=C[(x+4)%5]^rotl(C[(x+1)%5],1);
        for(let y=0;y<5;y++)S[x][y]^=D[x];}
      const B=Array.from({length:5},()=>new Array(5).fill(0n));
      for(let x=0;x<5;x++)for(let y=0;y<5;y++)B[y][(2*x+3*y)%5]=rotl(S[x][y],ROT[x][y]);
      for(let x=0;x<5;x++)for(let y=0;y<5;y++)S[x][y]=B[x][y]^(~B[(x+1)%5][y]&B[(x+2)%5][y]);
      S[0][0]^=RC[r];
    }
  }
  const out=new Uint8Array(32);
  for(let i=0;i<4;i++){let lane=S[i%5][(i/5)|0];
    for(let b=0;b<8;b++){out[i*8+b]=Number(lane&0xffn);lane>>=8n;}}
  return out;
}
const utf8=s=>new TextEncoder().encode(s);
const bytesToBig=u8=>u8.reduce((a,b)=>(a<<8n)|BigInt(b),0n);
function bigTo32(x){const u=new Uint8Array(32);for(let i=31;i>=0;i--){u[i]=Number(x&0xffn);x>>=8n;}return u;}
const hex=u8=>[...u8].map(b=>b.toString(16).padStart(2,"0")).join("");

/* ---------------- secp256k1 ---------------- */
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx= 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy= 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G = {x:Gx, y:Gy};
const O = null; // point at infinity

const mod=(a,m)=>((a%m)+m)%m;
function powmod(b,e,m){let r=1n;b=mod(b,m);while(e>0n){if(e&1n)r=(r*b)%m;b=(b*b)%m;e>>=1n;}return r;}
const inv=(a,m)=>powmod(mod(a,m),m-2n,m);

function onCurve(Q){ if(Q===O)return true;
  return mod(Q.y*Q.y - (Q.x*Q.x*Q.x + 7n), P)===0n; }
function ecAdd(A,B){
  if(A===O)return B; if(B===O)return A;
  if(A.x===B.x){
    if(mod(A.y+B.y,P)===0n) return O;
    // doubling
    const l=mod(3n*A.x*A.x * inv(2n*A.y,P), P);
    const x=mod(l*l - 2n*A.x, P);
    return {x, y: mod(l*(A.x-x)-A.y, P)};
  }
  const l=mod((B.y-A.y)*inv(B.x-A.x,P), P);
  const x=mod(l*l - A.x - B.x, P);
  return {x, y: mod(l*(A.x-x)-A.y, P)};
}
function ecMul(k,Q){
  k=mod(k,N); let R=O, T=Q;
  while(k>0n){ if(k&1n)R=ecAdd(R,T); T=ecAdd(T,T); k>>=1n; }
  return R;
}
function ecNeg(Q){ return Q===O?O:{x:Q.x, y:mod(-Q.y,P)}; }

/* Ethereum-style address of a point: last 20 bytes of keccak(x||y).
   Used by the on-chain verifier (ecrecover trick compares addresses). */
function pointAddr(Q){
  const u=new Uint8Array(64); u.set(bigTo32(Q.x),0); u.set(bigTo32(Q.y),32);
  return "0x"+hex(keccak256(u).slice(12));
}

/* ---------------- H: second generator, nothing-up-my-sleeve ----------------
   Try-and-increment from a fixed tag; discrete log of H wrt G unknown. */
function deriveH(){
  for(let i=0;;i++){
    const x=mod(bytesToBig(keccak256(utf8("zkQuiver/H/v1/"+i))),P);
    const y2=mod(x*x*x+7n,P);
    const y=powmod(y2,(P+1n)/4n,P);           // p ≡ 3 mod 4
    if(mod(y*y,P)===y2){ return {x, y: (y&1n)?mod(-y,P):y}; } // even y
  }
}
const H=deriveH();

/* ---------------- randomness ---------------- */
const nodeCrypto=require("crypto");
function randScalar(){
  while(true){
    const k=bytesToBig(new Uint8Array(nodeCrypto.randomBytes(32)));
    const r=mod(k,N); if(r>0n) return r;
  }
}

/* ---------------- Fiat-Shamir challenge ---------------- */
function challenge(tag, points, extra32s){
  const parts=[utf8(tag)];
  for(const Q of points){ parts.push(bigTo32(Q.x), bigTo32(Q.y)); }
  for(const e of (extra32s||[])) parts.push(e);
  const total=parts.reduce((s,p2)=>s+p2.length,0);
  const buf=new Uint8Array(total); let o=0;
  for(const p2 of parts){ buf.set(p2,o); o+=p2.length; }
  return mod(bytesToBig(keccak256(buf)), N);
}

/* ---------------- Pedersen commitment ----------------
   Commit to a 32-byte value (e.g. a state root). The value is reduced
   mod n; binding is to (value mod n). C = x*G + r*H. */
function commit(value32, r){
  const x=mod(bytesToBig(value32), N);
  r = r===undefined ? randScalar() : r;
  return { C: ecAdd(ecMul(x,G), ecMul(r,H)), x, r };
}

/* ---------------- NIZK: proof of opening (Okamoto) ----------------
   Proves knowledge of (x, r) with C = xG + rH, revealing neither. */
const TAG_OPEN="zkQuiver/sigma/open/v1";
function proveOpening(C, x, r, ctx32){
  const a=randScalar(), b=randScalar();
  const A=ecAdd(ecMul(a,G), ecMul(b,H));
  const c=challenge(TAG_OPEN,[C,A],[ctx32]);
  return { A, z1: mod(a+c*x,N), z2: mod(b+c*r,N) };
}
function verifyOpening(C, prf, ctx32){
  if(!onCurve(C)||!onCurve(prf.A)) return false;
  const c=challenge(TAG_OPEN,[C,prf.A],[ctx32]);
  const L=ecAdd(ecMul(prf.z1,G), ecMul(prf.z2,H));
  const R=ecAdd(prf.A, ecMul(c,C));
  return L!==O && R!==O && L.x===R.x && L.y===R.y;
}

/* ---------------- NIZK: equality of committed values ----------------
   C1 = xG + r1H and C2 = xG + r2H hide the SAME x  ⇔
   D = C1 - C2 = (r1-r2)H. Schnorr proof of knowledge of dlog of D
   base H. Reveals nothing about x. */
const TAG_EQ="zkQuiver/sigma/eq/v1";
function proveEquality(C1, r1, C2, r2, ctx32){
  const rho=mod(r1-r2,N);
  const k=randScalar();
  const A=ecMul(k,H);
  const c=challenge(TAG_EQ,[C1,C2,A],[ctx32]);
  return { A, z: mod(k+c*rho,N) };
}
function verifyEquality(C1, C2, prf, ctx32){
  if(!onCurve(C1)||!onCurve(C2)||!onCurve(prf.A)) return false;
  const D=ecAdd(C1, ecNeg(C2));
  if(D===O) return false;                 // identical commitments: reject
  const c=challenge(TAG_EQ,[C1,C2,prf.A],[ctx32]);
  const L=ecMul(prf.z,H);
  const R=ecAdd(prf.A, ecMul(c,D));
  return L!==O && R!==O && L.x===R.x && L.y===R.y;
}

/* ---------------- serialization (for on-chain + transport) ---------------- */
function pt(Qp){ return { x:"0x"+Qp.x.toString(16).padStart(64,"0"),
                          y:"0x"+Qp.y.toString(16).padStart(64,"0") }; }
function sc(s){ return "0x"+s.toString(16).padStart(64,"0"); }

module.exports={ keccak256, utf8, hex, bigTo32, bytesToBig,
  P,N,G,H,O, mod, inv, onCurve, ecAdd, ecMul, ecNeg, pointAddr,
  randScalar, challenge, commit,
  proveOpening, verifyOpening, proveEquality, verifyEquality,
  pt, sc, TAG_OPEN, TAG_EQ };
