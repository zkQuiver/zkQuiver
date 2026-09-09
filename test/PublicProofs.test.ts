import { expect } from "chai";
import { ethers } from "hardhat";
const { proveBundle } = require("../zk/prove.js");
const S = require("../zk/sigma.js");

describe("PublicProofs", () => {
  const ctx = S.keccak256(S.utf8("public/ctx"));
  const ctxHex = "0x" + S.hex(ctx);
  const rootA = S.keccak256(S.utf8("A")), rootB = S.keccak256(S.utf8("B"));

  async function setup() {
    const V = await ethers.getContractFactory("LineageVerifier");
    const v = await V.deploy();
    const P = await ethers.getContractFactory("PublicProofs");
    const p = await P.deploy(v.target);
    return { v, p };
  }

  it("records a valid proof with an id and event", async () => {
    const { p } = await setup();
    const [a] = await ethers.getSigners();
    const b = proveBundle(rootA, rootB, ctx);
    const tag = ethers.keccak256(ethers.toUtf8Bytes("alice"));
    expect(await p.check(b.hex, ctxHex)).to.equal(true);
    await expect(p.submit(b.hex, ctxHex, tag)).to.emit(p, "ProofRecorded");
    expect(await p.count()).to.equal(1);
    const r = await p.records(1);
    expect(r.submitter).to.equal(a.address);
    expect(r.tag).to.equal(tag);
  });

  it("rejects invalid proofs and duplicates", async () => {
    const { p } = await setup();
    const b = proveBundle(rootA, rootB, ctx);
    const bad = b.hex.slice(0, -2) + "00";
    await expect(p.submit(bad, ctxHex, ethers.ZeroHash)).to.be.revertedWithCustomError(p, "InvalidProof");
    await p.submit(b.hex, ctxHex, ethers.ZeroHash);
    await expect(p.submit(b.hex, ctxHex, ethers.ZeroHash)).to.be.revertedWithCustomError(p, "AlreadyRecorded");
    expect(await p.check(b.hex, ctxHex)).to.equal(false); // duplicate now
  });
});
