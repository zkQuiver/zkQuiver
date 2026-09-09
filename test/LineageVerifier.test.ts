import { expect } from "chai";
import { ethers } from "hardhat";
// The zero-dependency prover: same code that runs `node zk/selftest.js`
const { proveBundle, verifyBundleJS } = require("../zk/prove.js");
const S = require("../zk/sigma.js");

/**
 * On-chain verification of the sigma layer. Proof bundles are generated
 * fresh by the real prover at test time and must verify BOTH in the JS
 * contract-mirror and in the deployed LineageVerifier — any divergence
 * between the two implementations fails the suite.
 */
describe("LineageVerifier", () => {
  const ctx = S.keccak256(S.utf8("anchor/pi-hash/test"));
  const rootA = S.keccak256(S.utf8("rootA"));
  const rootB = S.keccak256(S.utf8("rootB"));
  const ctxHex = "0x" + S.hex(ctx);

  async function deployed() {
    const V = await ethers.getContractFactory("LineageVerifier");
    return V.deploy();
  }

  it("accepts a valid bundle (and JS mirror agrees)", async () => {
    const v = await deployed();
    const b = proveBundle(rootA, rootB, ctx);
    expect(verifyBundleJS(b.words, ctx)).to.equal(true);
    expect(await v.verify(b.hex, ctxHex)).to.equal(true);
  });

  it("rejects under a different publicInputsHash", async () => {
    const v = await deployed();
    const b = proveBundle(rootA, rootB, ctx);
    const other = "0x" + S.hex(S.keccak256(S.utf8("different-anchor")));
    expect(await v.verify(b.hex, other)).to.equal(false);
  });

  it("rejects tampered responses", async () => {
    const v = await deployed();
    const b = proveBundle(rootA, rootB, ctx);
    for (const idx of [8, 14, 20]) { // z1_in, z1_out, z_eq
      const w = b.words.slice();
      w[idx] = (w[idx] + 1n) % S.N;
      const buf = new Uint8Array(23 * 32);
      w.forEach((x: bigint, i: number) => buf.set(S.bigTo32(x), i * 32));
      expect(await v.verify("0x" + S.hex(buf), ctxHex)).to.equal(false);
    }
  });

  it("rejects an equality forgery between different hidden roots", async () => {
    const v = await deployed();
    const b = proveBundle(rootA, rootB, ctx);
    const other = proveBundle(rootB, rootB, ctx);
    const w = b.words.slice();
    w[4] = other.words[4]; w[5] = other.words[5]; // swap in a foreign prevCout
    const buf = new Uint8Array(23 * 32);
    w.forEach((x: bigint, i: number) => buf.set(S.bigTo32(x), i * 32));
    expect(await v.verify("0x" + S.hex(buf), ctxHex)).to.equal(false);
  });

  it("plugs into ProofAnchor as the live verifier", async () => {
    const [owner, aggregator] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("MockERC20");
    const token = await Token.deploy();
    const Anchor = await ethers.getContractFactory("ProofAnchor");
    const anchor = await Anchor.deploy(owner.address, aggregator.address,
      token.target, ethers.parseUnits("1", 18));
    const v = await deployed();
    await anchor.setVerifier(v.target);

    const b = proveBundle(rootA, rootB, ctx);
    const ph = ethers.keccak256(ethers.toUtf8Bytes("w1"));
    const dsHash = await anchor.computeDsHash(ph, 1, 64, 1);
    const sig = await aggregator.signMessage(ethers.getBytes(dsHash));

    // valid ZK bundle: anchors, and the record is marked zkVerified
    await anchor.anchorProof(ph, ethers.ZeroHash, ethers.ZeroHash,
      1, 64, 1, sig, b.hex, ctxHex);
    expect((await anchor.proofs(1)).zkVerified).to.equal(true);

    // invalid bundle: the anchor itself reverts
    const ph2 = ethers.keccak256(ethers.toUtf8Bytes("w2"));
    const ds2 = await anchor.computeDsHash(ph2, 65, 128, 2);
    const sig2 = await aggregator.signMessage(ethers.getBytes(ds2));
    const bad = b.hex.slice(0, -2) + "00";
    await expect(anchor.anchorProof(ph2, ethers.ZeroHash, ethers.ZeroHash,
      65, 128, 2, sig2, bad, ctxHex))
      .to.be.revertedWithCustomError(anchor, "ZkVerificationFailed");
  });
});
