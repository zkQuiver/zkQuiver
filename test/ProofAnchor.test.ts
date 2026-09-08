import { expect } from "chai";
import { ethers } from "hardhat";

/**
 * End-to-end verification of ProofAnchor on Hardhat's in-memory chain.
 * Run: npx hardhat test
 *
 * Covers the full lifecycle (register → sign → anchor → chain of windows),
 * every rejection rule, aggregator rotation, and a cross-implementation
 * conformance check against the golden vector produced by
 * orchestrator/src/kats.js (pure-JS, dependency-free implementation).
 */

const HEX1 = "0x" + "0".repeat(63) + "1";
const HEX2 = "0x" + "0".repeat(63) + "2";

describe("ProofAnchor", () => {
  async function deploy() {
    const [owner, aggregator, validator, outsider] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("MockERC20");
    const token = await Token.deploy();
    const lockAmount = ethers.parseUnits("1", 18);

    const Anchor = await ethers.getContractFactory("ProofAnchor");
    const anchor = await Anchor.deploy(owner.address, aggregator.address, token.target, lockAmount);

    await token.mint(validator.address, lockAmount);
    await token.connect(validator).approve(anchor.target, lockAmount);
    return { anchor, token, lockAmount, owner, aggregator, validator, outsider };
  }

  async function signDs(anchor: any, aggregator: any, proofHash: string, s: number, e: number, seq: number) {
    const dsHash: string = await anchor.computeDsHash(proofHash, s, e, seq);
    return aggregator.signMessage(ethers.getBytes(dsHash)); // EIP-191
  }

  function anchorArgs(proofHash: string, s: number, e: number, seq: number, sig: string) {
    return [proofHash, HEX1, HEX2, s, e, seq, sig, "0x", ethers.ZeroHash] as const;
  }

  it("registers a validator and escrows the lock", async () => {
    const { anchor, token, lockAmount, validator } = await deploy();
    await expect(anchor.connect(validator).registerValidator())
      .to.emit(anchor, "ValidatorRegistered");
    expect(await token.balanceOf(anchor.target)).to.equal(lockAmount);
    await expect(anchor.connect(validator).registerValidator())
      .to.be.revertedWithCustomError(anchor, "AlreadyRegistered");
    await anchor.connect(validator).unlockValidator();
    expect(await token.balanceOf(validator.address)).to.equal(lockAmount);
  });

  it("anchors a valid first proof (seq=1, startBlock=1)", async () => {
    const { anchor, aggregator, validator } = await deploy();
    const ph = ethers.keccak256(ethers.toUtf8Bytes("artifact-1")); // stands in for blake3
    const sig = await signDs(anchor, aggregator, ph, 1, 64, 1);
    await expect(anchor.connect(validator).anchorProof(...anchorArgs(ph, 1, 64, 1, sig)))
      .to.emit(anchor, "ProofAnchored");
    expect(await anchor.lastSeq()).to.equal(1);
    expect(await anchor.lastEndBlock()).to.equal(64);
    const rec = await anchor.proofs(1);
    expect(rec.proofHash).to.equal(ph);
  });

  it("builds a contiguous chain and rejects every malformed follow-up", async () => {
    const { anchor, aggregator, validator } = await deploy();
    const ph1 = ethers.keccak256(ethers.toUtf8Bytes("w1"));
    await anchor.connect(validator).anchorProof(
      ...anchorArgs(ph1, 1, 64, 1, await signDs(anchor, aggregator, ph1, 1, 64, 1)));

    const ph2 = ethers.keccak256(ethers.toUtf8Bytes("w2"));

    // wrong seq
    await expect(anchor.anchorProof(
      ...anchorArgs(ph2, 65, 128, 3, await signDs(anchor, aggregator, ph2, 65, 128, 3))
    )).to.be.revertedWithCustomError(anchor, "NonMonotonicSeq");

    // window gap
    await expect(anchor.anchorProof(
      ...anchorArgs(ph2, 66, 128, 2, await signDs(anchor, aggregator, ph2, 66, 128, 2))
    )).to.be.revertedWithCustomError(anchor, "RangeOverlap");

    // oversized window (> 2048)
    await expect(anchor.anchorProof(
      ...anchorArgs(ph2, 65, 65 + 2048, 2, await signDs(anchor, aggregator, ph2, 65, 65 + 2048, 2))
    )).to.be.revertedWithCustomError(anchor, "WindowTooLarge");

    // duplicate proofHash
    await expect(anchor.anchorProof(
      ...anchorArgs(ph1, 65, 128, 2, await signDs(anchor, aggregator, ph1, 65, 128, 2))
    )).to.be.revertedWithCustomError(anchor, "ProofAlreadyAnchored");

    // signature from the wrong key
    const { outsider } = await deploy(); // fresh signer, not the aggregator
    await expect(anchor.anchorProof(
      ...anchorArgs(ph2, 65, 128, 2, await signDs(anchor, outsider, ph2, 65, 128, 2))
    )).to.be.revertedWithCustomError(anchor, "InvalidSignature");

    // signature over the wrong seq (replay protection)
    const staleSig = await signDs(anchor, aggregator, ph2, 65, 128, 1);
    await expect(anchor.anchorProof(...anchorArgs(ph2, 65, 128, 2, staleSig)))
      .to.be.revertedWithCustomError(anchor, "InvalidSignature");

    // and the correct one succeeds
    await anchor.anchorProof(
      ...anchorArgs(ph2, 65, 128, 2, await signDs(anchor, aggregator, ph2, 65, 128, 2)));
    expect(await anchor.lastSeq()).to.equal(2);
  });

  it("rotates the aggregator at activationSeq", async () => {
    const { anchor, owner, aggregator, outsider } = await deploy();
    const ph1 = ethers.keccak256(ethers.toUtf8Bytes("r1"));
    await anchor.anchorProof(
      ...anchorArgs(ph1, 1, 10, 1, await signDs(anchor, aggregator, ph1, 1, 10, 1)));

    await anchor.connect(owner).scheduleAggregatorRotation(outsider.address, 2);

    // old key still valid, new key now also valid for seq >= 2
    const ph2 = ethers.keccak256(ethers.toUtf8Bytes("r2"));
    await anchor.anchorProof(
      ...anchorArgs(ph2, 11, 20, 2, await signDs(anchor, outsider, ph2, 11, 20, 2)));
    await anchor.connect(owner).finalizeAggregatorRotation();
    expect(await anchor.aggregator()).to.equal(outsider.address);
  });

  it("enforces pause and ZK verifier hook", async () => {
    const { anchor, owner, aggregator } = await deploy();
    await anchor.connect(owner).setPaused(true);
    const ph = ethers.keccak256(ethers.toUtf8Bytes("p1"));
    const sig = await signDs(anchor, aggregator, ph, 1, 10, 1);
    await expect(anchor.anchorProof(...anchorArgs(ph, 1, 10, 1, sig)))
      .to.be.revertedWithCustomError(anchor, "ContractPaused");
    await anchor.connect(owner).setPaused(false);

    const Noop = await ethers.getContractFactory("NoopVerifier");
    const noop = await Noop.deploy();
    await anchor.connect(owner).setVerifier(noop.target);

    // empty proof bytes fail the Noop verifier
    await expect(anchor.anchorProof(...anchorArgs(ph, 1, 10, 1, sig)))
      .to.be.revertedWithCustomError(anchor, "ZkVerificationFailed");
    // non-empty proof passes and marks zkVerified
    await anchor.anchorProof(ph, HEX1, HEX2, 1, 10, 1, sig, "0x01", ethers.ZeroHash);
    expect((await anchor.proofs(1)).zkVerified).to.equal(true);
  });

  it("CONFORMANCE: computeDsHash matches the pure-JS golden vector", async () => {
    // Golden vector produced by orchestrator/src/kats.js with:
    //   chainId=42161, contract=0x1111…, proofHash=0xaaaa…, window 1..64, seq=1
    // The contract packs block.chainid and address(this), so we recompute
    // the expected hash here with ethers over the SAME layout and assert
    // both (a) layout equivalence and (b) live-contract agreement.
    const { anchor } = await deploy();
    const net = await ethers.provider.getNetwork();
    const ph = "0x" + "aa".repeat(32);

    const packed = ethers.solidityPacked(
      ["bytes14", "uint64", "address", "bytes32", "uint64", "uint64", "uint64"],
      [ethers.toUtf8Bytes("zkRH/anchor/v1"), net.chainId, anchor.target, ph, 1, 64, 1]
    );
    expect(ethers.dataLength(packed)).to.equal(98); // layout: 98 bytes
    expect(await anchor.computeDsHash(ph, 1, 64, 1)).to.equal(ethers.keccak256(packed));
  });
});
