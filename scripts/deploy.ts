import { ethers } from "hardhat";

/**
 * Deploy ProofAnchor to Robinhood Chain.
 *
 * Robinhood Chain is fully EVM-compatible — Hardhat/Foundry work out of
 * the box. Configure the network in hardhat.config.ts with the RPC URL
 * and chain ID from https://docs.robinhood.com/chain/.
 *
 *   npx hardhat run scripts/deploy.ts --network robinhoodTestnet
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);

  const aggregator = process.env.AGGREGATOR_ADDRESS ?? deployer.address;
  const lockToken = process.env.LOCK_TOKEN_ADDRESS;
  const lockAmount = ethers.parseUnits(process.env.LOCK_AMOUNT ?? "1", 18);
  if (!lockToken) throw new Error("LOCK_TOKEN_ADDRESS required (SPL mint -> ERC-20)");

  const ProofAnchor = await ethers.getContractFactory("ProofAnchor");
  const anchor = await ProofAnchor.deploy(deployer.address, aggregator, lockToken, lockAmount);
  await anchor.waitForDeployment();
  console.log("ProofAnchor:", await anchor.getAddress());

  // Optional: deploy the Noop verifier for local end-to-end testing.
  if (process.env.DEPLOY_NOOP_VERIFIER === "1") {
    const Noop = await ethers.getContractFactory("NoopVerifier");
    const noop = await Noop.deploy();
    await noop.waitForDeployment();
    await (await anchor.setVerifier(await noop.getAddress())).wait();
    console.log("NoopVerifier:", await noop.getAddress());
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
