import { ethers } from "hardhat";
/** Adds PublicProofs to an EXISTING deployment (uses LINEAGE_VERIFIER_ADDRESS from .env):
 *    npx hardhat run scripts/deploy-public.ts --network robinhoodTestnet            */
async function main() {
  const v = (process.env.LINEAGE_VERIFIER_ADDRESS ?? "").trim();
  if (!v) throw new Error("Set LINEAGE_VERIFIER_ADDRESS in .env");
  const PP = await ethers.getContractFactory("PublicProofs");
  const pub = await PP.deploy(v);
  await pub.waitForDeployment();
  const addr = await pub.getAddress();
  console.log("PublicProofs:", addr);
  console.log(`\nPUBLIC_PROOFS_ADDRESS=${addr}`);
  console.log(`https://explorer.testnet.chain.robinhood.com/address/${addr}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
