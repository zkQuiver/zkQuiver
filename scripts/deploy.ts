import { ethers } from "hardhat";

/**
 * One-command testnet deployment:
 *   npx hardhat run scripts/deploy.ts --network robinhoodTestnet
 * Needs only DEPLOYER_PRIVATE_KEY in .env (wallet funded from the faucet).
 * Deploys: lock token (Mock, unless LOCK_TOKEN_ADDRESS set) -> ProofAnchor
 * -> LineageVerifier -> setVerifier. Prints .env lines, the site's
 * ZKQ_ONCHAIN snippet, and explorer links.
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error("Set DEPLOYER_PRIVATE_KEY in .env");
  const net = await ethers.provider.getNetwork();
  const bal = await ethers.provider.getBalance(deployer.address);
  console.log(`deployer ${deployer.address} | chain ${net.chainId} | balance ${ethers.formatEther(bal)} ETH`);
  if (bal === 0n) throw new Error("Wallet has 0 ETH. Get test ETH: https://faucet.testnet.chain.robinhood.com");

  // Blank .env values must count as "unset" (?? alone treats "" as a value)
  const envAddr = (k: string) => { const v = (process.env[k] ?? "").trim(); return v ? v : undefined; };
  let lockToken = envAddr("LOCK_TOKEN_ADDRESS");
  if (!lockToken) {
    const Token = await ethers.getContractFactory("MockERC20");
    const token = await Token.deploy();
    await token.waitForDeployment();
    lockToken = await token.getAddress();
    console.log("lock token (MockERC20):", lockToken);
  }

  const aggregator = envAddr("AGGREGATOR_ADDRESS") ?? deployer.address;
  console.log("aggregator:", aggregator, aggregator === deployer.address ? "(deployer; set AGGREGATOR_ADDRESS to a separate hot wallet for launch)" : "");
  const Anchor = await ethers.getContractFactory("ProofAnchor");
  const anchor = await Anchor.deploy(deployer.address, aggregator, lockToken, ethers.parseUnits("1", 18));
  await anchor.waitForDeployment();
  const anchorAddr = await anchor.getAddress();
  console.log("ProofAnchor:", anchorAddr);

  const V = await ethers.getContractFactory("LineageVerifier");
  const verifier = await V.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  await (await anchor.setVerifier(verifierAddr)).wait();
  console.log("LineageVerifier:", verifierAddr, "(wired: every anchor now requires a valid ZK bundle)");

  const rpc = (process.env.RPC_URL ?? "https://rpc.testnet.chain.robinhood.com");
  console.log("\n----- paste into .env -----");
  console.log(`PROOF_ANCHOR_ADDRESS=${anchorAddr}`);
  console.log(`LINEAGE_VERIFIER_ADDRESS=${verifierAddr}`);
  console.log("\n----- paste into site/index.html (ZKQ_ONCHAIN) -----");
  console.log(`window.ZKQ_ONCHAIN = { rpcUrl: "${rpc}", contract: "${anchorAddr}" };`);
  console.log("\n----- explorer -----");
  console.log(`https://explorer.testnet.chain.robinhood.com/address/${anchorAddr}`);
}
main().catch((e) => { console.error(e); process.exit(1); });
