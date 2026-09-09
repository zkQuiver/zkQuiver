import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";

// Accept keys with or without the 0x prefix (MetaMask exports without it).
const key = process.env.DEPLOYER_PRIVATE_KEY?.trim();
const accounts = key ? [key.startsWith("0x") ? key : "0x" + key] : [];

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true },
  },
  networks: {
    // In-memory chain: `npx hardhat test` needs no config at all.
    robinhoodTestnet: {
      url: process.env.RPC_URL ?? "https://rpc.testnet.chain.robinhood.com",
      chainId: Number(process.env.CHAIN_ID ?? 46630),
      accounts,
    },
  },
};
export default config;
