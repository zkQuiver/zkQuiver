import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";

const config: HardhatUserConfig = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    // In-memory chain: `npx hardhat test` needs no config at all.
    robinhoodTestnet: {
      url: process.env.RPC_URL ?? "",
      chainId: process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : undefined,
      accounts: process.env.SUBMITTER_PRIVATE_KEY ? [process.env.SUBMITTER_PRIVATE_KEY] : [],
    },
  },
};
export default config;
