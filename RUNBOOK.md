# RUNBOOK: finishing zkQuiver (testnet-live, verifiable on-chain)

Everything below is mechanical. Run `npm run doctor` at any point and it
prints the single next command. Never upload `.env`.

## 0. One-time machine setup (10 min)
1. Install Node.js LTS: https://nodejs.org (accept defaults).
2. Open a terminal inside the project folder (File Explorer > address bar >
   type `cmd` > Enter).
3. `npm run doctor`  ->  expect KATs 17/17 and ZK self-test 11/11.

## 1. Local proof that the whole stack works (15 min + fixes)
    npm install
    npx hardhat test
Expected: a list of green ticks. Suites: ProofAnchor (lifecycle, every
rejection rule, rotation, verifier hook, DS conformance) and LineageVerifier
(valid ZK bundle accepted, tampered/forged rejected, end-to-end through
ProofAnchor with zkVerified = true).

If red: copy the ENTIRE output and paste it to the assistant. First-run
compiler fixes are expected and small. Do not deploy until fully green.

Common snags:
- "running scripts is disabled": you are in PowerShell; use cmd.
- "cannot find module hardhat": `npm install` did not finish; rerun it.
- "Stack too deep": already mitigated (viaIR on); paste output if it appears.

## 2. Wallet + test ETH (10 min)
Key safety first (SECURITY.md): fresh wallets only, `.env` never leaves this
machine, and never paste a private key anywhere, including into a chat with
the assistant. If you need debugging help, paste error output, not `.env`.
1. Create a FRESH wallet in MetaMask (never your main one).
2. Add network: RPC https://rpc.testnet.chain.robinhood.com, chain ID 46630,
   symbol ETH, explorer https://explorer.testnet.chain.robinhood.com
3. Get free test ETH: https://faucet.testnet.chain.robinhood.com
   (drips are small; request early, more than once if needed).
4. Copy `.env.example` to `.env`, paste the wallet's private key into
   DEPLOYER_PRIVATE_KEY (with or without 0x, both work).

## 3. Deploy (2 min)
    npm run deploy:testnet
Deploys lock token -> ProofAnchor -> LineageVerifier, wires the verifier
(every anchor now requires a valid zero-knowledge bundle), and prints:
- lines to paste into `.env` (PROOF_ANCHOR_ADDRESS, LINEAGE_VERIFIER_ADDRESS)
- the `window.ZKQ_ONCHAIN = {...}` line for the website
- explorer links

## 4. First on-chain, ZK-verified record (1 min)
    npm run anchor:testnet
Generates a real proof bundle, signs the domain-separated message, submits.
Prints the tx link and `zkVerified on-chain: true`. Run it again for seq 2,
3, ... each new record links to the previous one in zero knowledge.

## 5. Make the website verify against the live contract (2 min)
Open `site/index.html`, find `window.ZKQ_ONCHAIN`, paste the line printed
by deploy (or just the contract address). Re-upload `index.html` to Netlify.
Press "Run verification" on the live site: after the 17 local assertions it
now shows the on-chain cross-check against your deployed contract.

## 5b. Let visitors record their own proofs on-chain (optional, 15 min)
1. `npm install` (adds ethers + @netlify/blobs for the relayer), then
   `npx hardhat test` (PublicProofs suite included).
2. `npm run deploy:public` -> prints PUBLIC_PROOFS_ADDRESS. Put it in `.env`
   and into `window.ZKQ_ONCHAIN` in `site/index.html` (publicProofs field).
3. Wallet path works immediately after re-uploading the site (visitors pay).
4. Free path (relayer): in Netlify, switch the site to "Import from GitHub"
   (build command empty; netlify.toml sets publish=site and the functions
   dir). Create a FRESH relayer wallet, fund it modestly (testnet: faucet;
   mainnet: $20 to $50 covers thousands of txs), and set environment
   variables in Netlify: RELAYER_PRIVATE_KEY, PUBLIC_PROOFS_ADDRESS.
   Optional: RELAY_PER_IP_PER_DAY (default 2), RELAY_GLOBAL_PER_DAY (300).
   The key never enters the repo or the site.

## 6. Publish
- GitHub: upload the whole folder (see README), including the workflow at
  `.github/workflows/ci.yml` (create by paste if the hidden folder is
  dropped by your browser). Badge turns green when CI passes.
- Verify the contracts' source on the explorer (Blockscout supports
  Hardhat flattened/standard-json verification): unverified contracts read
  as red flags to careful buyers.
- Then the article can truthfully say: deployed on Robinhood Chain testnet,
  zero-knowledge bundles verified on-chain, verify it from your browser.

## What remains after this (roadmap, not blockers)
- Mainnet deployment (chain ID 4663): same commands with RPC_URL/CHAIN_ID
  changed; real ETH for gas; contract freeze + full test pass first.
- zkVM tier (transition-correctness proving via SP1/RISC Zero): weeks+,
  treasury-funded. Docs already frame it honestly.
