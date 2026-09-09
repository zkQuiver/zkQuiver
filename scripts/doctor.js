#!/usr/bin/env node
// zkQuiver preflight. Bare node. Checks the machine, runs the zero-dep
// suites, inspects .env, and prints the single next command to run.
"use strict";
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "..");
const ok = (m) => console.log("  OK   " + m);
const bad = (m) => console.log("  !!   " + m);
let next = null;

console.log("\nzkQuiver doctor\n");
const major = Number(process.versions.node.split(".")[0]);
major >= 20 ? ok(`node ${process.versions.node}`) : (bad(`node ${process.versions.node} is old; install LTS from nodejs.org`), next = next || "install Node.js LTS, then rerun: npm run doctor");

for (const [name, cmd] of [["conformance KATs", "node orchestrator/src/kats.js"], ["ZK self-test", "node zk/selftest.js"]]) {
  try { const out = execSync(cmd, { cwd: root, stdio: "pipe" }).toString().trim().split("\n").pop(); ok(`${name}: ${out}`); }
  catch (e) { bad(`${name} FAILED`); next = next || `run '${cmd}' and send the output`; }
}

const hasModules = fs.existsSync(path.join(root, "node_modules", "hardhat"));
hasModules ? ok("hardhat installed") : (bad("hardhat not installed yet"), next = next || "npm install");

const envPath = path.join(root, ".env");
const env = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : "";
const get = (k) => (env.match(new RegExp("^" + k + "=(.*)$", "m")) || [])[1]?.trim();
if (!env) { bad(".env missing (copy .env.example to .env)"); }
else {
  get("DEPLOYER_PRIVATE_KEY") ? ok("DEPLOYER_PRIVATE_KEY set") : bad("DEPLOYER_PRIVATE_KEY empty");
  get("PROOF_ANCHOR_ADDRESS") ? ok(`PROOF_ANCHOR_ADDRESS ${get("PROOF_ANCHOR_ADDRESS")}`) : bad("PROOF_ANCHOR_ADDRESS empty (filled by deploy)");
}
try { execSync("node scripts/scan-secrets.js", { cwd: root, stdio: "pipe" }); ok("secret scan clean (no key material outside .env)"); }
catch (e) { bad("SECRET SCAN FAILED: key-shaped string outside .env. Remove it before uploading anything."); next = next || "node scripts/scan-secrets.js  (and remove what it flags)"; }
if (fs.existsSync(path.join(root, ".gitignore")) && /\.env/.test(fs.readFileSync(path.join(root, ".gitignore"), "utf8"))) ok(".env is git-ignored");
else bad(".gitignore missing .env line: never upload .env");

if (!next) {
  if (!hasModules) next = "npm install";
  else if (!fs.existsSync(path.join(root, "artifacts"))) next = "npx hardhat test";
  else if (!env || !get("DEPLOYER_PRIVATE_KEY")) next = "copy .env.example to .env, add DEPLOYER_PRIVATE_KEY (fresh wallet, funded at faucet.testnet.chain.robinhood.com)";
  else if (!get("PROOF_ANCHOR_ADDRESS")) next = "npm run deploy:testnet";
  else next = "npm run anchor:testnet   (then paste PROOF_ANCHOR_ADDRESS into site/index.html ZKQ_ONCHAIN)";
}
console.log("\nNEXT:  " + next + "\n");
