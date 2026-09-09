#!/usr/bin/env node
// Fails (exit 1) if a 64-hex-character string (private-key shaped) appears
// anywhere in the repo outside .env. Known non-secret 64-hex constants
// (curve parameters, generator coordinates, test vectors) are allow-listed
// by file. Run: node scripts/scan-secrets.js
"use strict";
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const ALLOW = new Set(["zk/sigma.js", "zk/selftest.js", "contracts/verifiers/LineageVerifier.sol",
  "orchestrator/src/kats.js", "site/index.html", "site/docs.html", "test/ProofAnchor.test.ts",
  "test/LineageVerifier.test.ts", "README.md", "SECURITY.md", "RUNBOOK.md"]);
const SKIP = /node_modules|\.git\/|artifacts|cache|dist|target|\.png$|\.zip$|\.lock$/;
const KEYISH = /(?:PRIVATE_KEY|private_key|privkey|secret)\s*[=:]\s*["']?(?:0x)?[0-9a-fA-F]{64}/;
let hits = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name), rel = path.relative(root, p).replace(/\\/g, "/");
    if (SKIP.test(rel + (e.isDirectory() ? "/" : ""))) continue;
    if (e.isDirectory()) { walk(p); continue; }
    if (rel === ".env") continue;
    const txt = fs.readFileSync(p, "utf8");
    if (KEYISH.test(txt)) hits.push(rel + "  (key assignment)");
    else if (!ALLOW.has(rel) && /(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/.test(txt)) hits.push(rel + "  (64-hex string)");
  }
})(root);
if (hits.length) { console.log("SECRET SCAN: possible private key material found:\n  " + hits.join("\n  ")); process.exit(1); }
console.log("secret scan: clean");
