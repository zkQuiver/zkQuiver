// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Pluggable ZK verification hook for ProofAnchor.
/// Implementations wrap real verifier contracts:
///   - SP1: wrap ISP1Verifier.verifyProof(vkey, publicValues, proofBytes)
///   - RISC Zero: wrap IRiscZeroVerifier.verify(seal, imageId, journalDigest)
///   - Groth16: a snarkjs/circom-exported verifier
/// The adapter binds `publicInputsHash` (hash of the canonical public
/// input set: C_in, C_out, H_B, S_in, S_out) to the proof's public values.
interface IProofVerifier {
    function verify(bytes calldata proof, bytes32 publicInputsHash) external view returns (bool);
}
