// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @notice Accepts any non-empty proof. For local testing only —
/// replace with an SP1/RISC Zero/Groth16 adapter before anything real.
contract NoopVerifier is IProofVerifier {
    function verify(bytes calldata proof, bytes32) external pure returns (bool) {
        return proof.length > 0;
    }
}
