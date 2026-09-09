// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IProofVerifier} from "./interfaces/IProofVerifier.sol";

/// @title PublicProofs
/// @notice Permissionless registry of zero-knowledge proof bundles.
/// Anyone may submit a bundle; it is checked by the same LineageVerifier
/// that guards the anchoring contract, and only accepted bundles are
/// recorded. Each record gets an id, a timestamp, the submitter, and an
/// optional tag chosen by the submitter (e.g. a hash of a nickname).
///
/// This is deliberately separate from ProofAnchor: the operator lineage
/// keeps its strict sequencing and aggregator signature, while this
/// registry lets any visitor create a permanent on-chain record that
/// their own proof verified.
contract PublicProofs {
    IProofVerifier public immutable verifier;
    uint256 public count;

    struct Record {
        address submitter;   // wallet or relayer that sent the tx
        bytes32 ctx;         // publicInputsHash the proof is bound to
        bytes32 tag;         // submitter-chosen label (may be zero)
        bytes32 bundleHash;  // keccak256(proof bytes)
        uint64  timestamp;
    }
    mapping(uint256 => Record) public records;
    mapping(bytes32 => uint256) public idByBundleHash; // dedupe

    event ProofRecorded(uint256 indexed id, address indexed submitter, bytes32 indexed ctx, bytes32 tag, bytes32 bundleHash);

    error InvalidProof();
    error AlreadyRecorded(uint256 id);

    constructor(IProofVerifier _verifier) { verifier = _verifier; }

    /// @notice Submit a bundle. Reverts unless the verifier accepts it.
    function submit(bytes calldata proof, bytes32 ctx, bytes32 tag) external returns (uint256 id) {
        bytes32 bh = keccak256(proof);
        uint256 existing = idByBundleHash[bh];
        if (existing != 0) revert AlreadyRecorded(existing);
        if (!verifier.verify(proof, ctx)) revert InvalidProof();
        id = ++count;
        records[id] = Record(msg.sender, ctx, tag, bh, uint64(block.timestamp));
        idByBundleHash[bh] = id;
        emit ProofRecorded(id, msg.sender, ctx, tag, bh);
    }

    /// @notice Free preflight: would this bundle be accepted?
    function check(bytes calldata proof, bytes32 ctx) external view returns (bool) {
        return idByBundleHash[keccak256(proof)] == 0 && verifier.verify(proof, ctx);
    }
}
