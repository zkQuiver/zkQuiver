// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IProofVerifier} from "./interfaces/IProofVerifier.sol";

/// @title ProofAnchor
/// @notice Anchors zero-knowledge proof records of block-window state transitions.
/// A designated aggregator signs a domain-separated (DS) message binding
/// each proof to (chainId, this contract, proofHash, blockWindow, seq).
/// The contract enforces:
///   - aggregator signature over the DS message (ECDSA / ecrecover)
///   - strictly monotonic sequence numbers (first proof is seq = 1)
///   - contiguous block windows (startBlock = lastEndBlock + 1)
///   - bounded window size (MAX_BLOCKS_PER_ARTIFACT)
///   - optional on-chain ZK verification via a pluggable IProofVerifier
///     (SP1 / RISC Zero / Groth16 verifier contracts drop in here)
///
/// Validator Lock: operators escrow exactly `lockAmount` of `lockToken`
/// to register — the protocol's economic engine.
contract ProofAnchor is Ownable {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------
    // Constants (protocol spec)
    // ---------------------------------------------------------------

    /// @dev 14-byte ASCII domain-separation prefix.
    bytes14 public constant DS_PREFIX = "zkRH/anchor/v1";
    uint64 public constant MAX_BLOCKS_PER_ARTIFACT = 2048;

    // ---------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------

    enum ValidatorStatus {
        None,
        Active,
        Unlocked
    }

    struct ValidatorRecord {
        ValidatorStatus status;
        uint64 lockTs;
        uint64 unlockTs;
        uint64 numAccepts;
    }

    struct ProofRecord {
        bytes32 proofHash;        // blake3(canonical artifact JSON), computed off-chain
        bytes32 dsHash;           // keccak256(DS message)
        bytes32 stateRootBefore;  // C_in
        bytes32 stateRootAfter;   // C_out
        uint64 startBlock;
        uint64 endBlock;
        uint64 timestamp;
        address submittedBy;
        bool zkVerified;          // true iff verifier was set and accepted the proof
    }

    // ---------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------

    address public aggregator;
    address public nextAggregator;
    uint64 public activationSeq;   // seq at which nextAggregator becomes valid
    bool public paused;

    IERC20 public immutable lockToken;
    uint256 public immutable lockAmount;

    IProofVerifier public verifier; // zero address => hash-anchoring mode only

    uint64 public lastSeq;
    uint64 public lastEndBlock;

    mapping(uint64 seq => ProofRecord) public proofs;
    mapping(bytes32 proofHash => uint64 seq) public seqByProofHash;
    mapping(address => ValidatorRecord) public validators;

    // ---------------------------------------------------------------
    // Events (the indexer's data source)
    // ---------------------------------------------------------------

    event ProofAnchored(
        uint64 indexed seq,
        bytes32 indexed proofHash,
        bytes32 dsHash,
        uint64 startBlock,
        uint64 endBlock,
        address submittedBy,
        bool zkVerified
    );
    event ValidatorRegistered(address indexed validator, uint64 lockTs);
    event ValidatorUnlocked(address indexed validator, uint64 unlockTs);
    event AggregatorRotationScheduled(address indexed next, uint64 activationSeq);
    event VerifierUpdated(address indexed verifier);
    event PausedSet(bool paused);

    // ---------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------

    error InvalidSignature();
    error AggregatorMismatch();
    error ProofAlreadyAnchored();
    error NonMonotonicSeq();
    error RangeOverlap();
    error BadDomainSeparation();
    error ContractPaused();
    error AlreadyRegistered();
    error NotRegistered();
    error WindowTooLarge();
    error InvalidWindow();
    error ZkVerificationFailed();

    constructor(
        address _owner,
        address _aggregator,
        IERC20 _lockToken,
        uint256 _lockAmount
    ) Ownable(_owner) {
        aggregator = _aggregator;
        lockToken = _lockToken;
        lockAmount = _lockAmount;
    }

    // ---------------------------------------------------------------
    // Validator Lock (escrow economic engine)
    // ---------------------------------------------------------------

    function registerValidator() external {
        ValidatorRecord storage v = validators[msg.sender];
        if (v.status == ValidatorStatus.Active) revert AlreadyRegistered();
        v.status = ValidatorStatus.Active;
        v.lockTs = uint64(block.timestamp);
        v.unlockTs = 0;
        lockToken.safeTransferFrom(msg.sender, address(this), lockAmount);
        emit ValidatorRegistered(msg.sender, v.lockTs);
    }

    function unlockValidator() external {
        ValidatorRecord storage v = validators[msg.sender];
        if (v.status != ValidatorStatus.Active) revert NotRegistered();
        v.status = ValidatorStatus.Unlocked;
        v.unlockTs = uint64(block.timestamp);
        lockToken.safeTransfer(msg.sender, lockAmount);
        emit ValidatorUnlocked(msg.sender, v.unlockTs);
    }

    // ---------------------------------------------------------------
    // Proof anchoring
    // ---------------------------------------------------------------

    /// @notice Anchor a proof record for a contiguous block window.
    /// @param proofHash        blake3 hash of the canonical artifact JSON
    /// @param stateRootBefore  state commitment at window start (C_in)
    /// @param stateRootAfter   state commitment at window end (C_out)
    /// @param startBlock       inclusive window start
    /// @param endBlock         inclusive window end
    /// @param seq              monotonic sequence number (first = 1)
    /// @param aggregatorSig    aggregator's EIP-191 signature over dsHash
    /// @param zkProof          optional proof bytes for the pluggable verifier
    /// @param publicInputsHash blake3/keccak hash of canonical public inputs
        function anchorProof(
        bytes32 proofHash,
        bytes32 stateRootBefore,
        bytes32 stateRootAfter,
        uint64 startBlock,
        uint64 endBlock,
        uint64 seq,
        bytes calldata aggregatorSig,
        bytes calldata zkProof,
        bytes32 publicInputsHash
    ) external {
        if (paused) revert ContractPaused();
        if (seqByProofHash[proofHash] != 0) revert ProofAlreadyAnchored();

        // Sequence monotonicity: first proof must be seq = 1.
        if (seq != lastSeq + 1) revert NonMonotonicSeq();

        // Contiguous, bounded window: first window starts at block 1.
        if (startBlock != lastEndBlock + 1) revert RangeOverlap();
        if (endBlock < startBlock) revert InvalidWindow();
        if (endBlock - startBlock + 1 > MAX_BLOCKS_PER_ARTIFACT) revert WindowTooLarge();

        // Domain separation + aggregator signature.
        bytes32 dsHash = computeDsHash(proofHash, startBlock, endBlock, seq);
        address signer = ECDSA.recover(
            MessageHashUtils.toEthSignedMessageHash(dsHash),
            aggregatorSig
        );
        if (!_isValidAggregator(signer, seq)) revert InvalidSignature();

        // Optional on-chain ZK verification. SP1/RISC Zero/Groth16
        // verifiers implement IProofVerifier and slot in here.
        bool zkVerified = false;
        if (address(verifier) != address(0)) {
            if (!verifier.verify(zkProof, publicInputsHash)) {
                revert ZkVerificationFailed();
            }
            zkVerified = true;
        }

        proofs[seq] = ProofRecord({
            proofHash: proofHash,
            dsHash: dsHash,
            stateRootBefore: stateRootBefore,
            stateRootAfter: stateRootAfter,
            startBlock: startBlock,
            endBlock: endBlock,
            timestamp: uint64(block.timestamp),
            submittedBy: msg.sender,
            zkVerified: zkVerified
        });
        seqByProofHash[proofHash] = seq;
        lastSeq = seq;
        lastEndBlock = endBlock;

        ValidatorRecord storage v = validators[msg.sender];
        if (v.status == ValidatorStatus.Active) {
            unchecked { v.numAccepts += 1; }
        }

        emit ProofAnchored(seq, proofHash, dsHash, startBlock, endBlock, msg.sender, zkVerified);
    }

    /// @notice Deterministic DS hash — must byte-match the prover and
    ///         orchestrator implementations (see conformance tests).
    /// Layout (abi.encodePacked):
    ///   prefix(14) | chainId u64 | contract addr(20) | proofHash(32)
    ///   | startBlock u64 | endBlock u64 | seq u64      => 98 bytes
    function computeDsHash(
        bytes32 proofHash,
        uint64 startBlock,
        uint64 endBlock,
        uint64 seq
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                DS_PREFIX,
                uint64(block.chainid),
                address(this),
                proofHash,
                startBlock,
                endBlock,
                seq
            )
        );
    }

    function _isValidAggregator(address signer, uint64 seq) internal view returns (bool) {
        if (signer == aggregator) return true;
        if (nextAggregator != address(0) && seq >= activationSeq && signer == nextAggregator) {
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------

    function scheduleAggregatorRotation(address _next, uint64 _activationSeq) external onlyOwner {
        nextAggregator = _next;
        activationSeq = _activationSeq;
        emit AggregatorRotationScheduled(_next, _activationSeq);
    }

    /// @notice Finalize a scheduled rotation once activationSeq has passed.
    function finalizeAggregatorRotation() external onlyOwner {
        if (nextAggregator == address(0) || lastSeq < activationSeq) revert AggregatorMismatch();
        aggregator = nextAggregator;
        nextAggregator = address(0);
        activationSeq = 0;
    }

    function setVerifier(IProofVerifier _verifier) external onlyOwner {
        verifier = _verifier;
        emit VerifierUpdated(address(_verifier));
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedSet(_paused);
    }
}
