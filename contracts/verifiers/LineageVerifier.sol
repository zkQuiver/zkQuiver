// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/// @title LineageVerifier
/// @notice On-chain verifier for zkQuiver's sigma layer: Pedersen
/// commitments to state roots with NIZK proofs of opening (Okamoto)
/// and a Chaum-Pedersen equality proof linking the previous window's
/// C_out to this window's C_in, all without revealing the roots.
///
/// secp256k1 scalar multiplication uses the ecrecover trick: ecrecover
/// yields the ADDRESS of (u1*G + u2*Q) in one call, so each sigma
/// equation is checked as an address equality between a point built
/// with one affine addition and the trick's output. Address comparison
/// is a 160-bit check; adequate for the testnet phase, stated openly.
///
/// Scope, stated plainly: proves commitment structure and lineage
/// linkage in zero knowledge. Does NOT prove the state transition is
/// correct; that is the zkVM tier (roadmap).
contract LineageVerifier is IProofVerifier {
    uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    // H: second generator, derived nothing-up-my-sleeve (zk/sigma.js deriveH)
    uint256 constant HX = 0x2253541214afe1c3d68a15e9bfcb88ab06e23ca73be393f0940f64104c2ecc04;
    uint256 constant HY = 0x3ca0237cecaa87892721fe5e06cd8d57d0e2016c2d5ab720a535afb8acb8b67c;

    struct Pt { uint256 x; uint256 y; }

    // Bundle layout, 23 words (zk/prove.js):
    // [0..1] C_in  [2..3] C_out  [4..5] prevCout
    // [6..7] openIn.A  [8] z1 [9] z2 [10..11] openIn.CC (= c*C_in)
    // [12..13] openOut.A [14] z1 [15] z2 [16..17] openOut.CC
    // [18..19] eq.A [20] z [21..22] eq.CD (= c*D)

    function verify(bytes calldata proof, bytes32 publicInputsHash)
        external pure returns (bool)
    {
        if (proof.length != 23 * 32) return false;
        uint256[23] memory w = abi.decode(proof, (uint256[23]));

        Pt memory cIn  = Pt(w[0], w[1]);
        Pt memory cOut = Pt(w[2], w[3]);
        Pt memory prev = Pt(w[4], w[5]);
        if (!onCurve(cIn) || !onCurve(cOut) || !onCurve(prev)) return false;

        bytes32 ctx = publicInputsHash; // proofs were generated bound to this

        if (!verifyOpening(cIn,  Pt(w[6], w[7]),   w[8],  w[9],  Pt(w[10], w[11]), ctx)) return false;
        if (!verifyOpening(cOut, Pt(w[12], w[13]), w[14], w[15], Pt(w[16], w[17]), ctx)) return false;
        if (!verifyEquality(prev, cIn, Pt(w[18], w[19]), w[20], Pt(w[21], w[22]), ctx)) return false;
        return true;
    }

    /// Okamoto: z1*G + z2*H == A + c*C, with CC (= c*C) supplied and address-checked.
    function verifyOpening(Pt memory C, Pt memory A, uint256 z1, uint256 z2, Pt memory CC, bytes32 ctx)
        internal pure returns (bool)
    {
        if (!onCurve(A) || !onCurve(CC)) return false;
        uint256 c = uint256(keccak256(abi.encodePacked(
            "zkQuiver/sigma/open/v1", C.x, C.y, A.x, A.y, ctx))) % NN;
        if (ecmulAddr(0, c, C) != pointAddr(CC)) return false;   // CC == c*C
        Pt memory R = ecAdd(A, CC);                                // A + c*C
        return ecmulAddr(z1, z2, Pt(HX, HY)) == pointAddr(R);      // z1*G + z2*H
    }

    /// Chaum-Pedersen: D = C1 - C2; z*H == A + c*D, with CD (= c*D) supplied and address-checked.
    function verifyEquality(Pt memory C1, Pt memory C2, Pt memory A, uint256 z, Pt memory CD, bytes32 ctx)
        internal pure returns (bool)
    {
        if (!onCurve(A) || !onCurve(CD)) return false;
        uint256 c = uint256(keccak256(abi.encodePacked(
            "zkQuiver/sigma/eq/v1", C1.x, C1.y, C2.x, C2.y, A.x, A.y, ctx))) % NN;
        Pt memory D = ecAdd(C1, Pt(C2.x, PP - C2.y));             // C1 + (-C2)
        if (D.x == 0 && D.y == 0) return false;                    // C1 == C2: reject
        if (ecmulAddr(0, c, D) != pointAddr(CD)) return false;    // CD == c*D
        Pt memory R = ecAdd(A, CD);
        return ecmulAddr(0, z, Pt(HX, HY)) == pointAddr(R);        // z*H
    }

    // ---------------- secp256k1 helpers ----------------

    function onCurve(Pt memory Q) internal pure returns (bool) {
        if (Q.x >= PP || Q.y >= PP) return false;
        return mulmod(Q.y, Q.y, PP) == addmod(mulmod(Q.x, mulmod(Q.x, Q.x, PP), PP), 7, PP);
    }

    /// Affine addition; returns (0,0) as the infinity sentinel.
    function ecAdd(Pt memory a, Pt memory b) internal pure returns (Pt memory r) {
        uint256 l;
        if (a.x == b.x) {
            if (addmod(a.y, b.y, PP) == 0) return Pt(0, 0);
            l = mulmod(mulmod(3, mulmod(a.x, a.x, PP), PP), inv(mulmod(2, a.y, PP)), PP);
        } else {
            l = mulmod(addmod(b.y, PP - a.y, PP), inv(addmod(b.x, PP - a.x, PP)), PP);
        }
        r.x = addmod(addmod(mulmod(l, l, PP), PP - a.x, PP), PP - b.x, PP);
        r.y = addmod(mulmod(l, addmod(a.x, PP - r.x, PP), PP), PP - a.y, PP);
    }

    function inv(uint256 a) internal pure returns (uint256) { return expmod(a, PP - 2, PP); }

    function expmod(uint256 b, uint256 e, uint256 m) internal pure returns (uint256 r) {
        r = 1; b %= m;
        while (e > 0) {
            if (e & 1 == 1) r = mulmod(r, b, m);
            b = mulmod(b, b, m);
            e >>= 1;
        }
    }

    /// last 20 bytes of keccak(x || y)
    function pointAddr(Pt memory Q) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(Q.x, Q.y)))));
    }

    /// ecrecover trick: address(u1*G + u2*Q). Requires Q.x in (0, n).
    function ecmulAddr(uint256 u1, uint256 u2, Pt memory Q) internal pure returns (address) {
        if (Q.x == 0 || Q.x >= NN) return address(0);
        uint256 s = mulmod(u2 % NN, Q.x, NN);
        if (s == 0) return address(0);
        uint256 e = mulmod(u1 % NN, Q.x, NN);
        e = e == 0 ? 0 : NN - e;                       // hash = -u1*Q.x mod n
        uint8 v = (Q.y & 1 == 0) ? 27 : 28;
        return ecrecover(bytes32(e), v, bytes32(Q.x), bytes32(s));
    }
}
