// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./GoldilocksExt3.sol";

/// @title SumcheckBridgeVerifier
/// @notice Verifies the sumcheck inner product argument that bridges
///         univariate polynomial evaluation p(ζ) to WHIR's MLE evaluation at point r.
///
///         Proves: Σ_{b ∈ {0,1}^n} f(b) · h_ζ(b) = p(ζ)
///         where h_ζ(b) = ζ^{int(b)}.
///
///         After verification, the verifier obtains:
///         - evalPoint r = (r_1, ..., r_n) derived from Fiat-Shamir
///         - finalClaim such that f(r) · h_ζ(r) = finalClaim
///
///         The WHIR proof then proves f(r) = v, and the verifier checks v · h_ζ(r) == finalClaim.
library SumcheckBridgeVerifier {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    uint64 constant GL_P = 0xFFFFFFFF00000001;

    /// @notice Verify sumcheck bridge proof and derive the evaluation point.
    /// @param numRounds Number of sumcheck rounds (= num_variables)
    /// @param roundPolys Round polynomials: roundPolys[i] = [g_i(0), g_i(1), g_i(2)]
    /// @param zeta The univariate evaluation point ζ (in Ext3)
    /// @param claimedSum The claimed value p(ζ) = Σ f(b) · h_ζ(b)
    /// @param sessionName Session name for Fiat-Shamir domain separation
    /// @return evalPoint The derived evaluation point r = (r_1, ..., r_n)
    /// @return finalClaim The final claim value (= g_{n-1}(r_{n-1}))
    function verify(
        uint256 numRounds,
        GoldilocksExt3.Ext3[][] memory roundPolys,
        GoldilocksExt3.Ext3 memory zeta,
        GoldilocksExt3.Ext3 memory claimedSum,
        string memory sessionName
    )
        internal
        pure
        returns (
            GoldilocksExt3.Ext3[] memory evalPoint,
            GoldilocksExt3.Ext3 memory finalClaim
        )
    {
        require(roundPolys.length == numRounds, "round count mismatch");

        evalPoint = new GoldilocksExt3.Ext3[](numRounds);
        GoldilocksExt3.Ext3 memory currentClaim = claimedSum;

        // Build Fiat-Shamir accumulator: matches Rust's Keccak256::new() + update() pattern.
        // Rust uses a running Keccak state: each .clone().finalize() hashes ALL accumulated data.
        // We simulate this by accumulating bytes and hashing the full buffer each time.
        bytes memory fsAccum = abi.encodePacked(
            "sumcheck-challenges",
            bytes(sessionName),
            _ext3ToLeBytes(zeta)
        );

        for (uint256 i = 0; i < numRounds; i++) {
            GoldilocksExt3.Ext3 memory g0 = roundPolys[i][0];
            GoldilocksExt3.Ext3 memory g1 = roundPolys[i][1];
            GoldilocksExt3.Ext3 memory g2 = roundPolys[i][2];

            // Check: g_i(0) + g_i(1) == currentClaim
            GoldilocksExt3.Ext3 memory sum01 = g0.add(g1);
            require(
                sum01.c0 == currentClaim.c0 &&
                sum01.c1 == currentClaim.c1 &&
                sum01.c2 == currentClaim.c2,
                "sumcheck: g(0)+g(1) != claim"
            );

            // Absorb round polynomial into accumulator (9 × u64 LE = 72 bytes)
            fsAccum = abi.encodePacked(
                fsAccum,
                _ext3ToLeBytes(g0),
                _ext3ToLeBytes(g1),
                _ext3ToLeBytes(g2)
            );

            // Derive challenge: hash full accumulator
            bytes32 h = keccak256(fsAccum);
            uint256 hVal = uint256(h);
            GoldilocksExt3.Ext3 memory r_i = GoldilocksExt3.Ext3({
                c0: uint64(_leU64(hVal >> 192) % GL_P),
                c1: uint64(_leU64(hVal >> 128) % GL_P),
                c2: uint64(_leU64(hVal >> 64) % GL_P)
            });
            evalPoint[i] = r_i;

            // Update claim: currentClaim = g_i(r_i) via degree-2 Lagrange interpolation
            currentClaim = _evalDegree2(g0, g1, g2, r_i);
        }

        finalClaim = currentClaim;
    }

    /// @notice Compute h_ζ(r) = Π_{j=0}^{n-1} (1 - r_j + r_j · ζ^{2^{n-1-j}})
    /// @dev Uses big-endian convention matching Rust's sumcheck.rs
    function computeHZeta(
        GoldilocksExt3.Ext3 memory zeta,
        GoldilocksExt3.Ext3[] memory evalPoint
    ) internal pure returns (GoldilocksExt3.Ext3 memory result) {
        uint256 n = evalPoint.length;
        result = GoldilocksExt3.one();

        // Precompute ζ^{2^k} for k = 0..n-1 via repeated squaring
        GoldilocksExt3.Ext3[] memory zetaPowers = new GoldilocksExt3.Ext3[](n);
        zetaPowers[0] = zeta;
        for (uint256 k = 1; k < n; k++) {
            zetaPowers[k] = zetaPowers[k - 1].square();
        }

        // result = Π (1 - r_j + r_j · ζ^{2^{n-1-j}})
        GoldilocksExt3.Ext3 memory oneExt = GoldilocksExt3.one();
        for (uint256 j = 0; j < n; j++) {
            // r[j] corresponds to bit position 2^{n-1-j} (big-endian)
            GoldilocksExt3.Ext3 memory zp = zetaPowers[n - 1 - j];
            // term = (1 - r_j) + r_j · zp = 1 + r_j · (zp - 1)
            GoldilocksExt3.Ext3 memory zpMinusOne = zp.sub(oneExt);
            GoldilocksExt3.Ext3 memory term = oneExt.add(evalPoint[j].mul(zpMinusOne));
            result = result.mul(term);
        }
    }

    /// @notice Verify the full bridge: sumcheck + h_ζ(r) · f(r) == finalClaim
    /// @param whirEvalAtR The WHIR-proven MLE evaluation f(r)
    function verifyBinding(
        GoldilocksExt3.Ext3 memory whirEvalAtR,
        GoldilocksExt3.Ext3 memory hZetaAtR,
        GoldilocksExt3.Ext3 memory finalClaim
    ) internal pure {
        // Check: f(r) · h_ζ(r) == finalClaim
        GoldilocksExt3.Ext3 memory product = whirEvalAtR.mul(hZetaAtR);
        require(
            product.c0 == finalClaim.c0 &&
            product.c1 == finalClaim.c1 &&
            product.c2 == finalClaim.c2,
            "sumcheck bridge: f(r)*h_zeta(r) != finalClaim"
        );
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// @dev Convert a big-endian uint64 (top 8 bytes of a shifted uint256) to little-endian value.
    ///      When Solidity extracts `uint64(h >> 192)`, the result is BE. Rust reads LE from bytes.
    ///      Example: hash bytes [0x01, 0x02, ..., 0x08] → Solidity uint64 = 0x0102030405060708 (BE)
    ///      Rust u64::from_le_bytes → 0x0807060504030201.
    function _leU64(uint256 beVal) private pure returns (uint256) {
        uint256 v = beVal & 0xFFFFFFFFFFFFFFFF;
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
        return v & 0xFFFFFFFFFFFFFFFF;
    }

    /// @dev Encode Ext3 as 24 little-endian bytes (3 × u64 LE).
    ///      Matches Rust: for each component, .into_bigint().0[0].to_le_bytes()
    function _ext3ToLeBytes(GoldilocksExt3.Ext3 memory e)
        private
        pure
        returns (bytes memory)
    {
        bytes memory out = new bytes(24);
        _writeU64LE(out, 0, e.c0);
        _writeU64LE(out, 8, e.c1);
        _writeU64LE(out, 16, e.c2);
        return out;
    }

    /// @dev Write a uint64 as 8 little-endian bytes into buf at offset.
    function _writeU64LE(bytes memory buf, uint256 offset, uint64 val) private pure {
        for (uint256 i = 0; i < 8; i++) {
            buf[offset + i] = bytes1(uint8(val & 0xFF));
            val >>= 8;
        }
    }


    /// @dev Evaluate degree-2 polynomial at point r via Lagrange interpolation on {0,1,2}.
    ///      g(r) = g(0)·L_0(r) + g(1)·L_1(r) + g(2)·L_2(r)
    ///      L_0(r) = (r-1)(r-2)/2, L_1(r) = -r(r-2), L_2(r) = r(r-1)/2
    function _evalDegree2(
        GoldilocksExt3.Ext3 memory g0,
        GoldilocksExt3.Ext3 memory g1,
        GoldilocksExt3.Ext3 memory g2,
        GoldilocksExt3.Ext3 memory r
    ) private pure returns (GoldilocksExt3.Ext3 memory) {
        GoldilocksExt3.Ext3 memory oneE = GoldilocksExt3.one();
        GoldilocksExt3.Ext3 memory twoE = GoldilocksExt3.Ext3({c0: 2, c1: 0, c2: 0});

        // inv2 = 2^{-1} mod GL_P
        // 2^{-1} mod (2^64 - 2^32 + 1) = (GL_P + 1) / 2 = 9223372034707292161
        GoldilocksExt3.Ext3 memory inv2E = GoldilocksExt3.Ext3({
            c0: 9223372034707292161,
            c1: 0,
            c2: 0
        });

        GoldilocksExt3.Ext3 memory rMinus1 = r.sub(oneE);
        GoldilocksExt3.Ext3 memory rMinus2 = r.sub(twoE);

        // L_0(r) = (r-1)(r-2) / 2
        GoldilocksExt3.Ext3 memory l0 = rMinus1.mul(rMinus2).mul(inv2E);
        // L_1(r) = -r(r-2)
        GoldilocksExt3.Ext3 memory l1 = r.mul(rMinus2).neg();
        // L_2(r) = r(r-1) / 2
        GoldilocksExt3.Ext3 memory l2 = r.mul(rMinus1).mul(inv2E);

        return g0.mul(l0).add(g1.mul(l1)).add(g2.mul(l2));
    }
}
