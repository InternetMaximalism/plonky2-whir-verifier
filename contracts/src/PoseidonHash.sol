// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonConstants.sol";

/// @title PoseidonHash — Poseidon sponge hash in base Goldilocks field
/// @dev Implements hash_no_pad as used by Plonky2 to hash public inputs.
///      Parameters: WIDTH=12, RATE=8, CAPACITY=4, HALF_N_FULL=4, N_PARTIAL=22
///      S-box: x^7 over GoldilocksField (p = 2^64 - 2^32 + 1)
library PoseidonHash {
    uint256 constant P = GoldilocksField.P;
    uint256 constant WIDTH = 12;
    uint256 constant RATE = 8;
    uint256 constant HALF_N_FULL = 4;
    uint256 constant N_PARTIAL = 22;

    /// @notice Poseidon hash_no_pad: hash arbitrary-length input to 4 field elements.
    /// @dev Sponge construction: absorb RATE elements per permutation call, squeeze 4.
    function hashNoPad(uint256[] memory inputs) internal pure returns (uint256[4] memory out) {
        uint256[WIDTH] memory state;
        // state initialized to zeros (default)

        uint256 len = inputs.length;
        uint256 offset = 0;
        while (offset < len) {
            uint256 chunkLen = len - offset;
            if (chunkLen > RATE) chunkLen = RATE;
            for (uint256 i = 0; i < chunkLen; i++) {
                state[i] = addmod(state[i], inputs[offset + i], P);
            }
            state = _permute(state);
            offset += RATE;
        }

        // If len == 0, apply one permutation on zero state
        if (len == 0) {
            state = _permute(state);
        }

        out[0] = state[0];
        out[1] = state[1];
        out[2] = state[2];
        out[3] = state[3];
    }

    /// @dev Full Poseidon permutation over 12 base field elements.
    function _permute(uint256[WIDTH] memory state) private pure returns (uint256[WIDTH] memory) {
        uint256 roundCtr = 0;

        // ---- First half full rounds (4 rounds) ----
        for (uint256 round = 0; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            _sboxLayer(state);
            state = _mdsLayer(state);
            roundCtr++;
        }

        // ---- Partial rounds (22 rounds, fast variant) ----
        // Add fastPartialFirstRoundConstant
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = addmod(state[i], PoseidonConstants.fastPartialFirstRoundConstant(i), P);
        }
        state = _mdsPartialLayerInit(state);

        for (uint256 r = 0; r < N_PARTIAL; r++) {
            state[0] = _sbox(state[0]);
            if (r < N_PARTIAL - 1) {
                state[0] = addmod(state[0], PoseidonConstants.fastPartialRoundConstant(r), P);
            }
            state = _mdsPartialLayerFast(state, r);
        }
        roundCtr += N_PARTIAL;

        // ---- Second half full rounds (4 rounds) ----
        for (uint256 round = 0; round < HALF_N_FULL; round++) {
            _constantLayer(state, roundCtr);
            _sboxLayer(state);
            state = _mdsLayer(state);
            roundCtr++;
        }

        return state;
    }

    /// @dev S-box: x^7 in base Goldilocks field
    function _sbox(uint256 x) private pure returns (uint256) {
        uint256 x2 = mulmod(x, x, P);
        uint256 x3 = mulmod(x, x2, P);
        uint256 x4 = mulmod(x2, x2, P);
        return mulmod(x3, x4, P);
    }

    /// @dev Add round constants to state
    function _constantLayer(uint256[WIDTH] memory state, uint256 roundCtr) private pure {
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = addmod(state[i], PoseidonConstants.roundConstant(i + WIDTH * roundCtr), P);
        }
    }

    /// @dev Apply S-box to all 12 state elements
    function _sboxLayer(uint256[WIDTH] memory state) private pure {
        for (uint256 i = 0; i < WIDTH; i++) {
            state[i] = _sbox(state[i]);
        }
    }

    /// @dev Full MDS layer: circulant matrix + diagonal
    function _mdsLayer(uint256[WIDTH] memory state) private pure returns (uint256[WIDTH] memory result) {
        for (uint256 r = 0; r < WIDTH; r++) {
            uint256 acc = 0;
            for (uint256 i = 0; i < WIDTH; i++) {
                uint256 idx = (i + r) % WIDTH;
                acc = addmod(acc, mulmod(state[idx], PoseidonConstants.mdsCirc(i), P), P);
            }
            acc = addmod(acc, mulmod(state[r], PoseidonConstants.mdsDiag(r), P), P);
            result[r] = acc;
        }
    }

    /// @dev Initial partial round MDS matrix (applied once before partial rounds)
    function _mdsPartialLayerInit(uint256[WIDTH] memory state) private pure returns (uint256[WIDTH] memory result) {
        result[0] = state[0];
        for (uint256 c = 1; c < WIDTH; c++) {
            uint256 acc = 0;
            for (uint256 r = 1; r < WIDTH; r++) {
                acc = addmod(acc, mulmod(state[r], PoseidonConstants.initialMatrix(r - 1, c - 1), P), P);
            }
            result[c] = acc;
        }
    }

    /// @dev Fast partial MDS layer (applied each partial round)
    function _mdsPartialLayerFast(uint256[WIDTH] memory state, uint256 r)
        private pure returns (uint256[WIDTH] memory result)
    {
        // M_00 = mdsCirc(0) + mdsDiag(0)
        uint256 m00 = addmod(PoseidonConstants.mdsCirc(0), PoseidonConstants.mdsDiag(0), P);
        uint256 d = mulmod(state[0], m00, P);
        for (uint256 i = 1; i < WIDTH; i++) {
            d = addmod(d, mulmod(state[i], PoseidonConstants.wHat(r, i - 1), P), P);
        }
        result[0] = d;
        for (uint256 i = 1; i < WIDTH; i++) {
            result[i] = addmod(mulmod(state[0], PoseidonConstants.vs(r, i - 1), P), state[i], P);
        }
    }
}
