// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Plonky2Verifier} from "./Plonky2Verifier.sol";
import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {SumcheckBridgeVerifier} from "./spongefish/SumcheckBridgeVerifier.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";

/// @title WhirPlonky2Verifier — Unified on-chain verifier for WHIR-Plonky2 proofs
/// @notice Orchestrates all verification steps in a single entry point:
///   1. WHIR polynomial commitment verification
///   2. Sumcheck bridge #1 (zeta) + binding
///   3. Sumcheck bridge #2 (g*zeta) + binding
///   4. On-chain challenge derivation (from Merkle root)
///   5. Recomposition at zeta
///   6. Decomposition + sub-decomposition at g*zeta
///   7. Build verified Openings
///   8. Plonky2 constraint check
contract WhirPlonky2Verifier is Plonky2Verifier {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    // -----------------------------------------------------------------------
    // Unified proof data structures
    // -----------------------------------------------------------------------

    /// @dev Sumcheck bridge data for the zeta evaluation point.
    struct SumcheckBridgeData {
        GoldilocksExt3.Ext3[] evalPoint;
        GoldilocksExt3.Ext3 claimedSum;
        GoldilocksExt3.Ext3 zeta;
        string sessionName;
        GoldilocksExt3.Ext3[][] roundPolys;
    }

    /// @dev Sumcheck bridge data for gZeta (includes gZeta value).
    struct SumcheckBridgeGZetaData {
        GoldilocksExt3.Ext3[] evalPoint;
        GoldilocksExt3.Ext3 claimedSum;
        GoldilocksExt3.Ext3 gZeta;
        GoldilocksExt3.Ext3[][] roundPolys;
    }

    /// @dev Complete WHIR-Plonky2 proof.
    struct WhirPlonky2Proof {
        bytes protocolId;
        bytes sessionId;
        bytes instance;
        bytes transcript;
        bytes hints;
        GoldilocksExt3.Ext3[] evaluations;
        SumcheckBridgeData bridgeZeta;
        SumcheckBridgeGZetaData bridgeGZeta;
        uint256[][] allOpeningsAtZetaFlat;
        uint256[] batch2OpeningsAtGZetaFlat;
        uint256[] batchEvalsAtGZetaFlat;
        uint256[] publicInputs;
    }

    /// @dev Circuit configuration (static per circuit).
    struct CircuitConfig {
        uint256 degreeBits;
        uint256 numChallenges;
        uint256 numRoutedWires;
        uint256 quotientDegreeFactor;
        uint256 numPartialProducts;
        uint256 numGateConstraints;
        uint256 numSelectors;
        uint256 numLookupSelectors;
        uint256[] batchSizes;
        uint256[] intraBatchPolyCounts;
        GateInfo[] gates;
        PermutationData permutation;
        string sessionName;
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify a complete WHIR-Plonky2 proof in one call.
    function verify(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config,
        SpongefishWhirVerify.WhirParams memory whirParams
    ) public pure returns (bool) {
        // Step 1: WHIR polynomial commitment verification
        _verifyWhir(proof, whirParams);

        // Steps 2-3: Sumcheck bridges + binding
        _verifySumcheckBridges(proof);

        // Steps 4-6: Challenges, recomposition, decomposition
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ = _verifyChallengesAndDecomposition(proof, config);

        // Steps 7-8: Build openings + constraint check
        return _buildAndVerifyConstraints(proof, config, batch2PolyEvalsGZ);
    }

    // -----------------------------------------------------------------------
    // Step 1: WHIR verification
    // -----------------------------------------------------------------------

    function _verifyWhir(
        WhirPlonky2Proof memory proof,
        SpongefishWhirVerify.WhirParams memory whirParams
    ) internal pure {
        bool whirOk = SpongefishWhirVerify.verifyWhirProof(
            proof.protocolId,
            proof.sessionId,
            proof.instance,
            proof.transcript,
            proof.hints,
            proof.evaluations,
            whirParams
        );
        require(whirOk, "WHIR proof verification failed");
    }

    // -----------------------------------------------------------------------
    // Steps 2-3: Sumcheck bridges
    // -----------------------------------------------------------------------

    function _verifySumcheckBridges(WhirPlonky2Proof memory proof) internal pure {
        // Bridge #1 (zeta)
        {
            (
                GoldilocksExt3.Ext3[] memory evalPoint1,
                GoldilocksExt3.Ext3 memory finalClaim1
            ) = SumcheckBridgeVerifier.verify(
                proof.bridgeZeta.roundPolys.length,
                proof.bridgeZeta.roundPolys,
                proof.bridgeZeta.zeta,
                proof.bridgeZeta.claimedSum,
                proof.bridgeZeta.sessionName
            );
            GoldilocksExt3.Ext3 memory hZetaR1 = SumcheckBridgeVerifier.computeHZeta(
                proof.bridgeZeta.zeta, evalPoint1
            );
            SumcheckBridgeVerifier.verifyBinding(proof.evaluations[0], hZetaR1, finalClaim1);
        }

        // Bridge #2 (g*zeta)
        {
            (
                GoldilocksExt3.Ext3[] memory evalPoint2,
                GoldilocksExt3.Ext3 memory finalClaim2
            ) = SumcheckBridgeVerifier.verifyWithTag(
                proof.bridgeGZeta.roundPolys.length,
                proof.bridgeGZeta.roundPolys,
                proof.bridgeGZeta.gZeta,
                proof.bridgeGZeta.claimedSum,
                proof.bridgeZeta.sessionName,
                "sumcheck-challenges-gzeta"
            );
            GoldilocksExt3.Ext3 memory hGZetaR2 = SumcheckBridgeVerifier.computeHZeta(
                proof.bridgeGZeta.gZeta, evalPoint2
            );
            SumcheckBridgeVerifier.verifyBinding(proof.evaluations[1], hGZetaR2, finalClaim2);
        }
    }

    // -----------------------------------------------------------------------
    // Steps 4-6: Challenge derivation + decomposition
    // -----------------------------------------------------------------------

    function _verifyChallengesAndDecomposition(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config
    ) internal pure returns (GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ) {
        // Step 5: Recomposition at zeta
        _verifyRecomposition(proof, config);

        // Step 6: g*zeta decomposition
        batch2PolyEvalsGZ = _verifyGZetaDecomposition(proof, config);
    }

    function _verifyRecomposition(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config
    ) internal pure {
        uint256 polyDegree = 1 << config.degreeBits;
        GoldilocksExt3.Ext3[] memory allOpenings = _loadAllOpeningsFromFlat(
            proof.allOpeningsAtZetaFlat, config.intraBatchPolyCounts
        );
        SumcheckBridgeVerifier.verifyRecomposition(
            proof.bridgeZeta.claimedSum,
            config.batchSizes,
            config.intraBatchPolyCounts,
            polyDegree,
            proof.bridgeZeta.zeta,
            allOpenings
        );
    }

    function _verifyGZetaDecomposition(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config
    ) internal pure returns (GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ) {
        uint256 polyDegree = 1 << config.degreeBits;
        GoldilocksExt3.Ext3 memory gZetaExt3 = proof.bridgeGZeta.gZeta;

        // Inter-batch decomposition at g*zeta
        uint256 nb = config.batchSizes.length;
        GoldilocksExt3.Ext3[] memory batchEvalsGZ = new GoldilocksExt3.Ext3[](nb);
        for (uint256 i = 0; i < nb; i++) {
            batchEvalsGZ[i] = GoldilocksExt3.Ext3(
                uint64(proof.batchEvalsAtGZetaFlat[i * 3]),
                uint64(proof.batchEvalsAtGZetaFlat[i * 3 + 1]),
                uint64(proof.batchEvalsAtGZetaFlat[i * 3 + 2])
            );
        }
        SumcheckBridgeVerifier.verifyDecomposition(
            proof.bridgeGZeta.claimedSum, config.batchSizes, gZetaExt3, batchEvalsGZ
        );

        // Batch 2 sub-decomposition at g*zeta
        uint256 n2 = config.intraBatchPolyCounts[2];
        batch2PolyEvalsGZ = new GoldilocksExt3.Ext3[](n2);
        for (uint256 j = 0; j < n2; j++) {
            batch2PolyEvalsGZ[j] = GoldilocksExt3.Ext3(
                uint64(proof.batch2OpeningsAtGZetaFlat[j * 3]),
                uint64(proof.batch2OpeningsAtGZetaFlat[j * 3 + 1]),
                uint64(proof.batch2OpeningsAtGZetaFlat[j * 3 + 2])
            );
        }
        SumcheckBridgeVerifier.verifySubDecomposition(
            batchEvalsGZ[2], polyDegree, gZetaExt3, batch2PolyEvalsGZ
        );
    }

    // -----------------------------------------------------------------------
    // Steps 7-8: Build openings + constraint check
    // -----------------------------------------------------------------------

    function _buildAndVerifyConstraints(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config,
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ
    ) internal pure returns (bool) {
        // Derive challenges on-chain
        (
            uint256[] memory betas,
            uint256[] memory gammas,
            uint256[] memory alphas,
            uint256 zetaC0,
            uint256 zetaC1,
            uint256 zetaC2
        ) = SumcheckBridgeVerifier.deriveKeccakChallengesV2(
            proof.transcript,
            bytes(config.sessionName),
            proof.publicInputs,
            config.numChallenges
        );

        // Build openings
        Openings memory openings = _buildOpenings(proof, config, batch2PolyEvalsGZ);

        // Build challenges struct
        Challenges memory chal;
        chal.plonkBetas = betas;
        chal.plonkGammas = gammas;
        chal.plonkAlphas = alphas;
        chal.plonkZeta = GoldilocksExt3.Ext3(uint64(zetaC0), uint64(zetaC1), uint64(zetaC2));

        // Build circuit params
        CircuitParams memory params;
        params.degreeBits = config.degreeBits;
        params.numChallenges = config.numChallenges;
        params.numRoutedWires = config.numRoutedWires;
        params.quotientDegreeFactor = config.quotientDegreeFactor;
        params.numPartialProducts = config.numPartialProducts;
        params.numGateConstraints = config.numGateConstraints;
        params.numSelectors = config.numSelectors;
        params.numLookupSelectors = config.numLookupSelectors;

        return verifyConstraints(
            openings, params, chal, config.permutation, config.gates, proof.publicInputs
        );
    }

    function _buildOpenings(
        WhirPlonky2Proof memory proof,
        CircuitConfig memory config,
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ
    ) internal pure returns (Openings memory openings) {
        uint256 numChallenges = config.numChallenges;
        uint256 numPartialProducts = config.numPartialProducts;

        GoldilocksExt3.Ext3[] memory b0evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[0], config.intraBatchPolyCounts[0]);
        GoldilocksExt3.Ext3[] memory b1evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[1], config.intraBatchPolyCounts[1]);
        GoldilocksExt3.Ext3[] memory b2evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[2], config.intraBatchPolyCounts[2]);
        GoldilocksExt3.Ext3[] memory b3evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[3], config.intraBatchPolyCounts[3]);

        // batch 0: constants then plonkSigmas
        {
            uint256 numSigmaPolys = config.numRoutedWires;
            uint256 numConstantEntries = config.intraBatchPolyCounts[0] - numSigmaPolys;
            openings.constants = new GoldilocksExt3.Ext3[](numConstantEntries);
            for (uint256 i = 0; i < numConstantEntries; i++) {
                openings.constants[i] = b0evals[i];
            }
            openings.plonkSigmas = new GoldilocksExt3.Ext3[](numSigmaPolys);
            for (uint256 i = 0; i < numSigmaPolys; i++) {
                openings.plonkSigmas[i] = b0evals[numConstantEntries + i];
            }
        }

        // batch 1: wires
        openings.wires = new GoldilocksExt3.Ext3[](config.intraBatchPolyCounts[1]);
        for (uint256 i = 0; i < config.intraBatchPolyCounts[1]; i++) {
            openings.wires[i] = b1evals[i];
        }

        // batch 2: [Z, partialProducts...] per challenge + Z(g*zeta) from batch2PolyEvalsGZ
        {
            uint256 stride = 1 + numPartialProducts;
            openings.plonkZs = new GoldilocksExt3.Ext3[](numChallenges);
            openings.partialProducts = new GoldilocksExt3.Ext3[](numChallenges * numPartialProducts);
            openings.plonkZsNext = new GoldilocksExt3.Ext3[](numChallenges);
            for (uint256 ch = 0; ch < numChallenges; ch++) {
                openings.plonkZs[ch] = b2evals[ch * stride];
                for (uint256 pp = 0; pp < numPartialProducts; pp++) {
                    openings.partialProducts[ch * numPartialProducts + pp] = b2evals[ch * stride + 1 + pp];
                }
                openings.plonkZsNext[ch] = batch2PolyEvalsGZ[ch * stride];
            }
        }

        // batch 3: quotient chunks
        openings.quotientPolys = new GoldilocksExt3.Ext3[](config.intraBatchPolyCounts[3]);
        for (uint256 i = 0; i < config.intraBatchPolyCounts[3]; i++) {
            openings.quotientPolys[i] = b3evals[i];
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// @dev Convert flat uint256[] [c0,c1,c2,c0,c1,c2,...] to Ext3 array.
    function _flatToExt3Array(uint256[] memory flat, uint256 count)
        internal pure returns (GoldilocksExt3.Ext3[] memory result)
    {
        result = new GoldilocksExt3.Ext3[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = GoldilocksExt3.Ext3(
                uint64(flat[i * 3]),
                uint64(flat[i * 3 + 1]),
                uint64(flat[i * 3 + 2])
            );
        }
    }

    /// @dev Load all individual polynomial openings from flat per-batch arrays.
    function _loadAllOpeningsFromFlat(
        uint256[][] memory flatBatches,
        uint256[] memory polyCounts
    ) internal pure returns (GoldilocksExt3.Ext3[] memory allOpenings) {
        uint256 total = 0;
        for (uint256 b = 0; b < polyCounts.length; b++) total += polyCounts[b];
        allOpenings = new GoldilocksExt3.Ext3[](total);
        uint256 idx = 0;
        for (uint256 b = 0; b < polyCounts.length; b++) {
            uint256[] memory flat = flatBatches[b];
            for (uint256 j = 0; j < polyCounts[b]; j++) {
                allOpenings[idx++] = GoldilocksExt3.Ext3(
                    uint64(flat[j * 3]),
                    uint64(flat[j * 3 + 1]),
                    uint64(flat[j * 3 + 2])
                );
            }
        }
    }
}
