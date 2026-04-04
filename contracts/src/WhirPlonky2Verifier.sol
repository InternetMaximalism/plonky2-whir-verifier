// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Plonky2Verifier} from "./Plonky2Verifier.sol";
import {SpongefishWhirVerify} from "./spongefish/SpongefishWhirVerify.sol";
import {SumcheckBridgeVerifier} from "./spongefish/SumcheckBridgeVerifier.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";

/// @title WhirPlonky2Verifier — On-chain verifier with immutable verifying key
/// @notice The verifying key (circuit config + WHIR params) is set once at deployment
///         and cannot be changed. Only proofs are submitted for verification.
///
///         This ensures a deployed verifier is permanently bound to a specific circuit.
///         To verify a different circuit, deploy a new contract.
contract WhirPlonky2Verifier is Plonky2Verifier {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    // -----------------------------------------------------------------------
    // Proof data structures (submitted per-verification)
    // -----------------------------------------------------------------------

    struct SumcheckBridgeData {
        GoldilocksExt3.Ext3[] evalPoint;
        GoldilocksExt3.Ext3 claimedSum;
        GoldilocksExt3.Ext3 zeta;
        GoldilocksExt3.Ext3[][] roundPolys;
    }

    struct SumcheckBridgeGZetaData {
        GoldilocksExt3.Ext3[] evalPoint;
        GoldilocksExt3.Ext3 claimedSum;
        GoldilocksExt3.Ext3 gZeta;
        GoldilocksExt3.Ext3[][] roundPolys;
    }

    /// @dev Proof data — changes every verification. Does NOT contain verifying key data.
    struct Proof {
        bytes transcript;
        bytes hints;
        GoldilocksExt3.Ext3[] evaluations;
        SumcheckBridgeData bridgeZeta;
        SumcheckBridgeGZetaData bridgeGZeta;
        uint256[][] allOpeningsAtZetaFlat;   // per-batch flat [c0,c1,c2,...] arrays
        uint256[] batch2OpeningsAtGZetaFlat;
        uint256[] batchEvalsAtGZetaFlat;
        uint256[] publicInputs;
    }

    // -----------------------------------------------------------------------
    // Verifying key (immutable, set at deployment)
    // -----------------------------------------------------------------------

    /// @dev Circuit configuration — part of verifying key.
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

    /// @dev The complete verifying key hash — used for integrity check.
    bytes32 public immutable vkHash;

    /// @dev Stored verifying key components.
    ///      These are stored in contract storage at deployment and never modified.
    CircuitConfig internal _circuitConfig;
    SpongefishWhirVerify.WhirParams internal _whirParams;
    bytes internal _protocolId;
    bytes internal _sessionId;
    bytes internal _instance;

    /// @dev Whether the verifying key has been initialized.
    bool internal _initialized;

    // -----------------------------------------------------------------------
    // Constructor — sets the verifying key permanently
    // -----------------------------------------------------------------------

    constructor() {
        // Default constructor — VK must be set via initialize().
        // This pattern allows the VK to contain dynamic arrays (gates, etc.)
        // which can't be passed as constructor args easily with foundry.
    }

    /// @notice Initialize the verifying key. Can only be called ONCE.
    ///         After initialization, the VK is permanently frozen.
    function initialize(
        CircuitConfig memory config,
        SpongefishWhirVerify.WhirParams memory whirParams,
        bytes memory protocolId,
        bytes memory sessionId,
        bytes memory instance
    ) external {
        require(!_initialized, "VK already initialized");
        _initialized = true;

        // Store circuit config
        _circuitConfig.degreeBits = config.degreeBits;
        _circuitConfig.numChallenges = config.numChallenges;
        _circuitConfig.numRoutedWires = config.numRoutedWires;
        _circuitConfig.quotientDegreeFactor = config.quotientDegreeFactor;
        _circuitConfig.numPartialProducts = config.numPartialProducts;
        _circuitConfig.numGateConstraints = config.numGateConstraints;
        _circuitConfig.numSelectors = config.numSelectors;
        _circuitConfig.numLookupSelectors = config.numLookupSelectors;
        _circuitConfig.sessionName = config.sessionName;

        // Copy dynamic arrays
        for (uint256 i = 0; i < config.batchSizes.length; i++) {
            _circuitConfig.batchSizes.push(config.batchSizes[i]);
        }
        for (uint256 i = 0; i < config.intraBatchPolyCounts.length; i++) {
            _circuitConfig.intraBatchPolyCounts.push(config.intraBatchPolyCounts[i]);
        }
        for (uint256 i = 0; i < config.gates.length; i++) {
            _circuitConfig.gates.push(config.gates[i]);
        }
        for (uint256 i = 0; i < config.permutation.kIs.length; i++) {
            _circuitConfig.permutation.kIs.push(config.permutation.kIs[i]);
        }

        // Store WHIR params
        _storeWhirParams(whirParams);

        // Store WHIR identifiers (derived from WHIR params, part of VK)
        _protocolId = protocolId;
        _sessionId = sessionId;
        _instance = instance;
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify a proof against the stored verifying key.
    ///         The verifying key was set at deployment and cannot be changed.
    /// @param proof The proof data (changes per verification)
    /// @return true if the proof is valid
    function verify(Proof memory proof) public view returns (bool) {
        require(_initialized, "VK not initialized");

        // Load VK from storage into memory for efficient access
        CircuitConfig memory config = _loadCircuitConfig();
        SpongefishWhirVerify.WhirParams memory whirParams = _loadWhirParams();

        // Set per-proof evaluation points in whirParams
        // (these are sumcheck-derived and change per proof)
        whirParams.evaluationPoint = proof.bridgeZeta.evalPoint;
        whirParams.evaluationPoint2 = proof.bridgeGZeta.evalPoint;

        // Step 1: WHIR polynomial commitment verification
        _verifyWhir(proof, whirParams);

        // Steps 2-3: Sumcheck bridges + binding
        _verifySumcheckBridges(proof, config.sessionName);

        // Steps 4-6: Challenges, recomposition, decomposition
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ = _verifyChallengesAndDecomposition(proof, config);

        // Steps 7-8: Build openings + constraint check
        return _buildAndVerifyConstraints(proof, config, batch2PolyEvalsGZ);
    }

    // -----------------------------------------------------------------------
    // Step 1: WHIR verification
    // -----------------------------------------------------------------------

    function _verifyWhir(
        Proof memory proof,
        SpongefishWhirVerify.WhirParams memory whirParams
    ) internal view {
        bool whirOk = SpongefishWhirVerify.verifyWhirProof(
            _protocolId,    // from VK (immutable)
            _sessionId,     // from VK (immutable)
            _instance,      // from VK (immutable)
            proof.transcript,
            proof.hints,
            proof.evaluations,
            whirParams      // from VK (immutable)
        );
        require(whirOk, "WHIR proof verification failed");
    }

    // -----------------------------------------------------------------------
    // Steps 2-3: Sumcheck bridges
    // -----------------------------------------------------------------------

    function _verifySumcheckBridges(Proof memory proof, string memory sessionName) internal pure {
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
                sessionName    // from VK
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
                sessionName,   // from VK
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
        Proof memory proof,
        CircuitConfig memory config
    ) internal pure returns (GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ) {
        _verifyRecomposition(proof, config);
        batch2PolyEvalsGZ = _verifyGZetaDecomposition(proof, config);
    }

    function _verifyRecomposition(
        Proof memory proof,
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
        Proof memory proof,
        CircuitConfig memory config
    ) internal pure returns (GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ) {
        uint256 polyDegree = 1 << config.degreeBits;
        GoldilocksExt3.Ext3 memory gZetaExt3 = proof.bridgeGZeta.gZeta;

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
        Proof memory proof,
        CircuitConfig memory config,
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ
    ) internal pure returns (bool) {
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

        // CRITICAL: verify on-chain derived ζ == sumcheck bridge ζ.
        // Without this check, a prover could submit openings verified at bridge ζ
        // while using different challenges (from tampered inputs) at a different ζ'.
        require(
            zetaC0 == uint256(proof.bridgeZeta.zeta.c0) &&
            zetaC1 == uint256(proof.bridgeZeta.zeta.c1) &&
            zetaC2 == uint256(proof.bridgeZeta.zeta.c2),
            "zeta mismatch: derived != bridge"
        );

        Openings memory openings = _buildOpenings(proof, config, batch2PolyEvalsGZ);

        Challenges memory chal;
        chal.plonkBetas = betas;
        chal.plonkGammas = gammas;
        chal.plonkAlphas = alphas;
        chal.plonkZeta = GoldilocksExt3.Ext3(uint64(zetaC0), uint64(zetaC1), uint64(zetaC2));

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
        Proof memory proof,
        CircuitConfig memory config,
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ
    ) internal pure returns (Openings memory openings) {
        uint256 numChallenges = config.numChallenges;
        uint256 numPartialProducts = config.numPartialProducts;

        GoldilocksExt3.Ext3[] memory b0evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[0], config.intraBatchPolyCounts[0]);
        GoldilocksExt3.Ext3[] memory b1evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[1], config.intraBatchPolyCounts[1]);
        GoldilocksExt3.Ext3[] memory b2evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[2], config.intraBatchPolyCounts[2]);
        GoldilocksExt3.Ext3[] memory b3evals = _flatToExt3Array(proof.allOpeningsAtZetaFlat[3], config.intraBatchPolyCounts[3]);

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

        openings.wires = new GoldilocksExt3.Ext3[](config.intraBatchPolyCounts[1]);
        for (uint256 i = 0; i < config.intraBatchPolyCounts[1]; i++) {
            openings.wires[i] = b1evals[i];
        }

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

        openings.quotientPolys = new GoldilocksExt3.Ext3[](config.intraBatchPolyCounts[3]);
        for (uint256 i = 0; i < config.intraBatchPolyCounts[3]; i++) {
            openings.quotientPolys[i] = b3evals[i];
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // VK storage helpers
    // -----------------------------------------------------------------------

    function _loadCircuitConfig() internal view returns (CircuitConfig memory config) {
        config.degreeBits = _circuitConfig.degreeBits;
        config.numChallenges = _circuitConfig.numChallenges;
        config.numRoutedWires = _circuitConfig.numRoutedWires;
        config.quotientDegreeFactor = _circuitConfig.quotientDegreeFactor;
        config.numPartialProducts = _circuitConfig.numPartialProducts;
        config.numGateConstraints = _circuitConfig.numGateConstraints;
        config.numSelectors = _circuitConfig.numSelectors;
        config.numLookupSelectors = _circuitConfig.numLookupSelectors;
        config.batchSizes = _circuitConfig.batchSizes;
        config.intraBatchPolyCounts = _circuitConfig.intraBatchPolyCounts;
        config.gates = _circuitConfig.gates;
        config.permutation = _circuitConfig.permutation;
        config.sessionName = _circuitConfig.sessionName;
    }

    function _storeWhirParams(SpongefishWhirVerify.WhirParams memory p) internal {
        _whirParams.numVariables = p.numVariables;
        _whirParams.foldingFactor = p.foldingFactor;
        _whirParams.numVectors = p.numVectors;
        _whirParams.outDomainSamples = p.outDomainSamples;
        _whirParams.inDomainSamples = p.inDomainSamples;
        _whirParams.initialSumcheckRounds = p.initialSumcheckRounds;
        _whirParams.numRounds = p.numRounds;
        _whirParams.finalSumcheckRounds = p.finalSumcheckRounds;
        _whirParams.finalSize = p.finalSize;
        _whirParams.initialCodewordLength = p.initialCodewordLength;
        _whirParams.initialMerkleDepth = p.initialMerkleDepth;
        _whirParams.initialDomainGenerator = p.initialDomainGenerator;
        _whirParams.initialInterleavingDepth = p.initialInterleavingDepth;
        _whirParams.initialNumVariables = p.initialNumVariables;
        _whirParams.initialCosetSize = p.initialCosetSize;
        _whirParams.initialNumCosets = p.initialNumCosets;
        for (uint256 i = 0; i < p.evaluationPoint.length; i++) {
            _whirParams.evaluationPoint.push(p.evaluationPoint[i]);
        }
        for (uint256 i = 0; i < p.evaluationPoint2.length; i++) {
            _whirParams.evaluationPoint2.push(p.evaluationPoint2[i]);
        }
        for (uint256 i = 0; i < p.rounds.length; i++) {
            _whirParams.rounds.push(p.rounds[i]);
        }
    }

    function _loadWhirParams() internal view returns (SpongefishWhirVerify.WhirParams memory p) {
        p.numVariables = _whirParams.numVariables;
        p.foldingFactor = _whirParams.foldingFactor;
        p.numVectors = _whirParams.numVectors;
        p.outDomainSamples = _whirParams.outDomainSamples;
        p.inDomainSamples = _whirParams.inDomainSamples;
        p.initialSumcheckRounds = _whirParams.initialSumcheckRounds;
        p.numRounds = _whirParams.numRounds;
        p.finalSumcheckRounds = _whirParams.finalSumcheckRounds;
        p.finalSize = _whirParams.finalSize;
        p.initialCodewordLength = _whirParams.initialCodewordLength;
        p.initialMerkleDepth = _whirParams.initialMerkleDepth;
        p.initialDomainGenerator = _whirParams.initialDomainGenerator;
        p.initialInterleavingDepth = _whirParams.initialInterleavingDepth;
        p.initialNumVariables = _whirParams.initialNumVariables;
        p.initialCosetSize = _whirParams.initialCosetSize;
        p.initialNumCosets = _whirParams.initialNumCosets;
        p.evaluationPoint = _whirParams.evaluationPoint;
        p.evaluationPoint2 = _whirParams.evaluationPoint2;
        p.rounds = _whirParams.rounds;
    }
}
