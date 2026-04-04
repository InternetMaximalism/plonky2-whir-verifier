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
        uint256[] batch0Coefficients;   // constants_sigmas polynomial coefficients (u64 values)
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
        bytes32 constantsSigmasHash;    // keccak256 of batch 0 coefficients (LE u64 bytes)
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
        _circuitConfig.constantsSigmasHash = config.constantsSigmasHash;

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

        // Step 4: Verify batch 0 (constants_sigmas) commitment
        _verifyBatch0Commitment(proof, config);

        // Steps 5-7: Challenges, recomposition, decomposition
        GoldilocksExt3.Ext3[] memory batch2PolyEvalsGZ = _verifyChallengesAndDecomposition(proof, config);

        // Steps 8-9: Build openings + constraint check
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
    // Step 4: Batch 0 (constants_sigmas) commitment verification
    // -----------------------------------------------------------------------

    /// @notice Verify that batch 0 coefficients match the VK commitment and
    ///         that the claimed openings at ζ are correct evaluations.
    ///         Uses Yul assembly for LE byte packing and Horner evaluation.
    function _verifyBatch0Commitment(
        Proof memory proof,
        CircuitConfig memory config
    ) internal pure {
        uint256[] memory coeffs = proof.batch0Coefficients;
        uint256 numCoeffs = coeffs.length;

        // Part 1: Hash verification — pack as LE u64 bytes and keccak256
        bytes32 computedHash;
        assembly ("memory-safe") {
            // Allocate scratch buffer for LE-packed bytes (numCoeffs * 8)
            let byteLen := mul(numCoeffs, 8)
            let buf := mload(0x40)
            mstore(0x40, add(buf, byteLen))

            let coeffData := add(coeffs, 0x20) // skip array length
            for { let i := 0 } lt(i, numCoeffs) { i := add(i, 1) } {
                let val := and(mload(add(coeffData, mul(i, 0x20))), 0xFFFFFFFFFFFFFFFF)
                // Byte-swap u64 from native (BE in EVM word) to LE
                // Swap bytes within 16-bit pairs
                val := or(and(shr(8, val), 0x00FF00FF00FF00FF), and(shl(8, val), 0xFF00FF00FF00FF00))
                // Swap 16-bit pairs within 32-bit groups
                val := or(and(shr(16, val), 0x0000FFFF0000FFFF), and(shl(16, val), 0xFFFF0000FFFF0000))
                // Swap 32-bit halves
                val := or(shr(32, val), shl(32, val))
                val := and(val, 0xFFFFFFFFFFFFFFFF)

                // Store 8 bytes at buf + i*8 (left-aligned in 32-byte word)
                mstore(add(buf, mul(i, 8)), shl(192, val))
            }

            computedHash := keccak256(buf, byteLen)
        }
        require(computedHash == config.constantsSigmasHash, "batch0: coefficients hash mismatch");

        // Part 2: Horner evaluation of each polynomial at ζ, compare with claimed openings.
        // Coefficients are base field (u64), ζ is Ext3.
        // Horner: eval = 0; for k = degree-1 downto 0: eval = eval * ζ + c_k
        //   - eval * ζ is Ext3 × Ext3 multiplication (9 mulmod)
        //   - + c_k only touches c0 component (addmod on c0 only)
        uint256 degree = 1 << config.degreeBits;
        uint256 numPolys = config.intraBatchPolyCounts[0];
        GoldilocksExt3.Ext3 memory zeta = proof.bridgeZeta.zeta;
        uint256[] memory flat0 = proof.allOpeningsAtZetaFlat[0];

        assembly ("memory-safe") {
            let p := 0xFFFFFFFF00000001
            let z0 := mload(zeta)
            let z1 := mload(add(zeta, 0x20))
            let z2 := mload(add(zeta, 0x40))

            let coeffData := add(coeffs, 0x20)    // skip array length
            let flatData := add(flat0, 0x20)       // skip array length

            for { let poly := 0 } lt(poly, numPolys) { poly := add(poly, 1) } {
                let baseIdx := mul(poly, degree)

                // Horner: r = c_{degree-1}
                let r0 := and(mload(add(coeffData, mul(add(baseIdx, sub(degree, 1)), 0x20))), 0xFFFFFFFFFFFFFFFF)
                let r1 := 0
                let r2 := 0

                // Horner loop: k from degree-2 downto 0
                for { let k := sub(degree, 1) } gt(k, 0) {} {
                    k := sub(k, 1)

                    // r = r * ζ (Ext3 × Ext3)
                    // c0' = r0*z0 + 2*(r1*z2 + r2*z1)
                    // c1' = r0*z1 + r1*z0 + 2*r2*z2
                    // c2' = r0*z2 + r1*z1 + r2*z0
                    let a0 := r0  let a1 := r1  let a2 := r2
                    let cross := addmod(mulmod(a1, z2, p), mulmod(a2, z1, p), p)
                    r0 := addmod(mulmod(a0, z0, p), mulmod(2, cross, p), p)
                    let t2 := addmod(mulmod(a0, z1, p), mulmod(a1, z0, p), p)
                    r1 := addmod(t2, mulmod(2, mulmod(a2, z2, p), p), p)
                    r2 := addmod(addmod(mulmod(a0, z2, p), mulmod(a1, z1, p), p), mulmod(a2, z0, p), p)

                    // r.c0 += c_k (base field coefficient — only affects c0)
                    let ck := and(mload(add(coeffData, mul(add(baseIdx, k), 0x20))), 0xFFFFFFFFFFFFFFFF)
                    r0 := addmod(r0, ck, p)
                }

                // Compare with claimed opening: flat0[poly*3], flat0[poly*3+1], flat0[poly*3+2]
                let fIdx := mul(poly, 3)
                let e0 := mload(add(flatData, mul(fIdx, 0x20)))
                let e1 := mload(add(flatData, mul(add(fIdx, 1), 0x20)))
                let e2 := mload(add(flatData, mul(add(fIdx, 2), 0x20)))

                if or(or(iszero(eq(r0, e0)), iszero(eq(r1, e1))), iszero(eq(r2, e2))) {
                    // revert with "batch0: opening mismatch at polynomial"
                    mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, 0x20)
                    mstore(0x24, 35) // length of message
                    mstore(0x44, "batch0: opening mismatch at poly")
                    mstore(0x64, "nomial")
                    revert(0x00, 0x84)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Steps 5-7: Challenge derivation + decomposition
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
        config.constantsSigmasHash = _circuitConfig.constantsSigmasHash;
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
