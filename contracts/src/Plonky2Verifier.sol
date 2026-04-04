// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonGateEval.sol";
import "./PoseidonConstants.sol";
import "./spongefish/GoldilocksExt3.sol";

/// @title Plonky2Verifier — On-chain Plonky2 constraint satisfaction check
/// @dev Verifies that polynomial openings at challenge point ζ satisfy
///      the Plonky2 circuit constraints. Combined with WHIR polynomial
///      commitment proofs, this provides a complete post-quantum validity proof.
///
///      The verification equation is:
///        vanishing(ζ)[i] == Z_H(ζ) · reduce_with_powers(quotient_chunks[i], ζ^n)
///
///      where vanishing(ζ) = boundary_terms + permutation_terms + gate_constraints
///      combined via alpha challenges (Horner reduction).
///
///      Gate constraints are evaluated using selector filters:
///        for each gate type: filter(gate) * gate.eval_unfiltered(wires, constants)
///      where filter is a polynomial that is nonzero only when the gate is active.
contract Plonky2Verifier {
    using GoldilocksField for uint256;
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    /// @dev Interpolation state: (eval, prod) as circuit Ext2 pairs
    struct InterpState {
        GoldilocksExt3.Ext3 eval0;
        GoldilocksExt3.Ext3 eval1;
        GoldilocksExt3.Ext3 prod0;
        GoldilocksExt3.Ext3 prod1;
    }

    uint256 constant GL_P = GoldilocksField.P;
    /// @dev Unused selector sentinel value (matches Plonky2's UNUSED_SELECTOR)
    uint256 constant UNUSED_SELECTOR = 0xFFFFFFFF;

    // -----------------------------------------------------------------------
    // Data structures matching Plonky2's OpeningSet
    // -----------------------------------------------------------------------

    /// @dev Opening values at challenge point ζ (and g·ζ for next-row values).
    struct Openings {
        GoldilocksExt3.Ext3[] constants;         // constants(ζ) [includes selectors]
        GoldilocksExt3.Ext3[] plonkSigmas;       // σ(ζ)
        GoldilocksExt3.Ext3[] wires;             // w(ζ)
        GoldilocksExt3.Ext3[] plonkZs;           // Z(ζ)
        GoldilocksExt3.Ext3[] plonkZsNext;       // Z(g·ζ)
        GoldilocksExt3.Ext3[] partialProducts;   // P(ζ)
        GoldilocksExt3.Ext3[] quotientPolys;     // t(ζ)
    }

    /// @dev Circuit-specific parameters.
    struct CircuitParams {
        uint256 degreeBits;
        uint256 numChallenges;
        uint256 numRoutedWires;
        uint256 quotientDegreeFactor;
        uint256 numPartialProducts;
        uint256 numGateConstraints;     // MAX of gate constraints (not sum)
        uint256 numSelectors;           // number of selector columns
        uint256 numLookupSelectors;     // number of lookup selector columns
    }

    /// @dev Fiat-Shamir challenges.
    struct Challenges {
        uint256[] plonkBetas;
        uint256[] plonkGammas;
        uint256[] plonkAlphas;
        GoldilocksExt3.Ext3 plonkZeta;
    }

    /// @dev Permutation coset shift constants.
    struct PermutationData {
        uint256[] kIs;
    }

    /// @dev Gate descriptor for selector-based constraint evaluation.
    struct GateInfo {
        uint256 gateType;          // enum: 0=Noop, 1=Constant, 2=PublicInput, 3=Poseidon, 4=Arithmetic, ...
        uint256 selectorIndex;     // which selector column to read
        uint256 groupStart;        // start of this gate's group range
        uint256 groupEnd;          // end (exclusive) of group range
        uint256 rowInGroup;        // this gate's position within the group
        uint256 numConstraints;    // number of constraints this gate produces
        // Gate-specific configuration (packed into a single array for gas efficiency)
        // Interpretation depends on gateType:
        //   Constant(1): [numConsts]
        //   Arithmetic(4): [numOps]
        //   BaseSumGate(5): [numLimbs, base]
        //   RandomAccessGate(6): [bits, numCopies, numExtraConstants, vecSize]
        //   ReducingExtensionGate(8): [numCoeffs]
        //   ArithmeticExtensionGate(9): [numOps]
        //   MulExtensionGate(10): [numOps]
        //   ExponentiationGate(11): [numPowerBits]
        //   CosetInterpolationGate(12): [subgroupBits, numPoints, numIntermediates, degree]
        uint256[] gateConfig;
    }

    // -----------------------------------------------------------------------
    // Circuit extension (D=2) helpers using W=7
    // -----------------------------------------------------------------------
    // The Plonky2 circuit uses quadratic extension (D=2) over the evaluation field.
    // A "circuit Ext2 element" is a pair (a0, a1) of Ext3 values representing a0 + a1*α
    // where α^2 = 7 (Goldilocks quadratic non-residue W=7).

    /// @dev Circuit Ext2 multiply: (a0 + a1*α)(b0 + b1*α) = (a0*b0 + 7*a1*b1) + (a0*b1 + a1*b0)*α
    function _circuitExt2Mul(
        GoldilocksExt3.Ext3 memory a0, GoldilocksExt3.Ext3 memory a1,
        GoldilocksExt3.Ext3 memory b0, GoldilocksExt3.Ext3 memory b1
    ) internal pure returns (GoldilocksExt3.Ext3 memory r0, GoldilocksExt3.Ext3 memory r1) {
        // r0 = a0*b0 + 7*a1*b1
        r0 = a0.mul(b0).add(a1.mul(b1).mulScalar(7));
        // r1 = a0*b1 + a1*b0
        r1 = a0.mul(b1).add(a1.mul(b0));
    }

    // -----------------------------------------------------------------------
    // Main verification entry point
    // -----------------------------------------------------------------------

    /// @notice Verify Plonky2 constraint satisfaction at challenge point ζ.
    function verifyConstraints(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) public pure returns (bool) {
        // Step 1: Compute Z_H(ζ) = ζ^n - 1
        GoldilocksExt3.Ext3 memory zetaPowN = GoldilocksExt3.expPowerOf2(challenges.plonkZeta, params.degreeBits);
        GoldilocksExt3.Ext3 memory zHZeta = zetaPowN.sub(GoldilocksExt3.one());

        // Step 2: Compute all vanishing polynomial terms
        GoldilocksExt3.Ext3[] memory vanishingTerms = _computeAllVanishingTerms(
            openings, params, challenges, permData, gates, publicInputs
        );

        // Step 3: Reduce with alpha challenges → one value per challenge
        GoldilocksExt3.Ext3[] memory vanishing = _reduceWithAlphas(
            vanishingTerms, challenges.plonkAlphas, params.numChallenges
        );

        // Step 4: Check vanishing[i] == Z_H(ζ) * quotient[i]
        for (uint256 i = 0; i < params.numChallenges; i++) {
            uint256 start = i * params.quotientDegreeFactor;
            GoldilocksExt3.Ext3[] memory chunks = new GoldilocksExt3.Ext3[](params.quotientDegreeFactor);
            for (uint256 j = 0; j < params.quotientDegreeFactor; j++) {
                chunks[j] = openings.quotientPolys[start + j];
            }
            GoldilocksExt3.Ext3 memory quotientAtZeta = GoldilocksExt3.reduceWithPowers(chunks, zetaPowN);
            GoldilocksExt3.Ext3 memory rhs = zHZeta.mul(quotientAtZeta);
            if (!GoldilocksExt3.eq(vanishing[i], rhs)) {
                return false;
            }
        }

        return true;
    }

    // -----------------------------------------------------------------------
    // Vanishing polynomial computation
    // -----------------------------------------------------------------------

    function _computeAllVanishingTerms(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        // 1. Boundary: L_0(ζ) · (Z(ζ) - 1)
        GoldilocksExt3.Ext3 memory l0Zeta = GoldilocksExt3.evalL0(
            challenges.plonkZeta, params.degreeBits
        );
        GoldilocksExt3.Ext3[] memory boundaryTerms = new GoldilocksExt3.Ext3[](params.numChallenges);
        for (uint256 i = 0; i < params.numChallenges; i++) {
            boundaryTerms[i] = l0Zeta.mul(openings.plonkZs[i].sub(GoldilocksExt3.one()));
        }

        // 2. Permutation checks
        GoldilocksExt3.Ext3[] memory permTerms = _checkPermutation(
            openings, params, challenges, permData
        );

        // 3. Gate constraints (with selector filters)
        GoldilocksExt3.Ext3[] memory gateTerms = _evaluateGateConstraints(
            openings, params, gates, publicInputs
        );

        // Concatenate: boundary + permutation + gate
        uint256 totalLen = boundaryTerms.length + permTerms.length + gateTerms.length;
        GoldilocksExt3.Ext3[] memory allTerms = new GoldilocksExt3.Ext3[](totalLen);
        uint256 idx = 0;
        for (uint256 i = 0; i < boundaryTerms.length; i++) allTerms[idx++] = boundaryTerms[i];
        for (uint256 i = 0; i < permTerms.length; i++) allTerms[idx++] = permTerms[i];
        for (uint256 i = 0; i < gateTerms.length; i++) allTerms[idx++] = gateTerms[i];

        return allTerms;
    }

    // -----------------------------------------------------------------------
    // Gate constraint evaluation with selector filters
    // -----------------------------------------------------------------------

    /// @dev Evaluate all gate constraints with selector filtering.
    ///
    ///   constraints[j] = SUM over gates: filter(gate) * gate.eval_unfiltered(j)
    ///
    ///   The filter ensures only the active gate's constraints are nonzero.
    function _evaluateGateConstraints(
        Openings memory openings,
        CircuitParams memory params,
        GateInfo[] memory gates,
        uint256[] memory publicInputs
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        GoldilocksExt3.Ext3[] memory constraints = new GoldilocksExt3.Ext3[](params.numGateConstraints);
        for (uint256 i = 0; i < params.numGateConstraints; i++) {
            constraints[i] = GoldilocksExt3.zero();
        }

        // Strip selector + lookup selector columns from constants
        uint256 constOffset = params.numSelectors + params.numLookupSelectors;

        for (uint256 g = 0; g < gates.length; g++) {
            // Compute selector filter
            GoldilocksExt3.Ext3 memory selectorVal = openings.constants[gates[g].selectorIndex];
            GoldilocksExt3.Ext3 memory filter = _computeFilter(
                gates[g].rowInGroup,
                gates[g].groupStart,
                gates[g].groupEnd,
                selectorVal,
                params.numSelectors > 1
            );

            // Evaluate gate-specific unfiltered constraints
            GoldilocksExt3.Ext3[] memory unfiltered = _evalGateUnfiltered(
                gates[g].gateType,
                openings,
                constOffset,
                publicInputs,
                gates[g].gateConfig
            );

            // Accumulate: constraints[j] += filter * unfiltered[j]
            for (uint256 j = 0; j < unfiltered.length; j++) {
                constraints[j] = constraints[j].add(filter.mul(unfiltered[j]));
            }
        }

        return constraints;
    }

    /// @dev Compute selector filter for a gate.
    ///   filter = PRODUCT_{i in group, i != row} (i - s) * (UNUSED - s)
    function _computeFilter(
        uint256 row,
        uint256 groupStart,
        uint256 groupEnd,
        GoldilocksExt3.Ext3 memory s,
        bool multipleSelectors
    ) internal pure returns (GoldilocksExt3.Ext3 memory) {
        GoldilocksExt3.Ext3 memory filter = GoldilocksExt3.one();

        for (uint256 i = groupStart; i < groupEnd; i++) {
            if (i != row) {
                filter = filter.mul(GoldilocksExt3.fromBase(uint64(i)).sub(s));
            }
        }

        if (multipleSelectors) {
            filter = filter.mul(GoldilocksExt3.fromBase(uint64(UNUSED_SELECTOR)).sub(s));
        }

        return filter;
    }

    /// @dev Dispatch gate-specific constraint evaluation.
    function _evalGateUnfiltered(
        uint256 gateType,
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory publicInputs,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        if (gateType == 0) return new GoldilocksExt3.Ext3[](0);                          // NoopGate
        if (gateType == 1) return _evalConstantGate(openings, constOffset, gateConfig);   // ConstantGate
        if (gateType == 2) return _evalPublicInputGate(openings, publicInputs);           // PublicInputGate
        if (gateType == 3) return PoseidonGateEval.evaluateExt3(openings.wires);          // PoseidonGate
        if (gateType == 4) return _evalArithmeticGate(openings, constOffset, gateConfig); // ArithmeticGate
        if (gateType == 5) return _evalBaseSumGate(openings, gateConfig);                 // BaseSumGate
        if (gateType == 6) return _evalRandomAccessGate(openings, gateConfig);            // RandomAccessGate
        if (gateType == 7) return _evalReducingGate(openings, gateConfig);                // ReducingGate
        if (gateType == 8) return _evalReducingExtensionGate(openings, gateConfig);       // ReducingExtensionGate
        if (gateType == 9) return _evalArithmeticExtensionGate(openings, constOffset, gateConfig); // ArithmeticExtensionGate
        if (gateType == 10) return _evalMulExtensionGate(openings, constOffset, gateConfig); // MulExtensionGate
        if (gateType == 11) return _evalExponentiationGate(openings, gateConfig);         // ExponentiationGate
        if (gateType == 12) return _evalCosetInterpolationGate(openings, gateConfig);     // CosetInterpolationGate
        if (gateType == 15) return _evalPoseidonMdsGate(openings);                        // PoseidonMdsGate
        revert("Plonky2Verifier: unsupported gate type");
    }

    // -----------------------------------------------------------------------
    // Gate implementations
    // -----------------------------------------------------------------------

    /// @dev ConstantGate: wire[i] - constant[constOffset + i] = 0
    ///      gateConfig: [numConsts]
    function _evalConstantGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numConsts = gateConfig[0];
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numConsts);
        for (uint256 i = 0; i < numConsts; i++) {
            c[i] = openings.wires[i].sub(openings.constants[constOffset + i]);
        }
        return c;
    }

    /// @dev PublicInputGate: wire[i] - piHash[i] = 0 for i in 0..4
    function _evalPublicInputGate(
        Openings memory openings,
        uint256[] memory publicInputs
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](4);
        for (uint256 i = 0; i < 4; i++) {
            GoldilocksExt3.Ext3 memory piVal = GoldilocksExt3.fromBase(
                uint64(i < publicInputs.length ? publicInputs[i] : 0)
            );
            c[i] = openings.wires[i].sub(piVal);
        }
        return c;
    }

    /// @dev ArithmeticGate: output - (m0 * m1 * c0 + addend * c1) = 0 per op
    ///      gateConfig: [numOps]
    function _evalArithmeticGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numOps = gateConfig[0];
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numOps);
        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 4;
            GoldilocksExt3.Ext3 memory expected = openings.wires[wBase].mul(openings.wires[wBase + 1])
                .mul(openings.constants[constOffset + i * 2])
                .add(openings.wires[wBase + 2].mul(openings.constants[constOffset + i * 2 + 1]));
            c[i] = openings.wires[wBase + 3].sub(expected);
        }
        return c;
    }

    /// @dev BaseSumGate<B>: sum decomposition into base-B limbs
    ///      Constraint 0: computed_sum - wire[0]  (where computed_sum = Σ limb[i] * B^i)
    ///      Constraints 1..numLimbs: range check each limb: Π_{k=0}^{B-1} (limb - k) = 0
    ///      gateConfig: [numLimbs, base]
    function _evalBaseSumGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numLimbs = gateConfig[0];
        uint256 base = gateConfig[1];
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](1 + numLimbs);

        // Constraint 0: reduce_with_powers(limbs, base) - sum
        GoldilocksExt3.Ext3 memory computedSum = GoldilocksExt3.zero();
        GoldilocksExt3.Ext3 memory basePow = GoldilocksExt3.one();
        GoldilocksExt3.Ext3 memory baseExt = GoldilocksExt3.fromBase(uint64(base));
        for (uint256 i = 0; i < numLimbs; i++) {
            computedSum = computedSum.add(openings.wires[1 + i].mul(basePow));
            if (i + 1 < numLimbs) basePow = basePow.mul(baseExt);
        }
        c[0] = computedSum.sub(openings.wires[0]);

        // Constraints 1..numLimbs: range check Π_{k=0}^{B-1} (limb - k)
        for (uint256 i = 0; i < numLimbs; i++) {
            GoldilocksExt3.Ext3 memory prod = GoldilocksExt3.one();
            for (uint256 k = 0; k < base; k++) {
                prod = prod.mul(openings.wires[1 + i].sub(GoldilocksExt3.fromBase(uint64(k))));
            }
            c[1 + i] = prod;
        }
        return c;
    }

    /// @dev RandomAccessGate: binary decomposition + MUX selection
    ///      gateConfig: [bits, numCopies, numExtraConstants, vecSize]
    function _evalRandomAccessGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 bits = gateConfig[0];
        uint256 numCopies = gateConfig[1];
        uint256 numExtraConstants = gateConfig[2];
        uint256 vecSize = gateConfig[3];
        uint256 perCopy = bits + 2;
        uint256 total = numCopies * perCopy + numExtraConstants;
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](total);

        uint256 routedPerCopy = 2 + vecSize;
        uint256 numRoutedTotal = numCopies * routedPerCopy + numExtraConstants;

        for (uint256 copy = 0; copy < numCopies; copy++) {
            _evalRandomAccessCopy(openings, c, copy * routedPerCopy, numRoutedTotal + copy * bits, copy * perCopy, bits, vecSize);
        }
        for (uint256 i = 0; i < numExtraConstants; i++) {
            c[numCopies * perCopy + i] = GoldilocksExt3.zero();
        }
        return c;
    }

    function _evalRandomAccessCopy(
        Openings memory openings,
        GoldilocksExt3.Ext3[] memory c,
        uint256 rBase,
        uint256 nBase,
        uint256 cBase,
        uint256 bits,
        uint256 vecSize
    ) internal pure {
        // Boolean + index reconstruction
        GoldilocksExt3.Ext3 memory reconstructed = GoldilocksExt3.zero();
        GoldilocksExt3.Ext3 memory pow2 = GoldilocksExt3.one();
        for (uint256 b = 0; b < bits; b++) {
            GoldilocksExt3.Ext3 memory bit = openings.wires[nBase + b];
            c[cBase + b] = bit.mul(bit.sub(GoldilocksExt3.one()));
            reconstructed = reconstructed.add(bit.mul(pow2));
            pow2 = pow2.mul(GoldilocksExt3.fromBase(2));
        }
        c[cBase + bits] = reconstructed.sub(openings.wires[rBase]);

        // MUX: fold list using bits
        GoldilocksExt3.Ext3[] memory list = new GoldilocksExt3.Ext3[](vecSize);
        for (uint256 v = 0; v < vecSize; v++) {
            list[v] = openings.wires[rBase + 2 + v];
        }
        uint256 curSize = vecSize;
        for (uint256 b = 0; b < bits; b++) {
            GoldilocksExt3.Ext3 memory bit = openings.wires[nBase + b];
            uint256 half = curSize >> 1;
            for (uint256 j = 0; j < half; j++) {
                list[j] = list[2 * j].add(bit.mul(list[2 * j + 1].sub(list[2 * j])));
            }
            curSize = half;
        }
        c[cBase + bits + 1] = list[0].sub(openings.wires[rBase + 1]);
    }

    /// @dev ReducingGate: Horner reduction with BASE FIELD coefficients
    ///      Same as ReducingExtensionGate but coefficients are single base field elements,
    ///      not extension field elements.
    ///      gateConfig: [numCoeffs]
    ///
    ///      The circuit extension degree D=2 means accumulators and alpha are pairs of Ext3,
    ///      representing elements of (Ext3)^2 with W=7 arithmetic.
    function _evalReducingGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (circuit extension element = pair of Ext3)
        //   wires[2..3]: alpha (circuit extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs-1]: coefficients (numCoeffs BASE FIELD scalars)
        //   Non-routed: accumulators (numCoeffs circuit extension elements, last reuses output)
        GoldilocksExt3.Ext3 memory alpha0 = openings.wires[2];
        GoldilocksExt3.Ext3 memory alpha1 = openings.wires[3];
        uint256 numRouted = 3 * D + numCoeffs; // coefficients are single scalars

        GoldilocksExt3.Ext3 memory prevAcc0 = openings.wires[4];
        GoldilocksExt3.Ext3 memory prevAcc1 = openings.wires[5];

        for (uint256 i = 0; i < numCoeffs; i++) {
            // Coefficient is a single base field scalar (promoted to circuit ext via (coeff, 0))
            GoldilocksExt3.Ext3 memory coeff = openings.wires[6 + i];

            // computed = prevAcc * alpha + (coeff, 0) using circuit Ext2 mul with W=7
            (GoldilocksExt3.Ext3 memory prod0, GoldilocksExt3.Ext3 memory prod1) =
                _circuitExt2Mul(prevAcc0, prevAcc1, alpha0, alpha1);
            GoldilocksExt3.Ext3 memory computed0 = prod0.add(coeff);
            GoldilocksExt3.Ext3 memory computed1 = prod1;

            GoldilocksExt3.Ext3 memory actualAcc0;
            GoldilocksExt3.Ext3 memory actualAcc1;
            if (i == numCoeffs - 1) {
                actualAcc0 = openings.wires[0];
                actualAcc1 = openings.wires[1];
            } else {
                uint256 accBase = numRouted + i * D;
                actualAcc0 = openings.wires[accBase];
                actualAcc1 = openings.wires[accBase + 1];
            }

            GoldilocksExt3.Ext3 memory diff0 = actualAcc0.sub(computed0);
            GoldilocksExt3.Ext3 memory diff1 = actualAcc1.sub(computed1);
            c[i * D] = diff0;
            c[i * D + 1] = diff1;

            prevAcc0 = actualAcc0;
            prevAcc1 = actualAcc1;
        }
        return c;
    }

    /// @dev ReducingExtensionGate: Horner-style polynomial evaluation
    ///      acc[0] = old_acc * alpha + coeff[0]
    ///      acc[i] = acc[i-1] * alpha + coeff[i]
    ///      constraint[i*D..i*D+D-1]: acc[i] - computed (D=2 circuit extension components)
    ///      gateConfig: [numCoeffs]
    function _evalReducingExtensionGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2; // Circuit extension degree
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (circuit extension element)
        //   wires[2..3]: alpha (circuit extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs*2-1]: coefficients (numCoeffs circuit extension elements)
        //   Non-routed: intermediate accumulators (except last = output)
        GoldilocksExt3.Ext3 memory alpha0 = openings.wires[2];
        GoldilocksExt3.Ext3 memory alpha1 = openings.wires[3];

        // Start wire index for intermediates (non-routed)
        uint256 numRouted = 3 * D + numCoeffs * D;

        GoldilocksExt3.Ext3 memory prevAcc0 = openings.wires[4];
        GoldilocksExt3.Ext3 memory prevAcc1 = openings.wires[5];

        for (uint256 i = 0; i < numCoeffs; i++) {
            uint256 coeffBase = 6 + i * D;
            GoldilocksExt3.Ext3 memory coeff0 = openings.wires[coeffBase];
            GoldilocksExt3.Ext3 memory coeff1 = openings.wires[coeffBase + 1];

            // computed = prevAcc * alpha + coeff using circuit Ext2 mul with W=7
            (GoldilocksExt3.Ext3 memory prod0, GoldilocksExt3.Ext3 memory prod1) =
                _circuitExt2Mul(prevAcc0, prevAcc1, alpha0, alpha1);
            GoldilocksExt3.Ext3 memory computed0 = prod0.add(coeff0);
            GoldilocksExt3.Ext3 memory computed1 = prod1.add(coeff1);

            // Get the actual accumulator value
            GoldilocksExt3.Ext3 memory actualAcc0;
            GoldilocksExt3.Ext3 memory actualAcc1;
            if (i == numCoeffs - 1) {
                // Last accumulator is the output wire
                actualAcc0 = openings.wires[0];
                actualAcc1 = openings.wires[1];
            } else {
                // Intermediate accumulators in non-routed wires
                uint256 accBase = numRouted + i * D;
                actualAcc0 = openings.wires[accBase];
                actualAcc1 = openings.wires[accBase + 1];
            }

            // Constraint: actualAcc - computed (D=2 circuit extension components, each an Ext3)
            GoldilocksExt3.Ext3 memory diff0 = actualAcc0.sub(computed0);
            GoldilocksExt3.Ext3 memory diff1 = actualAcc1.sub(computed1);
            c[i * D] = diff0;
            c[i * D + 1] = diff1;

            prevAcc0 = actualAcc0;
            prevAcc1 = actualAcc1;
        }
        return c;
    }

    /// @dev ArithmeticExtensionGate: c0*x*y + c1*z on circuit extension field elements (D=2)
    ///      gateConfig: [numOps]
    function _evalArithmeticExtensionGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numOps = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numOps * D);

        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 4 * D;
            // Read circuit extension elements (each is D=2 consecutive Ext3 wire openings)
            GoldilocksExt3.Ext3 memory m0_0 = openings.wires[wBase];
            GoldilocksExt3.Ext3 memory m0_1 = openings.wires[wBase + 1];
            GoldilocksExt3.Ext3 memory m1_0 = openings.wires[wBase + D];
            GoldilocksExt3.Ext3 memory m1_1 = openings.wires[wBase + D + 1];
            GoldilocksExt3.Ext3 memory add0 = openings.wires[wBase + 2 * D];
            GoldilocksExt3.Ext3 memory add1 = openings.wires[wBase + 2 * D + 1];
            GoldilocksExt3.Ext3 memory out0 = openings.wires[wBase + 3 * D];
            GoldilocksExt3.Ext3 memory out1 = openings.wires[wBase + 3 * D + 1];

            // Constants are base field scalars (Ext3 openings, use as scalar multiplier)
            GoldilocksExt3.Ext3 memory cc0 = openings.constants[constOffset + i * 2];
            GoldilocksExt3.Ext3 memory cc1 = openings.constants[constOffset + i * 2 + 1];

            // product = m0 * m1 (circuit Ext2 mul with W=7)
            (GoldilocksExt3.Ext3 memory p0, GoldilocksExt3.Ext3 memory p1) =
                _circuitExt2Mul(m0_0, m0_1, m1_0, m1_1);

            // expected = product * c0 + addend * c1
            // c0 and c1 are Ext3 elements (constants evaluated at zeta)
            // product * c0 means scaling each component of the circuit Ext2 pair by the Ext3 constant
            GoldilocksExt3.Ext3 memory exp0 = p0.mul(cc0).add(add0.mul(cc1));
            GoldilocksExt3.Ext3 memory exp1 = p1.mul(cc0).add(add1.mul(cc1));

            c[i * D] = out0.sub(exp0);
            c[i * D + 1] = out1.sub(exp1);
        }
        return c;
    }

    /// @dev MulExtensionGate: c0*x*y on circuit extension field elements (D=2)
    ///      gateConfig: [numOps]
    function _evalMulExtensionGate(
        Openings memory openings,
        uint256 constOffset,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numOps = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numOps * D);

        for (uint256 i = 0; i < numOps; i++) {
            uint256 wBase = i * 3 * D;
            GoldilocksExt3.Ext3 memory m0_0 = openings.wires[wBase];
            GoldilocksExt3.Ext3 memory m0_1 = openings.wires[wBase + 1];
            GoldilocksExt3.Ext3 memory m1_0 = openings.wires[wBase + D];
            GoldilocksExt3.Ext3 memory m1_1 = openings.wires[wBase + D + 1];
            GoldilocksExt3.Ext3 memory out0 = openings.wires[wBase + 2 * D];
            GoldilocksExt3.Ext3 memory out1 = openings.wires[wBase + 2 * D + 1];

            GoldilocksExt3.Ext3 memory cc0 = openings.constants[constOffset + i];

            // product = m0 * m1 (circuit Ext2 mul with W=7)
            (GoldilocksExt3.Ext3 memory p0, GoldilocksExt3.Ext3 memory p1) =
                _circuitExt2Mul(m0_0, m0_1, m1_0, m1_1);

            // expected = product * c0 (scale each component by the Ext3 constant)
            GoldilocksExt3.Ext3 memory exp0 = p0.mul(cc0);
            GoldilocksExt3.Ext3 memory exp1 = p1.mul(cc0);

            c[i * D] = out0.sub(exp0);
            c[i * D + 1] = out1.sub(exp1);
        }
        return c;
    }

    /// @dev ExponentiationGate: binary exponentiation base^power
    ///      gateConfig: [numPowerBits]
    function _evalExponentiationGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numPowerBits = gateConfig[0];
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numPowerBits + 1);

        GoldilocksExt3.Ext3 memory base_ = openings.wires[0];
        uint256 outputWire = 1 + numPowerBits;
        uint256 intermediateStart = 2 + numPowerBits;

        GoldilocksExt3.Ext3 memory oneVal = GoldilocksExt3.one();

        for (uint256 i = 0; i < numPowerBits; i++) {
            // Bit at position (numPowerBits - 1 - i) in BE order
            GoldilocksExt3.Ext3 memory curBit = openings.wires[1 + numPowerBits - 1 - i];

            // prev_intermediate = intermediate[i-1]^2 if i > 0, else 1
            GoldilocksExt3.Ext3 memory prevIntermediate;
            if (i == 0) {
                prevIntermediate = oneVal;
            } else {
                GoldilocksExt3.Ext3 memory prevVal = openings.wires[intermediateStart + i - 1];
                prevIntermediate = prevVal.mul(prevVal);
            }

            // computed = prevIntermediate * (curBit * base + (1 - curBit))
            //          = prevIntermediate * (curBit * (base - 1) + 1)
            GoldilocksExt3.Ext3 memory selector = curBit.mul(base_.sub(oneVal)).add(oneVal);
            GoldilocksExt3.Ext3 memory computed = prevIntermediate.mul(selector);
            GoldilocksExt3.Ext3 memory actual = openings.wires[intermediateStart + i];
            c[i] = actual.sub(computed);
        }

        // Final constraint: output - intermediate[numPowerBits - 1]
        c[numPowerBits] = openings.wires[outputWire].sub(openings.wires[intermediateStart + numPowerBits - 1]);
        return c;
    }

    /// @dev CosetInterpolationGate: Barycentric interpolation on a coset
    ///      gateConfig: [subgroupBits, numPoints, numIntermediates, degree,
    ///                   w0..w_{numPoints-1}, d0..d_{numPoints-1}]
    function _evalCosetInterpolationGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numPoints = gateConfig[1];
        uint256 numIntermediates = gateConfig[2];
        uint256 degree = gateConfig[3];
        uint256 D = 2;
        uint256 numConstraints = D * (2 + 2 * numIntermediates);
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numConstraints);

        // Wire layout indices
        uint256 evalPointStart = 1 + numPoints * D;
        uint256 evalValueStart = evalPointStart + D;
        uint256 intEvalStart = evalValueStart + D;
        uint256 intProdStart = intEvalStart + numIntermediates * D;
        uint256 shiftedEvalStart = intProdStart + numIntermediates * D;

        // Constraint 0-1: evaluation_point - shifted_evaluation_point * shift = 0
        {
            GoldilocksExt3.Ext3 memory shift = openings.wires[0];
            c[0] = openings.wires[evalPointStart].sub(openings.wires[shiftedEvalStart].mul(shift));
            c[1] = openings.wires[evalPointStart + 1].sub(openings.wires[shiftedEvalStart + 1].mul(shift));
        }

        // Barycentric interpolation constraints via _cosetInterpConstraints helper
        // Pack indices to avoid stack-too-deep
        {
            uint256[] memory idx = new uint256[](8);
            idx[0] = numPoints; idx[1] = numIntermediates; idx[2] = degree;
            idx[3] = intEvalStart; idx[4] = intProdStart;
            idx[5] = evalValueStart; idx[6] = shiftedEvalStart; idx[7] = numConstraints;
            _cosetInterpConstraints(openings, gateConfig, c, idx);
        }

        return c;
    }

    /// @dev Helper: compute intermediate + final constraints for CosetInterpolationGate.
    ///      idx = [numPoints, numIntermediates, degree, intEvalStart, intProdStart,
    ///             evalValueStart, shiftedEvalStart, numConstraints]
    function _cosetInterpConstraints(
        Openings memory openings,
        uint256[] memory gateConfig,
        GoldilocksExt3.Ext3[] memory c,
        uint256[] memory idx
    ) internal pure {
        uint256 D = 2;
        GoldilocksExt3.Ext3 memory z0 = openings.wires[idx[6]];
        GoldilocksExt3.Ext3 memory z1 = openings.wires[idx[6] + 1];

        InterpState memory st;
        st.eval0 = GoldilocksExt3.zero(); st.eval1 = GoldilocksExt3.zero();
        st.prod0 = GoldilocksExt3.one();  st.prod1 = GoldilocksExt3.zero();
        _partialInterpolate(openings, gateConfig, idx[0], 0, idx[2], z0, z1, st);

        uint256 cIdx = D;
        for (uint256 i = 0; i < idx[1]; i++) {
            uint256 eBase = idx[3] + i * D;  // intEvalStart offset
            uint256 pBase = idx[4] + i * D;  // intProdStart offset

            c[cIdx++] = openings.wires[eBase].sub(st.eval0);
            c[cIdx++] = openings.wires[eBase + 1].sub(st.eval1);
            c[cIdx++] = openings.wires[pBase].sub(st.prod0);
            c[cIdx++] = openings.wires[pBase + 1].sub(st.prod1);

            uint256 chunkStart = 1 + (idx[2] - 1) * (i + 1);
            uint256 chunkEnd = chunkStart + idx[2] - 1;
            if (chunkEnd > idx[0]) chunkEnd = idx[0];

            st.eval0 = openings.wires[eBase]; st.eval1 = openings.wires[eBase + 1];
            st.prod0 = openings.wires[pBase]; st.prod1 = openings.wires[pBase + 1];
            _partialInterpolate(openings, gateConfig, idx[0], chunkStart, chunkEnd, z0, z1, st);
        }

        // Final: evalValue * lastProd - lastEval = 0
        (GoldilocksExt3.Ext3 memory vp0, GoldilocksExt3.Ext3 memory vp1) =
            _circuitExt2Mul(openings.wires[idx[5]], openings.wires[idx[5] + 1], st.prod0, st.prod1);
        c[idx[7] - 2] = vp0.sub(st.eval0);
        c[idx[7] - 1] = vp1.sub(st.eval1);
    }

    /// @dev Partial Barycentric interpolation fold (modifies st in-place via struct).
    function _partialInterpolate(
        Openings memory openings,
        uint256[] memory gateConfig,
        uint256 numPoints,
        uint256 startIdx,
        uint256 endIdx,
        GoldilocksExt3.Ext3 memory z0,
        GoldilocksExt3.Ext3 memory z1,
        InterpState memory st
    ) internal pure {
        uint256 D = 2;
        uint256 wOff = 4;           // weights offset in gateConfig
        uint256 dOff = 4 + numPoints; // domain offset in gateConfig

        for (uint256 j = startIdx; j < endIdx; j++) {
            // term = z - domain[j] (circuit Ext2: subtract base scalar from c0 only)
            GoldilocksExt3.Ext3 memory t0 = z0.sub(GoldilocksExt3.fromBase(uint64(gateConfig[dOff + j])));

            // weighted value = value[j] * weight[j]
            GoldilocksExt3.Ext3 memory wv0 = openings.wires[1 + j * D].mulScalar(uint64(gateConfig[wOff + j]));
            GoldilocksExt3.Ext3 memory wv1 = openings.wires[1 + j * D + 1].mulScalar(uint64(gateConfig[wOff + j]));

            // newEval = eval * term + weightedVal * prod
            (GoldilocksExt3.Ext3 memory et0, GoldilocksExt3.Ext3 memory et1) =
                _circuitExt2Mul(st.eval0, st.eval1, t0, z1);
            (GoldilocksExt3.Ext3 memory wp0, GoldilocksExt3.Ext3 memory wp1) =
                _circuitExt2Mul(wv0, wv1, st.prod0, st.prod1);
            st.eval0 = et0.add(wp0);
            st.eval1 = et1.add(wp1);

            // newProd = prod * term
            (st.prod0, st.prod1) = _circuitExt2Mul(st.prod0, st.prod1, t0, z1);
        }
    }

    /// @dev PoseidonMdsGate: MDS matrix multiplication on 12 circuit extension elements
    ///      output[r] = Σ MDS_CIRC[i] * input[(i+r)%12] + MDS_DIAG[r] * input[r]
    ///      24 constraints (12 outputs × D=2)
    function _evalPoseidonMdsGate(
        Openings memory openings
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 D = 2;
        uint256 W = 12; // SPONGE_WIDTH
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](W * D);

        // Read 12 input circuit extension elements (each is D=2 consecutive Ext3 wires)
        // inputs[i] is a pair (inputs0[i], inputs1[i])
        GoldilocksExt3.Ext3[12] memory inputs0;
        GoldilocksExt3.Ext3[12] memory inputs1;
        for (uint256 i = 0; i < W; i++) {
            inputs0[i] = openings.wires[i * D];
            inputs1[i] = openings.wires[i * D + 1];
        }

        // For each output row r, compute MDS multiplication
        // MDS constants are base field scalars, so they scale each component of the circuit Ext2 pair
        for (uint256 r = 0; r < W; r++) {
            GoldilocksExt3.Ext3 memory acc0 = GoldilocksExt3.zero();
            GoldilocksExt3.Ext3 memory acc1 = GoldilocksExt3.zero();
            for (uint256 i = 0; i < W; i++) {
                uint256 idx = (i + r) % W;
                uint64 mdsVal = uint64(PoseidonConstants.mdsCirc(i));
                acc0 = acc0.add(inputs0[idx].mulScalar(mdsVal));
                acc1 = acc1.add(inputs1[idx].mulScalar(mdsVal));
            }
            uint64 diagVal = uint64(PoseidonConstants.mdsDiag(r));
            acc0 = acc0.add(inputs0[r].mulScalar(diagVal));
            acc1 = acc1.add(inputs1[r].mulScalar(diagVal));

            // Read output circuit extension element
            GoldilocksExt3.Ext3 memory output0 = openings.wires[(W + r) * D];
            GoldilocksExt3.Ext3 memory output1 = openings.wires[(W + r) * D + 1];

            c[r * D] = output0.sub(acc0);
            c[r * D + 1] = output1.sub(acc1);
        }
        return c;
    }

    // -----------------------------------------------------------------------
    // Permutation argument
    // -----------------------------------------------------------------------

    function _checkPermutation(
        Openings memory openings,
        CircuitParams memory params,
        Challenges memory challenges,
        PermutationData memory permData
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        // chunk_size = max_degree = quotient_degree_factor (NOT - 1)
        uint256 chunkSize = params.quotientDegreeFactor;
        uint256 numChunks = (params.numRoutedWires + chunkSize - 1) / chunkSize;

        GoldilocksExt3.Ext3[] memory terms = new GoldilocksExt3.Ext3[](
            numChunks * params.numChallenges
        );

        for (uint256 ch = 0; ch < params.numChallenges; ch++) {
            _checkPermutationForChallenge(
                openings, params, permData,
                challenges.plonkBetas[ch],
                challenges.plonkGammas[ch],
                challenges.plonkZeta,
                ch, chunkSize, numChunks, terms
            );
        }

        return terms;
    }

    function _checkPermutationForChallenge(
        Openings memory openings,
        CircuitParams memory params,
        PermutationData memory permData,
        uint256 betaBase,
        uint256 gammaBase,
        GoldilocksExt3.Ext3 memory zeta,
        uint256 ch,
        uint256 chunkSize,
        uint256 numChunks,
        GoldilocksExt3.Ext3[] memory terms
    ) internal pure {
        GoldilocksExt3.Ext3 memory beta = GoldilocksExt3.fromBase(uint64(betaBase));
        GoldilocksExt3.Ext3 memory gamma = GoldilocksExt3.fromBase(uint64(gammaBase));
        GoldilocksExt3.Ext3 memory betaZeta = beta.mul(zeta);
        uint256 partialIdx = ch * params.numPartialProducts;

        for (uint256 chunk = 0; chunk < numChunks; chunk++) {
            uint256 cEnd = (chunk + 1) * chunkSize;
            if (cEnd > params.numRoutedWires) cEnd = params.numRoutedWires;
            terms[ch * numChunks + chunk] = _computePermChunkTerm(
                openings, permData, beta, gamma, betaZeta,
                PermChunkParams(ch, chunk, chunk * chunkSize, cEnd, numChunks, partialIdx)
            );
        }
    }

    /// @dev Packed permutation chunk parameters to avoid stack depth issues.
    struct PermChunkParams {
        uint256 ch;
        uint256 chunk;
        uint256 chunkStart;
        uint256 chunkEnd;
        uint256 numChunks;
        uint256 partialIdx;
    }

    function _computePermChunkTerm(
        Openings memory openings,
        PermutationData memory permData,
        GoldilocksExt3.Ext3 memory beta,
        GoldilocksExt3.Ext3 memory gamma,
        GoldilocksExt3.Ext3 memory betaZeta,
        PermChunkParams memory p
    ) internal pure returns (GoldilocksExt3.Ext3 memory) {
        GoldilocksExt3.Ext3 memory prevAcc = p.chunk == 0
            ? openings.plonkZs[p.ch]
            : openings.partialProducts[p.partialIdx + p.chunk - 1];

        GoldilocksExt3.Ext3 memory nextAcc = p.chunk == p.numChunks - 1
            ? openings.plonkZsNext[p.ch]
            : openings.partialProducts[p.partialIdx + p.chunk];

        GoldilocksExt3.Ext3 memory numProd = GoldilocksExt3.one();
        GoldilocksExt3.Ext3 memory denProd = GoldilocksExt3.one();
        for (uint256 j = p.chunkStart; j < p.chunkEnd; j++) {
            GoldilocksExt3.Ext3 memory wireVal = openings.wires[j];
            numProd = numProd.mul(wireVal.add(betaZeta.mulScalar(uint64(permData.kIs[j]))).add(gamma));
            denProd = denProd.mul(wireVal.add(beta.mul(openings.plonkSigmas[j])).add(gamma));
        }

        return prevAcc.mul(numProd).sub(nextAcc.mul(denProd));
    }

    // -----------------------------------------------------------------------
    // Alpha reduction
    // -----------------------------------------------------------------------

    function _reduceWithAlphas(
        GoldilocksExt3.Ext3[] memory terms,
        uint256[] memory alphas,
        uint256 numChallenges
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        GoldilocksExt3.Ext3[] memory result = new GoldilocksExt3.Ext3[](numChallenges);
        for (uint256 i = 0; i < numChallenges; i++) {
            GoldilocksExt3.Ext3 memory alpha = GoldilocksExt3.fromBase(uint64(alphas[i]));
            GoldilocksExt3.Ext3 memory acc = GoldilocksExt3.zero();
            for (uint256 j = terms.length; j > 0; j--) {
                acc = acc.mul(alpha).add(terms[j - 1]);
            }
            result[i] = acc;
        }
        return result;
    }
}
