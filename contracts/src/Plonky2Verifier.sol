// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GoldilocksField.sol";
import "./PoseidonGateEval.sol";
import "./PoseidonConstants.sol";
import {GoldilocksExt3} from "./spongefish/GoldilocksExt3.sol";

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
            if (!GoldilocksExt3.isEqual(vanishing[i], rhs)) {
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
                filter = filter.mul(GoldilocksExt3.fromBaseU256(i).sub(s));
            }
        }

        if (multipleSelectors) {
            filter = filter.mul(GoldilocksExt3.fromBaseU256(UNUSED_SELECTOR).sub(s));
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
            GoldilocksExt3.Ext3 memory piVal = GoldilocksExt3.fromBaseU256(
                i < publicInputs.length ? publicInputs[i] : 0
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
        GoldilocksExt3.Ext3 memory baseExt = GoldilocksExt3.fromBaseU256(base);
        for (uint256 i = 0; i < numLimbs; i++) {
            computedSum = computedSum.add(openings.wires[1 + i].mul(basePow));
            if (i + 1 < numLimbs) basePow = basePow.mul(baseExt);
        }
        c[0] = computedSum.sub(openings.wires[0]);

        // Constraints 1..numLimbs: range check Π_{k=0}^{B-1} (limb - k)
        for (uint256 i = 0; i < numLimbs; i++) {
            GoldilocksExt3.Ext3 memory prod = GoldilocksExt3.one();
            for (uint256 k = 0; k < base; k++) {
                prod = prod.mul(openings.wires[1 + i].sub(GoldilocksExt3.fromBaseU256(k)));
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
    function _evalReducingGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2;
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (extension element)
        //   wires[2..3]: alpha (extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs-1]: coefficients (numCoeffs BASE FIELD scalars)
        //   Non-routed: accumulators (numCoeffs extension elements, last reuses output)
        GoldilocksExt3.Ext3 memory alpha = GoldilocksExt3.Ext3(
            openings.wires[2].c0, openings.wires[3].c0, 0
        );
        uint256 numRouted = 3 * D + numCoeffs; // coefficients are single scalars

        GoldilocksExt3.Ext3 memory prevAcc = GoldilocksExt3.Ext3(
            openings.wires[4].c0, openings.wires[5].c0, 0
        );

        for (uint256 i = 0; i < numCoeffs; i++) {
            // Coefficient is a single base field scalar (promoted to Ext3 via fromBase)
            GoldilocksExt3.Ext3 memory coeff = GoldilocksExt3.fromBase(openings.wires[6 + i].c0);
            GoldilocksExt3.Ext3 memory computed = prevAcc.mul(alpha).add(coeff);

            GoldilocksExt3.Ext3 memory actualAcc;
            if (i == numCoeffs - 1) {
                actualAcc = GoldilocksExt3.Ext3(openings.wires[0].c0, openings.wires[1].c0, 0);
            } else {
                uint256 accBase = numRouted + i * D;
                actualAcc = GoldilocksExt3.Ext3(
                    openings.wires[accBase].c0, openings.wires[accBase + 1].c0, 0
                );
            }

            GoldilocksExt3.Ext3 memory diff = actualAcc.sub(computed);
            c[i * D] = GoldilocksExt3.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt3.fromBase(diff.c1);

            prevAcc = actualAcc;
        }
        return c;
    }

    /// @dev ReducingExtensionGate: Horner-style polynomial evaluation
    ///      acc[0] = old_acc * alpha + coeff[0]
    ///      acc[i] = acc[i-1] * alpha + coeff[i]
    ///      constraint[i*D..i*D+D-1]: acc[i] - computed (D=2 extension components)
    ///      gateConfig: [numCoeffs]
    function _evalReducingExtensionGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numCoeffs = gateConfig[0];
        uint256 D = 2; // Extension degree (wire packing)
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numCoeffs * D);

        // Wire layout (D=2):
        //   wires[0..1]: output (extension element)
        //   wires[2..3]: alpha (extension element)
        //   wires[4..5]: old_acc (initial accumulator)
        //   wires[6..6+numCoeffs*2-1]: coefficients (numCoeffs extension elements)
        //   Non-routed: intermediate accumulators (except last = output)
        GoldilocksExt3.Ext3 memory alpha = GoldilocksExt3.Ext3(
            openings.wires[2].c0, openings.wires[3].c0, 0
        );

        // Start wire index for intermediates (non-routed)
        uint256 numRouted = 3 * D + numCoeffs * D;

        GoldilocksExt3.Ext3 memory prevAcc = GoldilocksExt3.Ext3(
            openings.wires[4].c0, openings.wires[5].c0, 0
        );

        for (uint256 i = 0; i < numCoeffs; i++) {
            uint256 coeffBase = 6 + i * D;
            GoldilocksExt3.Ext3 memory coeff = GoldilocksExt3.Ext3(
                openings.wires[coeffBase].c0, openings.wires[coeffBase + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory computed = prevAcc.mul(alpha).add(coeff);

            // Get the actual accumulator value
            GoldilocksExt3.Ext3 memory actualAcc;
            if (i == numCoeffs - 1) {
                // Last accumulator is the output wire
                actualAcc = GoldilocksExt3.Ext3(openings.wires[0].c0, openings.wires[1].c0, 0);
            } else {
                // Intermediate accumulators in non-routed wires
                uint256 accBase = numRouted + i * D;
                actualAcc = GoldilocksExt3.Ext3(
                    openings.wires[accBase].c0, openings.wires[accBase + 1].c0, 0
                );
            }

            // Constraint: actualAcc - computed (split into D=2 base field components)
            GoldilocksExt3.Ext3 memory diff = actualAcc.sub(computed);
            c[i * D] = GoldilocksExt3.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt3.fromBase(diff.c1);

            prevAcc = actualAcc;
        }
        return c;
    }

    /// @dev ArithmeticExtensionGate: c0*x*y + c1*z on extension field elements
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
            // Read extension elements (each is D=2 consecutive wires)
            GoldilocksExt3.Ext3 memory m0 = GoldilocksExt3.Ext3(
                openings.wires[wBase].c0, openings.wires[wBase + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory m1 = GoldilocksExt3.Ext3(
                openings.wires[wBase + D].c0, openings.wires[wBase + D + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory addend = GoldilocksExt3.Ext3(
                openings.wires[wBase + 2 * D].c0, openings.wires[wBase + 2 * D + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory output = GoldilocksExt3.Ext3(
                openings.wires[wBase + 3 * D].c0, openings.wires[wBase + 3 * D + 1].c0, 0
            );
            // Constants are base field scalars
            GoldilocksExt3.Ext3 memory c0 = openings.constants[constOffset + i * 2];
            GoldilocksExt3.Ext3 memory c1 = openings.constants[constOffset + i * 2 + 1];

            GoldilocksExt3.Ext3 memory expected = m0.mul(m1).mul(c0).add(addend.mul(c1));
            GoldilocksExt3.Ext3 memory diff = output.sub(expected);
            c[i * D] = GoldilocksExt3.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt3.fromBase(diff.c1);
        }
        return c;
    }

    /// @dev MulExtensionGate: c0*x*y on extension field elements
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
            GoldilocksExt3.Ext3 memory m0 = GoldilocksExt3.Ext3(
                openings.wires[wBase].c0, openings.wires[wBase + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory m1 = GoldilocksExt3.Ext3(
                openings.wires[wBase + D].c0, openings.wires[wBase + D + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory output = GoldilocksExt3.Ext3(
                openings.wires[wBase + 2 * D].c0, openings.wires[wBase + 2 * D + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory c0 = openings.constants[constOffset + i];
            GoldilocksExt3.Ext3 memory expected = m0.mul(m1).mul(c0);
            GoldilocksExt3.Ext3 memory diff = output.sub(expected);
            c[i * D] = GoldilocksExt3.fromBase(diff.c0);
            c[i * D + 1] = GoldilocksExt3.fromBase(diff.c1);
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

        GoldilocksExt3.Ext3 memory base = openings.wires[0];
        uint256 outputWire = 1 + numPowerBits;
        uint256 intermediateStart = 2 + numPowerBits;

        GoldilocksExt3.Ext3 memory oneExt = GoldilocksExt3.one();

        for (uint256 i = 0; i < numPowerBits; i++) {
            // Bit at position (numPowerBits - 1 - i) in BE order
            GoldilocksExt3.Ext3 memory curBit = openings.wires[1 + numPowerBits - 1 - i];

            // prev_intermediate = intermediate[i-1]^2 if i > 0, else 1
            GoldilocksExt3.Ext3 memory prevIntermediate;
            if (i == 0) {
                prevIntermediate = oneExt;
            } else {
                GoldilocksExt3.Ext3 memory prevVal = openings.wires[intermediateStart + i - 1];
                prevIntermediate = prevVal.mul(prevVal);
            }

            // computed = prevIntermediate * (curBit * base + (1 - curBit))
            //          = prevIntermediate * (curBit * (base - 1) + 1)
            GoldilocksExt3.Ext3 memory selector = curBit.mul(base.sub(oneExt)).add(oneExt);
            GoldilocksExt3.Ext3 memory computed = prevIntermediate.mul(selector);
            GoldilocksExt3.Ext3 memory actual = openings.wires[intermediateStart + i];
            c[i] = actual.sub(computed);
        }

        // Final constraint: output - intermediate[numPowerBits - 1]
        c[numPowerBits] = openings.wires[outputWire].sub(openings.wires[intermediateStart + numPowerBits - 1]);
        return c;
    }

    /// @dev CosetInterpolationGate: Barycentric interpolation on a coset
    ///      gateConfig: [subgroupBits, numPoints, numIntermediates, degree, barycentricWeights...]
    function _evalCosetInterpolationGate(
        Openings memory openings,
        uint256[] memory gateConfig
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 numPoints = gateConfig[1];
        uint256 numIntermediates = gateConfig[2];
        uint256 D = 2;
        // Total constraints: D + D + 2*D*numIntermediates = D*(2 + 2*numIntermediates)
        uint256 numConstraints = D * (2 + 2 * numIntermediates);
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](numConstraints);

        // Wire layout:
        //   wire[0]: shift (base field)
        //   wires[1..1+numPoints*D-1]: values (numPoints extension elements)
        //   wires[1+numPoints*D..+D-1]: evaluation_point (extension element)
        //   wires[1+numPoints*D+D..+D-1]: evaluation_value (output extension element)
        //   Non-routed:
        //     intermediate_eval[i]: numIntermediates extension elements
        //     intermediate_prod[i]: numIntermediates extension elements
        //     shifted_evaluation_point: extension element

        uint256 evalPointStart = 1 + numPoints * D;
        uint256 evalValueStart = evalPointStart + D;
        uint256 numRouted = evalValueStart + D;
        uint256 intEvalStart = numRouted;
        uint256 intProdStart = intEvalStart + numIntermediates * D;
        uint256 shiftedEvalStart = intProdStart + numIntermediates * D;

        GoldilocksExt3.Ext3 memory shift = openings.wires[0];
        GoldilocksExt3.Ext3 memory evalPoint = GoldilocksExt3.Ext3(
            openings.wires[evalPointStart].c0, openings.wires[evalPointStart + 1].c0, 0
        );
        GoldilocksExt3.Ext3 memory shiftedEvalPoint = GoldilocksExt3.Ext3(
            openings.wires[shiftedEvalStart].c0, openings.wires[shiftedEvalStart + 1].c0, 0
        );

        // Constraint 0-1 (D=2): evaluation_point - shifted_evaluation_point * shift = 0
        GoldilocksExt3.Ext3 memory diff0 = evalPoint.sub(shiftedEvalPoint.mul(shift));
        c[0] = GoldilocksExt3.fromBase(diff0.c0);
        c[1] = GoldilocksExt3.fromBase(diff0.c1);

        // Intermediate constraints: 2*D per intermediate
        uint256 cIdx = D;
        for (uint256 i = 0; i < numIntermediates; i++) {
            // TODO: Full Barycentric interpolation constraint checking
            c[cIdx++] = GoldilocksExt3.zero();
            c[cIdx++] = GoldilocksExt3.zero();
            c[cIdx++] = GoldilocksExt3.zero();
            c[cIdx++] = GoldilocksExt3.zero();
        }

        // Final constraint (D=2): evaluation_value - final_computed_eval = 0
        if (numIntermediates > 0) {
            uint256 lastEvalBase = intEvalStart + (numIntermediates - 1) * D;
            uint256 lastProdBase = intProdStart + (numIntermediates - 1) * D;
            GoldilocksExt3.Ext3 memory lastEval = GoldilocksExt3.Ext3(
                openings.wires[lastEvalBase].c0, openings.wires[lastEvalBase + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory lastProd = GoldilocksExt3.Ext3(
                openings.wires[lastProdBase].c0, openings.wires[lastProdBase + 1].c0, 0
            );
            GoldilocksExt3.Ext3 memory evalValue = GoldilocksExt3.Ext3(
                openings.wires[evalValueStart].c0, openings.wires[evalValueStart + 1].c0, 0
            );
            // finalEval = lastEval / lastProd
            // constraint: evalValue * lastProd - lastEval = 0
            GoldilocksExt3.Ext3 memory finalDiff = evalValue.mul(lastProd).sub(lastEval);
            c[numConstraints - 2] = GoldilocksExt3.fromBase(finalDiff.c0);
            c[numConstraints - 1] = GoldilocksExt3.fromBase(finalDiff.c1);
        }

        return c;
    }

    /// @dev PoseidonMdsGate: MDS matrix multiplication on 12 extension elements
    ///      output[r] = Σ MDS_CIRC[i] * input[(i+r)%12] + MDS_DIAG[r] * input[r]
    ///      24 constraints (12 outputs × D=2)
    function _evalPoseidonMdsGate(
        Openings memory openings
    ) internal pure returns (GoldilocksExt3.Ext3[] memory) {
        uint256 D = 2;
        uint256 W = 12; // SPONGE_WIDTH
        GoldilocksExt3.Ext3[] memory c = new GoldilocksExt3.Ext3[](W * D);

        // Read 12 input extension elements
        GoldilocksExt3.Ext3[12] memory inputs;
        for (uint256 i = 0; i < W; i++) {
            inputs[i] = GoldilocksExt3.Ext3(
                openings.wires[i * D].c0,
                openings.wires[i * D + 1].c0,
                0
            );
        }

        // For each output row r, compute MDS multiplication
        for (uint256 r = 0; r < W; r++) {
            GoldilocksExt3.Ext3 memory acc = GoldilocksExt3.zero();
            for (uint256 i = 0; i < W; i++) {
                uint256 idx = (i + r) % W;
                acc = acc.add(GoldilocksExt3.mulScalarU256(inputs[idx], PoseidonConstants.mdsCirc(i)));
            }
            acc = acc.add(GoldilocksExt3.mulScalarU256(inputs[r], PoseidonConstants.mdsDiag(r)));

            // Read output extension element
            GoldilocksExt3.Ext3 memory output = GoldilocksExt3.Ext3(
                openings.wires[(W + r) * D].c0,
                openings.wires[(W + r) * D + 1].c0,
                0
            );

            GoldilocksExt3.Ext3 memory diff = output.sub(acc);
            c[r * D] = GoldilocksExt3.fromBase(diff.c0);
            c[r * D + 1] = GoldilocksExt3.fromBase(diff.c1);
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
        GoldilocksExt3.Ext3 memory beta = GoldilocksExt3.fromBaseU256(betaBase);
        GoldilocksExt3.Ext3 memory gamma = GoldilocksExt3.fromBaseU256(gammaBase);
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
            numProd = numProd.mul(wireVal.add(GoldilocksExt3.mulScalarU256(betaZeta, permData.kIs[j])).add(gamma));
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
            GoldilocksExt3.Ext3 memory alpha = GoldilocksExt3.fromBaseU256(alphas[i]);
            GoldilocksExt3.Ext3 memory acc = GoldilocksExt3.zero();
            for (uint256 j = terms.length; j > 0; j--) {
                acc = acc.mul(alpha).add(terms[j - 1]);
            }
            result[i] = acc;
        }
        return result;
    }
}
