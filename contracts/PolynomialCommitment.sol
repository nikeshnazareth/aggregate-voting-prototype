//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "./BN256Adapter.sol";
import "./TrustedSetup.sol";

/**
 * This contract provides convenience functions to create and interact with Polynomial commitments,
 * which is a mechanism of fingerprinting a large amount of data. In particular, it implements
 * Kate commitments (https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
 *
 * In contrast to hash commitments and Merkle trees, it is possible to prove that a Kate commitment
 * contains a particular piece of data in constant time. The tradeoff is that it takes linear
 * time to construct the proof, and it requires a trusted setup. This tradeoff makes sense in a
 * blockchain context since proofs can be constructed off-chain and verified efficiently on-chain.
 *
 * Kate commitments are also partially homomorphic. This is a fancy term for a straightforward
 * (but extraordinarily powerful) pair of properties:
 *   1. If A is the commitment to data array [ a0, a1, a2, ...] then
 *      x⋅A is the commitment to data array [ x⋅a0, x⋅a1, x⋅a2, ...] for any constant x
 *   2. If A and B are commitments to two data arrays [ a0, a1, a2, ...] and [ b0, b1, b2, ...] then
 *      A + B is the commitment to data array [ a0 + b0, a1 + b1, a2 + b2, ...]
 * In other words, it is possible to add commitments to each other, and multiply them by constants,
 * and this will have the same effect as performing those operations on the original data and then
 * computing the resulting commitment
 */
contract PolynomialCommitment {
    using BN256Adapter for BN256Adapter.PointG1;
    using BN256Adapter for BN256Adapter.PointG2;

    uint256 public DATA_ARRAY_SIZE;

    // This provides the powers of s, for a secret value s, in both groups
    // These values are used to construct the commitments
    TrustedSetup internal trustedSetup;

    /**
     * @notice set the TrustedSetup contract that will be used to generate commitments
     */
    constructor(TrustedSetup _trustedSetup) public {
        trustedSetup = _trustedSetup;

        // During the aggregate vote operation the aggregator will need to
        // multiply two commitments together. Each commitment can be thought of as
        // a degree n polynomial evaluated at secret point s:
        //   C1 = a0 + (a1)s + (a2)s^2 + ... + (an)s^n
        //   C2 = b0 + (b1)s + (b2)s^2 + ... + (bn)s^n
        // Their product is a degree 2n polynomial: the highest term is (an)(bn)s^(2n)
        // To ensure this can be evaluated, 2n cannot exceed MAX_DEGREE
        // Therefore, n cannot exceed MAX_DEGREE / 2
        // We can commit n+1 values including the degree zero term.
        DATA_ARRAY_SIZE = _trustedSetup.MAX_DEGREE() / 2 + 1;
    }

    /**
     * @notice Create a polynomial commitment in group 1 to a data array with a single non-zero value
     * @dev the commitment is equal to (value)(s^index)⋅[P1]
     * @param value the value to commit to
     * @param index the index of the non-zero value
     * @return the corresponding polynomial commitment
     */
    function _commitSingleValueG1(uint256 value, uint256 index)
        internal
        view
        returns (BN256Adapter.PointG1 memory)
    {
        // In a production system, the contract could create more commitments
        // to accomodate more keys. If there are K commitments, every
        // BN256Adapter.PairingEquation in this codebase would correspond to K
        // PairingEquations in the generalized version
        require(index < DATA_ARRAY_SIZE);
        return trustedSetup.S1(index).multiply(value);
    }

    /**
     * @notice Create a polynomial commitment in group 2 to a data array with a single non-zero value
     * @dev the commitment is equal to (value)(s^index)⋅[P2]
     * @param value the value to commit to
     * @param index the index of the non-zero value
     * @return the corresponding polynomial commitment
     */
    function _commitSingleValueG2(uint256 value, uint256 index)
        internal
        view
        returns (BN256Adapter.PointG2 memory)
    {
        // In a production system, the contract could create more commitments
        // to accomodate more keys. If there are K commitments, every
        // BN256Adapter.PairingEquation in this codebase would correspond to K
        // PairingEquations in the generalized version
        require(index < DATA_ARRAY_SIZE);
        return trustedSetup.S2(index).multiply(value);
    }

    /**
     * @notice Constructs pairing equations to test whether the value commitment corresponds to a data array with
     * a single non-zero value at the specified index. The two proof elements should be commitments to the
     * same data array except the non-zero value is in the first and last position respectively.
     * ie. if the value commitment corresponds to data array D = [0, 0, ..., 0, X, 0, ..., 0] then
     *  - first corresponds to data array F = [X, 0, 0, ...] and
     *  - last corresponds to data array L = [0, 0, ..., X]
     * @dev internally, this produces two shift equations. If it is possible to construct a commitment (first)
     * that corresponds to D shifted left by index number of positions, then D cannot have non-zero terms before index.
     * Similarly, if it's possible to construct a commitment (last) that corresponds to F shifted right by MAX_DEGREE
     * positions, then F must be zero at all non-zero indices. These two properties imply D has (at most) a single
     * non-zero term at the specified index.
     * @param valueCommitment a polynomial commitment to a data array with a single non-zero value
     * @param index the index of the non-zero value in the data array
     * @param first a polynomial commitment to a data array with the same non-zero value in the first position (and zero elsewhere)
     * @param last a polynomial commitment to a data array with the same non-zero value in the last position (and zero elsewhere)
     * @return two pairing equations that validate the consistency of these conditions
     */
    function _isSingleValueEquations(
        BN256Adapter.PointG2 memory valueCommitment,
        uint256 index,
        BN256Adapter.PointG2 memory first,
        BN256Adapter.PointG2 memory last
    ) internal view returns (BN256Adapter.PairingEquation[2] memory) {
        return [
            _isShiftEquation(first, valueCommitment, index),
            _isShiftEquation(first, last, trustedSetup.MAX_DEGREE())
        ];
    }

    /**
     * @notice Constructs a pairing equation that tests whether the right commitment corresponds to the same
     * data array (R) as the left one (L) after shifting the array right by delta positions.
     * The equation will succeed if every L[i] corresponds to R[i+delta] and unmatched elements (at the start
     * of R and the end of L) are zero.
     * @param left a polynomial commitment of some data array
     * @param right a claimed polynomial commitment to a right-shifted version of the same data array
     * @param delta the size of the shift
     */
    function _isShiftEquation(
        BN256Adapter.PointG2 memory left,
        BN256Adapter.PointG2 memory right,
        uint256 delta
    ) internal view returns (BN256Adapter.PairingEquation memory) {
        // meaningful data arrays are restricted to DATA_ARRAY_SIZE, but safety checks span the whole MAX_DEGREE
        require(delta <= trustedSetup.MAX_DEGREE(), "array shift too large for trusted setup");

        // if L is a data array [ d0, d1, d2, ... ] then its commitment is
        // left = l⋅[P2] where l = d0 + (d1)(s) + (d2)(s^2) + ...
        // if R is the same data array right shifted [ 0, 0, ... , d0, d1, d2, ...], its commitment is
        // right = r⋅[P2] where r = (d0)(s^delta) + (d1)(s^(delta+1)) + d2(s^(delta+2)) + ....
        // => r = (s^delta)(d0 + (d1)(s) + (d2)(s^2) + ...)
        // => r = (s^delta)(l)
        // so the pairing equation is
        //    e((s^delta)⋅[P1], left)*e(-1⋅[P1], right) = 1
        // => e((s^delta)⋅[P1], l⋅[P2])*e(-1⋅[P1], r⋅[P2]) = 1
        // this should be interpreted as
        //    (s^delta)(l) + (-1)(r) = 0
        // => r = (s^delta)(l)
        return
            BN256Adapter.PairingEquation({
                A: trustedSetup.S1(delta),
                B: left,
                C: BN256Adapter.negP1(),
                D: right
            });
    }
}
