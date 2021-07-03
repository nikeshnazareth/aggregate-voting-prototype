//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "bls-solidity/contracts/BN256G1.sol";
import "bls-solidity/contracts/BN256G2.sol";

/**
 * The BN256G1 and BN256G2 libraries provides convenience functions to perform 
 * elliptic curve operations. However, the interface is optimized for efficiency
 * rather than clarity. Since the goal of this prototype is to explain the 
 * Aggregate Voting proposal, a more descriptive interface is preferable. 
 * This library provides that interface.
 *
 * Note that the EIP2537 (https://eips.ethereum.org/EIPS/eip-2537) will add support for
 * new precompiles that will remove the need for an elliptic curve library.
 * In particular, EIP-196 (https://eips.ethereum.org/EIPS/eip-196) and 
 * EIP197 (https://eips.ethereum.org/EIPS/eip-197) introduced precompiles for the BN256
 * curve, but they only support addition and multiplication operations on the G1 group 
 * used in the pairing. EIP2537 supports the BLS12-381 curve, and also introduces precompiles
 * for addition and multiplication on the G2 group.
 */
library BN256Adapter {

    struct PointG1 {
        uint256 x;
        uint256 y;
    }

    struct PointG2 {
        uint256 x_real;
        uint256 x_imag;
        uint256 y_real;
        uint256 y_imag;
    }

    /**
     * @dev The generators are defined in EIP197 (https://eips.ethereum.org/EIPS/eip-197)
     * @return The group 1 (G1) generator 
     */
    function P1() internal returns (PointG1 memory) {
        return PointG1({
            x: BN256G1.GX,
            y: BN256G1.GY
        });
    }

    /**
     * @dev The generators are defined in EIP197 (https://eips.ethereum.org/EIPS/eip-197)
     * The BN256G2 library defines negative P2 because that simplifies pairing
     * Due to the curve's symmetry, -(x, y) = (x, -y) so we can recover P2 by negating the y value,
     * which is equivalent to (p - y) when working modulo p 
     * @return The group 2 (G2) generator 
     */
    function P2() internal returns (PointG2 memory) {
        return PointG2({
            // The BN256G2 library incorrectly swaps the real and imaginary components
            // This issue has been raised here: https://github.com/witnet/bls-solidity/pull/2
            // Until that is addressed, just swap them here
            x_real: BN256G2.G2_NEG_X_IM,
            x_imag: BN256G2.G2_NEG_X_RE,
            y_real: BN256G2.FIELD_MODULUS - BN256G2.G2_NEG_Y_IM,
            y_imag: BN256G2.FIELD_MODULUS - BN256G2.G2_NEG_Y_RE
        });
    }

    /**
     * @notice computes scalar * Point
     * @param Point the elliptic curve point (in G1) to multiply
     * @param scalar the multiplier to use
     */
    function multiply(PointG1 memory Point, uint256 scalar) internal returns (PointG1 memory) {
        uint256[3] memory input = [
            Point.x,
            Point.y,
            scalar % BN256G1.PP
        ];
        (uint256 x, uint256 y) = BN256G1.multiply(input);
        return PointG1({x: x, y: y});
    }

    /**
     * @notice computes scalar * Point
     * @param Point the elliptic curve point (in G2) to multiply
     * @param scalar the multiplier to use
     */
    function multiply(PointG2 memory Point, uint256 scalar) internal returns (PointG2 memory) {
        (uint256 xr, uint256 xi, uint256 yr, uint256 yi) = 
            BN256G2.ecTwistMul(scalar, Point.x_real, Point.x_imag, Point.y_real, Point.y_imag);
        return PointG2({x_real: xr, x_imag: xi, y_real: yr, y_imag: yi});
    }
}
