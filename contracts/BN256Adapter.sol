//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "bls-solidity/contracts/BN256G1.sol";

/**
 * The BN256G1 library provides convenience functions to perform elliptic curve operations
 * However, the interface is optimized for efficiency rather than clarity
 * Since the goal of this prototype is to explain the Aggregate Voting proposal, a more
 * descriptive interface is preferable. This library provides that interface
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

    // The group 1 (G1) generator defined in EIP197 (https://eips.ethereum.org/EIPS/eip-197)
    function P1() internal returns (PointG1 memory) {
        return PointG1({
            x: BN256G1.GX,
            y: BN256G1.GY
        });
    }

    /**
     * @notice computes scalar * Point
     * @param Point the elliptic curve point to multiply
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

}
