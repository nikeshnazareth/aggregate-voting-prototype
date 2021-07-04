//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "./BN256G1.sol";
import "./BN256G2.sol";

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

    // the q value in EIP-197 (https://eips.ethereum.org/EIPS/eip-197)
    uint256 constant GROUP_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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
    function P1() public pure returns (PointG1 memory) {
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
    function P2() public pure returns (PointG2 memory) {
        return PointG2({
            x_real: BN256G2.G2_NEG_X_RE,
            x_imag: BN256G2.G2_NEG_X_IM,
            y_real: BN256G2.FIELD_MODULUS - BN256G2.G2_NEG_Y_RE,
            y_imag: BN256G2.FIELD_MODULUS - BN256G2.G2_NEG_Y_IM
        });
    }

    /**
     * @notice computes scalar * Point
     * @param Point the elliptic curve point (in G1) to multiply
     * @param scalar the multiplier to use
     * @return the G1 point (scalar * Point)
     */
    function multiply(PointG1 memory Point, uint256 scalar) public view returns (PointG1 memory) {
        uint256[3] memory input = [
            Point.x,
            Point.y,
            scalar % GROUP_ORDER
        ];
        (uint256 x, uint256 y) = BN256G1.multiply(input);
        return PointG1({x: x, y: y});
    }

    /**
     * @notice computes scalar * Point
     * @param Point the elliptic curve point (in G2) to multiply
     * @param scalar the multiplier to use
     * @return the G2 point (scalar * Point)
     */
    function multiply(PointG2 memory Point, uint256 scalar) public view returns (PointG2 memory) {
        (uint256 xr, uint256 xi, uint256 yr, uint256 yi) = 
            BN256G2.ecTwistMul(scalar %  GROUP_ORDER, Point.x_real, Point.x_imag, Point.y_real, Point.y_imag);
        return PointG2({x_real: xr, x_imag: xi, y_real: yr, y_imag: yi});
    }

    /**
     * @notice computes the sum of all the points
     * @dev Points must have at least one item
     * @param Points the list of elliptic curve points (in G1) to add
     * @return the G1 point corresponding to the sum of the input points
     */
    function sum(PointG1[] memory Points) public view returns (PointG1 memory) {
        require(Points.length > 0, "Cannot sum empty list");
        PointG1 memory sum = Points[0];

        uint256[4] memory input;
        for(uint256 i = 1; i < Points.length; i++) {
            input = [
                sum.x,
                sum.y,
                Points[i].x,
                Points[i].y
            ];
            (uint256 x, uint256 y) = BN256G1.add(input);
            sum = PointG1({x: x, y: y});
        }
        return sum;
    }

    /**
     * @notice computes the sum of all the points
     * @dev Points must have at least one item
     * @param Points the list of elliptic curve points (in G2) to add
     * @return the G2 point corresponding to the sum of the input points
     */
    function sum(PointG2[] memory Points) public view returns (PointG2 memory) {
        require(Points.length > 0, "Cannot sum empty list");
        PointG2 memory sum = Points[0];

        for(uint256 i = 1; i < Points.length; i++) {
            (uint256 xr, uint256 xi, uint256 yr, uint256 yi) =
                BN256G2.ecTwistAdd(
                    sum.x_real, sum.x_imag, sum.y_real, sum.y_imag,
                    Points[i].x_real, Points[i].x_imag, Points[i].y_real, Points[i].y_imag
                );
            sum = PointG2({x_real: xr, x_imag: xi, y_real: yr, y_imag: yi});
        }
        return sum;
    }

    /**
     * @notice uses the `_message` as a seed to produce a psuedorandom point on G1
     * @dev this will check 256 psuedorandom x values to see if it maps to a point on G1
     * The first valid point is returned. The function reverts if no valid points are found
     * @return a pseudorandom point in G1
     */
    function hashToG1(bytes memory _message) public pure returns (PointG1 memory) {
        (uint256 x, uint256 y) = BN256G1.hashToTryAndIncrement(_message);
        return PointG1({x: x, y: y});
    }

    /**
     * @notice validates whether the inputs correspond to a valid BLS signature
     * @dev the hash of the message can be thought of as H = (𝛿 * P1) for an unknown 𝛿
     * The signature would then be (PRIVATE_KEY * 𝛿 * P1)
     * The public key is given by (PRIVATE_KEY * P2)
     * If e is an elliptic curve pairing from G1 x G2 -> GT, the function validates whether
     * e(H, _publicKey) == (signature, P2) or equivalently,
     * e(𝛿 * P1, PRIVATE_KEY * P2) == e(PRIVATE_KEY * 𝛿 * P1, P2)
     * Both sides should evaluate to PRIVATE_KEY * 𝛿 * GT
     * @param _message the message that was signed
     * @param _signature the signature of the message
     * @param _publicKey the public key corresponding to the private key that signed the message
     * @return whether the signature is valid
     */
    function verify(bytes memory _message, PointG1 memory _signature, PointG2 memory _publicKey) public view returns (bool) {
        PointG1 memory msgHash = hashToG1(_message);
        uint256[12] memory input = [
            msgHash.x,
            msgHash.y,
            _publicKey.x_imag,
            _publicKey.x_real,
            _publicKey.y_imag,
            _publicKey.y_real,
            _signature.x,
            _signature.y,
            // `bn256CheckPairing` evaluates whether the two points multiply to 1 (they are inverses)
            // Therefore, we use -P2 instead of P2.
            BN256G2.G2_NEG_X_IM,
            BN256G2.G2_NEG_X_RE,
            BN256G2.G2_NEG_Y_IM,
            BN256G2.G2_NEG_Y_RE
        ];

        return BN256G1.bn256CheckPairing(input);
    }
}
