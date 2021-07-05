//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;


import "../BN256Adapter.sol";

/**
 * This contract provides helper functions to support unit tests
 * In particular, it provides a mechanism to interact with the BN256Adapter library directly
 */

contract TestHelper {
    /**
     * Pass-through function for BN256Adapter.verify
     */
    function verify(
        bytes memory _message,
        BN256Adapter.PointG1 memory _signature,
        BN256Adapter.PointG2 memory _publicKey
        ) public view returns (bool) {
            return BN256Adapter.verify(_message, _signature, _publicKey);
     }
     /**
     * Pass-through functions for BN256Adapter.sum (both versions)
     */
    function sumG1(BN256Adapter.PointG1[] memory Points) public view returns (BN256Adapter.PointG1 memory) {
        return BN256Adapter.sum(Points);
     }
     function sumG2(BN256Adapter.PointG2[] memory Points) public view returns (BN256Adapter.PointG2 memory) {
        return BN256Adapter.sum(Points);
     }
     /**
     * Pass-through functions for BN256Adapter.multiply (both versions)
     */
     function multiplyG1(BN256Adapter.PointG1 memory Point, uint256 scalar) public view returns (BN256Adapter.PointG1 memory) {
         return BN256Adapter.multiply(Point, scalar);
     }
     function multiplyG2(BN256Adapter.PointG2 memory Point, uint256 scalar) public view returns (BN256Adapter.PointG2 memory) {
         return BN256Adapter.multiply(Point, scalar);
     }
}
