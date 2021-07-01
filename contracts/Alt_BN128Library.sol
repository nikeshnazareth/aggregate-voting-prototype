//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Provides utility functions to access the Alt_BN128 precompiles introduced in 
 * EIP-196 (https://eips.ethereum.org/EIPS/eip-196) and
 * EIP-197 (https://eips.ethereum.org/EIPS/eip-197)
 */
library Alt_BN128Library {
    struct Point_G1 {
        uint256 x;
        uint256 y;
    }

    // the prime that defines the field
    uint256 constant private p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    uint256 constant private MUL_PRECOMPILE_ADDRESS = 7;


    function mul(Point_G1 memory point, uint256 scalar) public view returns (Point_G1 memory output) {
        bytes memory input = abi.encode(point, scalar % p);

        bool success;
        assembly {
            success:= staticcall(gas(), MUL_PRECOMPILE_ADDRESS, add(input, 0x20), 0x60, output, 0x40)
        }
        require(success, "Alt_BN128Library: ECMUL failed");
    }

    function P1() public pure returns (Point_G1 memory) {
        return Point_G1({x: 1, y: 2});
    }
}