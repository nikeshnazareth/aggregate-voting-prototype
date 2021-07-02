//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./BN256Adapter.sol";

/**
 * Simulates a wallet that uses BLS signatures
 * 
 * WARNING: this is intended for illustrative purposes only. It is insecure.
 * The PRIVATE_KEY is neither random, nor private.
 * Do not use this contract in production code
 */
contract SimulatedBLSWallet {
  using BN256Adapter for BN256Adapter.PointG1;

  uint256 private PRIVATE_KEY;
  BN256Adapter.PointG1 public PUBLIC_KEY;

  constructor(string memory _name) public {
    // a simple hack to create a unique predictable value.
    PRIVATE_KEY = uint256(keccak256(bytes(_name)));
    
    PUBLIC_KEY = BN256Adapter.P1().multiply(PRIVATE_KEY);
  }
}
