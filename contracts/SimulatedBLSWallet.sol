//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Alt_BN128Library.sol";

/**
 * Simulates a wallet that uses BLS signatures
 * 
 * WARNING: this is intended for illustrative purposes only. It is insecure.
 * The PRIVATE_KEY is neither random, nor private.
 * Do not use this contract in production code
 */
contract SimulatedBLSWallet {
  using Alt_BN128Library for Alt_BN128Library.Point_G1;

  uint256 private PRIVATE_KEY;

  Alt_BN128Library.Point_G1 public PUBLIC_KEY;

  constructor(string memory _name) {
    PRIVATE_KEY = uint256(keccak256(bytes(_name)));
    PUBLIC_KEY = Alt_BN128Library.P1().mul(PRIVATE_KEY);
  }
}
