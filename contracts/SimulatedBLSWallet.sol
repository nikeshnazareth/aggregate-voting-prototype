//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;


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
  using BN256Adapter for BN256Adapter.PointG2;

  uint256 private PRIVATE_KEY;
  BN256Adapter.PointG2 public PUBLIC_KEY;

  /**
   * @notice Set PRIVATE_KEY to the hash of the _name
   * PUBLIC_KEY = PRIVATE_KEY⋅[P2]
   */
  constructor(string memory _name) public {
    // a simple hack to create a unique predictable value.
    PRIVATE_KEY = uint256(keccak256(bytes(_name)));

    PUBLIC_KEY = BN256Adapter.P2().multiply(PRIVATE_KEY);
  }

  /**
   * @notice produce a BLS signature over _message
   * @dev the hash function used has a small probability of reverting
   * if a suitable point cannot be found.
   * The hash can be thought of as H = 𝛿⋅[P1] for an unknown 𝛿
   * The signature would then be PRIVATE_KEY⋅𝛿⋅[P1]
   * The signature can be verified with BN256Adapter.verify
   * To take advantage of BLS aggregation:
   *   - multiple signatures can be aggregated with BN256Adapter.sum (PointG1 version)
   *   - the corresponding public keys can be aggregated with BN256Adapter.sum (PointG2 version)
   *     this produces the matching public key for the aggregate signature
   *   - the aggregate signature can be verified like a normal signature
   * @param _message the message to be signed
   * @return the BLS signature
   */
  function sign(bytes memory _message) public view returns (BN256Adapter.PointG1 memory) {
    BN256Adapter.PointG1 memory msgHash = BN256Adapter.hashToG1(_message);
    return msgHash.multiply(PRIVATE_KEY);
  }
}
