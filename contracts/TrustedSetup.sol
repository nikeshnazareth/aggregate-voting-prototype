//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;


import "./BN256Adapter.sol";

/**
 * Simulates a simple trusted setup that can be used with
 * Kate commitments (https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
 *
 * It produces the powers of s, for a secret value s, in group 1 (G1) of BN256Adapter.sol
 *   ie. it produces [P1], s⋅[P1], (s^2)⋅[P1], (s^3)⋅[P1], ...
 * Note that a property of the group is that s can remain secret, even if s⋅[P1] is known.
 *
 * This is a universal scheme. It is not specialized for any particular protocol
 * (aggregate voting, in our case), which means it can be reused across many protocols.
 * In practice, if this protocol is adopted, we will likely reuse the trusted setup from ETH 2.0
 *
 * This is also an updateable scheme. It is critically important for security that nobody knows
 * the secret value s, but the entropy used to generate it is provided by individual contributors.
 * This means that users need to trust that at least one contributor securely deleted their entropy.
 * For maximum assurance, users can contribute their own entropy to update s.
 * Once enough users have contributed, or a time limit is reached, the setup can be adopted.
 *
 * The setup should not change during a particular use case, but as long as users can coordinate, 
 * it can change between different instances of the protocol (eg. for different votes).
 * This means that the setup can be refreshed every few months (for example) to continuously
 * allow new contributors to provide entropy.
 */

 import "hardhat/console.sol";
contract TrustedSetup {

    // in a real system, this could be in the millions
    uint256 constant public MAX_DEGREE = 10;

    // the powers of the secret value s in group G1
    // S[i] = (s^i)⋅[P1]
    BN256Adapter.PointG1[MAX_DEGREE + 1] public S;

    /**
     * @notice Initialize all S values to P1, which implicitly
     * sets the secret s to 1.
     */
    constructor() public {
        for(uint256 i = 0; i <= MAX_DEGREE; i++) {
            S[i] = BN256Adapter.P1();
        }
    }

    

}