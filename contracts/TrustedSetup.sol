//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;


import "./BN256Adapter.sol";
import "./BN256G1.sol";

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

contract TrustedSetup {
    using BN256Adapter for BN256Adapter.PointG1;
    using BN256Adapter for BN256Adapter.PointG2;

    // in a real system, this could be in the millions
    uint256 constant public MAX_DEGREE = 10;

    // the powers of the secret value s in group G1
    // S[i] = (s^i)⋅[P1]
    BN256Adapter.PointG1[MAX_DEGREE + 1] public S;

    // the value s⋅[P2], which is used to verify updates to S.
    BN256Adapter.PointG2 public verifierArtifact;

    /**
     * @notice Initialize all S values to P1, which implicitly
     * sets the secret s to 1.
     */
    constructor() public {
        for(uint256 i = 0; i <= MAX_DEGREE; i++) {
            S[i] = BN256Adapter.P1();
        }
        verifierArtifact = BN256Adapter.P2();
    }

    /**
     * @notice Generates an update proof to add entropy k to the trusted setup
     * The secret s will be replaced with s' = ks
     * @dev the k value is a secret and should not be revealed.
     * This is a view function, so it will be executed locally as long as it is called
     * in an isolated transaction (or with other view functions)
     * However, the value will be revealed to the local node as well as
     * anyone listening on the communication channel. Therefore, it should only
     * be executed using trusted local infrastructure.
     * @param k the entropy to add to the trusted setup
     * @return the updated powers of s
     * @return the update proof PointG1 k⋅[P1], which is used to prove that this update is valid
     * @return the verifier artifact PointG2 s'⋅[P2]  ( or (ks)⋅[P2] ), which is used to verify consistency of the updates
     */
    function generateUpdateProof(uint256 k) public view
        returns (BN256Adapter.PointG1[MAX_DEGREE+1] memory , BN256Adapter.PointG1 memory, BN256Adapter.PointG2 memory){
        BN256Adapter.PointG1[MAX_DEGREE+1] memory updatedS;

        uint256 powerOfK;
        for (uint256 degree = 0; degree <= MAX_DEGREE; degree++) {
            powerOfK = _modExp(k, degree, BN256Adapter.GROUP_ORDER);
            updatedS[degree] = S[degree].multiply(powerOfK);
        }

        return (updatedS, BN256Adapter.P1().multiply(k), verifierArtifact.multiply(k));
    }

    /**
     * @notice Replaces S with updatedS after verifying consistency
     * @dev The parameters can be obtained directly from the `generateUpdateProof` function.
     * However, as noted in its function comments, it should be called in a separate transaction
     * to avoid revealing k.
     * @param updatedS the updated S values. updatedS[i] should be (s'^i)⋅[P1]
     * @param proof the value k⋅[P1]. This is used to demonstrate the new secret s' is sk (ie. the original entropy has not been discarded)
     * @param updatedVerifierArtifact the value s'⋅[P2]. This is used to validate the consistency of the updates
     */
    function update(
        BN256Adapter.PointG1[MAX_DEGREE+1] memory updatedS,
        BN256Adapter.PointG1 memory proof,
        BN256Adapter.PointG2 memory updatedVerifierArtifact
    ) public {
        BN256Adapter.PairingEquation[] memory equations = new BN256Adapter.PairingEquation[](MAX_DEGREE+1);

        // prove that the updated verifier artifact is (ks)⋅[P2] for some k (ie. the original s has not been discarded)
        // we're checking the equation
        //    e(proof, s⋅[P2])*e(-1⋅[P1], updatedVerifierArtifact) = 1
        // using k and x as the unknown coefficients, this becomes
        //    e(k⋅[P1], s⋅[P2])*e(-1⋅[P1], x⋅[P2]) = 1
        // this  should be interpreted as
        //   (k)(s) + (-1)(x) = 0
        // => x = ks
        equations[0] = BN256Adapter.PairingEquation({
            A: proof, // claimed to be k⋅[P1]
            B: verifierArtifact, // known to be s⋅[P2]
            C: BN256Adapter.negP1(), // known to be -1⋅[P1]
            D: updatedVerifierArtifact // claimed to be (ks)⋅[P2]
        });

        // the first term is redundant because S[0] never changes (it's always P1)
        // it's included anyway to simplify the interface
        require(
            updatedS[0].x == BN256Adapter.P1().x &&
            updatedS[0].y == BN256Adapter.P1().y,
            "Invalid degree zero term. It should be P1"
        );
        for(uint256 degree = 1; degree <= MAX_DEGREE; degree++) {
            // we want to demonstrate that updatedS[degree] = ((ks)^degree)⋅[P1]
            // we can build this from the previous term by proving that
            // updatedS[degree] = (ks)*updatedS[degree - 1]
            // we're checking the equation
            //    e(((ks)^(degree-1))⋅[P1], (ks)⋅[P2])*e(updatedS[degree], -1⋅[P2]) = 1
            // using x as the unknown coefficient, this becomes
            //    e(((ks)^(degree-1))⋅[P1], (ks)⋅[P2])*e(x⋅[P1], -1⋅[P2]) = 1
            // this should be interpreted as
            //    (ks)^(degree-1)(ks) + (x)(-1) = 0
            // => x = (ks)^degree
            equations[degree] = BN256Adapter.PairingEquation({
                A: updatedS[degree - 1], // known to be ((ks)^(degree-1))⋅[P1] (assuming equations[degree - 1] holds)
                B: updatedVerifierArtifact, //known to be (ks)⋅[P2] (assuming equations[0] holds)
                C: updatedS[degree], // claimed to be ((ks)^degree)⋅[P1]
                D: BN256Adapter.negP2() // known to be -1⋅[P2]
            });
        }

        require(BN256Adapter.verifyPairingEquations(equations), "Cannot update S. Invalid proofs provided");

        verifierArtifact = updatedVerifierArtifact;
        for(uint256 i = 0; i < updatedS.length; i++) {
            S[i] = updatedS[i];
        }
    }

    function _modExp(uint256 base, uint256 exponent, uint256 modulus) private view returns (uint256) {
        // all values are 32-bytes long
        bytes memory input = abi.encode(32, 32, 32, base, exponent, modulus);
        // the output will be less than modulus, so it will fit in a single word
        uint256[1] memory output;

        bool success;
        assembly {
            // modular exponentiation precompile (https://eips.ethereum.org/EIPS/eip-198)
            success := staticcall(not(0), 0x05, add(input, 0x20), mload(input), output, 0x20)
        }
        require(success, "modular exponentiation failed");
        return output[0];
    }
}
