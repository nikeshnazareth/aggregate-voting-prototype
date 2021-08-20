//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "./BN256Adapter.sol";
import "./CommitmentToken.sol";

/**
 * A voting contract that uses Polynomial Commitments to record the user balances and
 * BLS public keys. This lets anyone collect votes off-chain and submit an aggregate commitment,
 * while proving the individual votes were signed by the relevant users. Subsequently, it allows
 * anyone to compute the final tally and prove that it matches the committed votes.
 *
 * This contract implements the simplest version of the scheme, where:
 * - all users are represented by the BLS Keys Commitment. If desired, the mechanism can be generalized
 *   to allow some users to provide ECDSA (regular Ethereum address-based) authentication without aggregation,
 *   while the users with BLS keys can utilize the aggregation benefits
 * - votes are not hidden during the voting procedure. If hidden votes are required, the BlindedAggregateVoting
 *   contract in this repository supports that use case.
 */
contract AggregateVoting {

    // The Kate commitment representing an ordered list of user balances
    BN256Adapter.PointG1 public BalancesCommitment;

    // The Kate commitment representing an ordered list of user BLS public keys.
    // The key at position i is authorized to vote with the tokens at position i in BalancesCommitment
    BN256Adapter.PointG2 public KeysCommitment;

    // The question that users are voting on
    string public topic;
    constructor(CommitmentToken _token, string memory _topic) public {

        // Copy the commitments from the token. This effectively snapshots the balances since subsequent
        // token transfers will not update these commitments. The voter aggregator will need to know the
        // values associated with these commitments, even if the token updates its internal balances.
        // It is assumed they have a mechanism.
        BalancesCommitment = _token.BalancesCommitment();
        KeysCommitment = _token.KeysCommitment();

        topic = _topic;
    }
}