# Aggregate Voting Prototype

## Overview

This project is intended to develop and illustrate an idea, [shared on ETH research](https://ethresear.ch/t/kate-commitments-for-aggregated-off-chain-voting/9682), for a voting token that allows users to aggregate their votes off-chain, and efficiently prove the result on chain.

Briefly, the idea is:

- the token contract can save a [Kate commitment](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) of the balances.
- users can sign their votes and publish them off-chain.
- anyone can collect any subset of these votes to produce an aggregate vote commitment.
- if the votes were signed with BLS signatures, the contract can validate that the vote commitment correctly captures all the votes in constant time, regardless of the number of voters.
- anyone can locally calculate the final tally and publish the result on-chain. The contract can validate the result in constant time.
- there is an additional mechanism to allow blinded votes (ie. to use a commit-reveal scheme). This requires more off-chain coordination, but it retains the basic property that it is efficient to validate the results on-chain.

The main disadvantages are:

- Wallets that support BLS signatures are uncommon within the Ethereum ecosystem. There is minimal advantage to aggregating votes if the contract needs to validate individual ECDSA signatures (although there may still be a modest gas saving as a result of avoiding storage lookups to retrieve the balances).
- Kate commitments rely on infrastructure (a trusted setup and elliptic curve precompiles) that is not fully mature in the Ethereum ecosystem. It should be noted that the infrastructure is being developed anyway to support ETH 2.0 and SNARKs.
- There are some loopholes in the design that need to be closed, ideally by someone with more experience than me.
- There are several potential complications, depending on the implementation details, when using this mechanism with existing ERC20 tokens.

Separately, Kate commitments permit a different optimization: the corresponding data (eg. the user balances) can be stored off-chain and supplied to the contract when needed. The contract can validate that the data is correct in constant time. This is entirely optional and only makes sense for operations that access lots of storage locations (so the cost of the accesses exceeds the data verification costs).

## Usage

This project is intended to be illustrative rather than functional. Therefore, the intended usage is simply to review the contracts and run the tests (with the `npx hardhat test` command) to understand the idea and its implementation.

## Contact

If you would like to discuss the idea, or suggest improvements, please contact me at nikesh@openzeppelin.com

## A Fatal Design Flaw

While building this code base I identified a flaw in the design that may be fatal. The "dot product" mechanism, which is used to count votes, cannot also be used to determine the aggregate public key from the `KeysCommitment`. This is because the "dot product" requires the aggregator to produce a polynomial with irrelevant terms before selecting the relevant ones, and they would not have enough information to construct the irrelevant ones. Specifically:

- the original design incorrectly implies the BLS public keys are coefficients of the Keys polynomial (that `KeyCommitment` represents)
- this is a confusion, because BLS public keys are already elliptic curve points. Specifically, for private keys `a`, `b`, `c`, ..., the corresponding public keys are `a⋅[P2]`, `b⋅[P2]`, `c⋅[P2]`
- The public keys are revealed at the time of registration
- Moreover, when combined into a commitment (see the `register` function of the `CommitmentToken` contract), they become: <code>KeysCommitment = (as + bs<sup>2</sup> + cs<sup>3</sup> + ...)⋅[P2]</code>. The polynomial `Keys` could be notated with the coefficient array `[0, a, b, c, ...]`
- The goal is to efficiently produce the sum of the public keys for a specific subset of users, without iterating through each one individually.
- For example, if Alice and Charlie decide to aggregate their votes, they would create a "selection" polynomial with the coefficient array `[0, 1, 0, 1, 0, 0, ...]` (ie. 1s in the selected positions), which translates to <code>Selection = s + s<sup>3</sup></code>
- The goal is to use this selection to produce their aggregate public key `(a+c)⋅[P2]`.
- The design assumes they can take a dot product between `Selection` and the coefficient polynomial for `KeysCommitment`, but in practice this means:
    - reversing the coefficients in the selection
    - calculating  <code>Product = Selection<sub>reversed</sub> * Keys</code>
    - creating commitments for the `Product` and <code>Selection<sub>reversed</sub></code> polynomials
    - using the elliptic curve pairing to prove the relationship between these commitments
    - revealing the relevant term in `Product` that corresponds to the dot product
- Some of the terms in `Product` are unknown terms in `Keys` scaled by powers of `s`. In the particular example described here, the aggregator would need Bob's cooperation to calculate <code>(bs<sup>3</sup>)⋅[P2]</code> and <code>(bs<sup>5</sup>)⋅[P2]</code>, even though those terms will eventually be ignored.
- Since we cannot rely on the cooperation of users outside the selection, this mechanism does not work


Here are some ideas that are not full solutions, but may include ideas that can be further developed.

### Non-Solution: Require all scaled keys

When registering, the natural consistency checks requires user to reveal their public key at three degrees of scaling. In the example, Bob would reveal:
- his actual public key `b⋅[P2]`
- his public key at index 2 of the commitment <code>bs<sup>2</sup>⋅[P2]</code>
- his public key at the last index of the commitment <code>bs<sup>MAX_DEGREE</sup>⋅[P2]</code> where `MAX_DEGREE` is a property of the trusted setup

If all users revealed the equivalent values at all other positions, anyone would be able to select the appropriate version when computing the `Product` polynomial. This is unworkable because `MAX_DEGREE` could be in the millions.

### Non-Solution: Require user subsets to occur in ranges

Instead of doing a dot product, the users could publish the subset of `KeysCommitment` that corresponds to their keys. If the users had consecutive indices, the consistency checks could be combined. For example:
- Bob, Charlie and Diane form a subset
- They publish <code>(bs<sup>2</sup> + cs<sup>3</sup> + ds<sup>4</sup>)⋅[P2]</code>
    - note: anyone, including attackers, can construct this. That's fine. We're just trying to identify the relevant public keys. If an unwitting party is included, the eventual signature check would fail.
- This could be subtracted from the `KeyCommitment` to obtain <code>(as + es<sup>5</sup> + fs<sup>6</sup> + ...)⋅[P2]</code>
- The zero terms at indices 2-4 prove their subset commitment was calculated correctly
- To prove consistency, they just need to prove that:
    - the terms before index 2 are unchanged
    - the terms after index 4 are unchanged
    - the terms between indices 2 and 4 are zero
- This is efficient because these three checks don't change for any sized subset of users
- Since all terms in the subset commitment are known, they could prove consistency of the aggregate public key as before

This is undesirable because requiring user subsets to occur in ranges adds a lot of complexity. Moreover, a non-cooperative user in the middle of a subset would undermine the scheme, forcing the remaining users to form two subsets. This becomes more likely for very large subsets.