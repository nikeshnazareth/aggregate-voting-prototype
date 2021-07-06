# Aggregate Voting Prototype

## Overview

This project is intended to develop and illustrate an idea, [shared on ETH research](https://ethresear.ch/t/kate-commitments-for-aggregated-off-chain-voting/9682), for a voting token that allows users to aggregate their votes off-chain, and efficiently prove the result on chain.

Briefly, the idea is:

- the token contract can save a [Kate commitment](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) of the balances.
- users can sign their votes and publish them off-chain.
- anyone can collect any subset of these votes to produce an aggregate vote commitment.
- if the votes were signed with BLS signatures, the contract can validate that the vote commitment correctly captures all the votes in constant time, regardless of the number of the voters.
- anyone can locally calculate the final tally and publish the result on-chain. The contract can validate the result in constant time.
- there is an additional mechanism to allow blinded votes (ie. to use a commit-reveal scheme). This requires more off-chain coordination, but it retains the basic property that it is efficient to validate the results on-chain.

The main disadvantages are:

- Wallets that support BLS signatures are uncommon within the Ethereum ecosystem. There is minimal advantage to aggregating votes if the contract needs to validate individual ECDSA signatures (although there may still be a modest gas saving as a result of avoiding storage lookups to retrieve the balances).
- Kate commitments rely on infrastructure (a trusted setup and elliptic curve precompiles) that is not fully mature in the Ethereum ecosystem. It should be noted that the infrastructure is being developed anyway to support ETH 2.0 and SNARKS.
- There are some loopholes in the design that need to be closed, ideally by someone with more experience than me.

## Usage

This project is intended to be illustrative rather than functional. Therefore, the intended usage is simply to review the contracts and run the tests (with the `npx hardhat test` command) to understand the idea and its implementation.

## Contact

If you would like to discuss the idea, or suggest improvements, please contact me at nikesh@openzeppelin.com