//SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "./BN256Adapter.sol";
import "./TrustedSetup.sol";
import "./PolynomialCommitment.sol";

/**
 * A token that saves a Polynomial Commitment to all the user balances. In other words,
 * BalancesCommitment is a single BN256Adapter.PointG1 value that represents an ordered
 * list of balances. This facilitates off-chain vote counting with efficient on-chain validation.
 *
 * In the version implemented here, the contract also tracks a KeysCommitment, which is a
 * BN256Adapter.PointG2 value that represents an ordered list of BLS public keys that can
 * vote with the tokens. The public key at position i in the KeysCommitment controls the tokens at position i
 * in the BalancesCommitment. This pattern facilitates off-chain vote aggregation with efficient
 * on-chain validation. This is ideal because efficient vote counting has minimal utility if the votes
 * aren't also aggregated off-chain (if users have to submit their votes individually, they might as well
 * update the tally at the same time).
 *
 * However, to support the maximum number of use cases, it should be noted that:
 * - the voting contract could allow some users to vote with Ethereum addresses, to support contracts
 *   and existing wallets. In such a scenario, the subset of balances held by BLS public keys could aggregate
 *   their votes off-chain, while the Ethereum addresses would still vote individually.
 * - in this version, the BLS keys are used for voting while Ethereum addresses are used for token transfers.
 *   This is partly to ensure it still follows the ERC20 specification and partly to clearly separate the two
 *   features so they can be understood in isolation. This may also be useful for differential security,
 *   where a hardware wallet that only supports ECDSA (for example) could be authorized to transfer the tokens,
 *   while a less secure browser-based BLS wallet (for example) could be authorized to vote. Naturally,
 *   the contract could be modified to accept BLS keys for token transfers if desired.
 *
 * Additionally, it should be noted that the commitments allow the contract to eliminate most contract storage.
 * Users can reconstruct the data by tracking events or querying a data provider that watches the contract.
 * Users can then provide the relevant data as need to the contract, along with corresponding inclusion proofs.
 * The contract can efficiently validate the proofs against the commitments. This behavior is not implemented
 * because individual operations (like token transfers) that only access a few storage locations are still
 * cheaper than verifying the data against a commitment. Nevertheless, it's worth noting this possibility for
 * use cases that involve accessing large amounts of storage.
 *
 * Lastly, in the interests of focussing on the core mechanism, this contract does not handle send/receive hooks,
 * flash mints or any other features. Like regular tokens, these can be added as desired.
 * This may seem obvious but I'm just trying to forestall a potential misunderstanding by clarifying that
 * the BLS signatures are used to convince the contract that an operation is authorized, but they do not restrict
 * the powers of the contract to manage state arbitrarily. In fact, there are some esoteric use cases that
 * would be simplified (eg. snapshots can be taken by simply copying the BalancesCommitment, rebases can be
 * achieved by multiplying the commitment by a constant, token merges can be achieved by adding commitments together).
 */
contract CommitmentToken is PolynomialCommitment, ERC20 {
    using Counters for Counters.Counter;

    uint256 public constant INITIAL_SUPPLY = 1000e18;

    // The Kate commitment representing an ordered list of user balances
    BN256Adapter.PointG1 public BalancesCommitment;

    // The Kate commitment representing an ordered list of user BLS public keys.
    // The key at position i is authorized to vote with the tokens at position i in BalancesCommitment
    BN256Adapter.PointG2 public KeysCommitment;

    // The first free position in both commitments. It is initialized to 1.
    // We avoid position 0 to ensure indexOf[address] is non-zero for all known addresses
    Counters.Counter internal nextFreeIndex;

    // A mapping from a token holder address to the corresponding index in the commitments
    // The default (zero) value implies the address/balance combination is not in the commitments
    mapping(address => uint256) public indexOf;

    /**
     * @param name the name of the token (display purposes only)
     * @param symbol the token symbol (display purposes only)
     * @dev mint INITIAL_SUPPLY tokens for the message sender
     * the decimals values is implicitly set to 18
     */
    constructor(
        string memory name,
        string memory symbol,
        TrustedSetup _trustedSetup
    ) public ERC20(name, symbol) PolynomialCommitment(_trustedSetup) {
        _mint(msg.sender, INITIAL_SUPPLY);

        // start at 1 so 0 can indicate an address/balance combination that is not in the commitments
        nextFreeIndex.increment();
    }

    /**
     * @notice Returns the first empty position in the KeysCommitment and BalancesCommitment
     * This is the index that will be used the next time someone registers a BLS key
     * @return the next index that will be used to register a BLS key
     */
    function nextIndex() public view returns (uint256) {
        return nextFreeIndex.current();
    }

    /**
     * @notice Register a new BLS public key
     * @dev the key is associated with the message sender (in indexOf) and added
     * to the KeysCommitment. If the message sender's balance is non-zero, the
     * BalancesCommitment is updated accordingly.
     * This function reverts if the message sender already has a BLS key.
     * It also reverts if the commitments are full (all positions are used).
     * In a production deployment, it could start another Commitment instead.
     * The parameters are [PUBLIC_KEY], s^(index)⋅[PUBLIC_KEY] and s^(MAX_DEGREE)⋅[PUBLIC_KEY]
     *  Note: s and MAX_DEGREE are properties of the trusted setup
     * In practice, the last two parameters would be obtained by signing the points
     * returned by registrationArtifacts()
     * @param key the BLS public key to register
     * @param encodedKey the BLS public key encoded for inclusion in KeysCommitment
     * @param encodingArtifact an artifact used to validate consistency of the encoding
     */
    function register(
        BN256Adapter.PointG2 memory key,
        BN256Adapter.PointG2 memory encodedKey,
        BN256Adapter.PointG2 memory encodingArtifact
    ) public {
        // It would be more natural to replace the BLS key instead of reverting
        // However, this would require knowing the key, which means the contract
        // would need to save it in storage or validate a key provided by the user
        // Since this code base is intended to be informational, and replacing keys
        // offers minimal explanatory value, we just prohibit the use case
        require(indexOf[msg.sender] == 0, "User already has a BLS key");

        uint256 index = nextFreeIndex.current();
        nextFreeIndex.increment();

        // In a production deployment, we could start another Commitment instead
        require(index < DATA_ARRAY_SIZE, "Too many registered users");
        indexOf[msg.sender] = index;

        // before adding the encoded key to the KeysCommitment, we should ensure
        // that it only affects the record at the specified index
        BN256Adapter.PairingEquation[] memory equations = new BN256Adapter.PairingEquation[](2);
        BN256Adapter.PairingEquation[2] memory keysEqns = _isSingleValueEquations(
            encodedKey,
            index,
            key,
            encodingArtifact
        );
        equations[0] = keysEqns[0];
        equations[1] = keysEqns[1];
        require(
            BN256Adapter.verifyPairingEquations(equations),
            "Cannot register key. Invalid proof provided"
        );

        // add the encoded key to the keys commitment
        BN256Adapter.PointG2[] memory keyComms = new BN256Adapter.PointG2[](2);
        keyComms[0] = KeysCommitment;
        keyComms[1] = encodedKey;
        KeysCommitment = BN256Adapter.sum(keyComms);

        // add the user's balance to the balances commitment
        uint256 balance = balanceOf(msg.sender);
        if (balance != 0) {
            BN256Adapter.PointG1[] memory balanceComms = new BN256Adapter.PointG1[](2);
            balanceComms[0] = BalancesCommitment;
            balanceComms[1] = BN256Adapter.multiply(trustedSetup.S1(index), balance);
            BalancesCommitment = BN256Adapter.sum(balanceComms);
        }
    }

    /**
     * @notice Generates the artifacts required to register a new BLS key
     * @dev The artifacts are s^(index)⋅[P2] and s^(MAX_DEGREE)⋅[P2]
     *  Note: s and MAX_DEGREE are properties of the trusted setup
     * These points should be signed by the user's wallet, to become
     * PRIVATE_KEY⋅s^(index)⋅[P2] and PRIVATE_KEY⋅s^(MAX_DEGREE)⋅[P2] or, equivalently
     * s^(index)⋅[PUBLIC_KEY] and s^(MAX_DEGREE)⋅[PUBLIC_KEY], which can be passed to the register function
     * This does not handle race conditions where someone else registers their key in the
     * same position. If that occurs, this function will need to be called again to generate
     * new artifacts.
     * @return the positionArtifact, which will become the encodedKey for the register function when signed
     * @return the boundaryArtifact, which will become the encodingArtifact for the register function when signed
     */
    function registrationArtifacts()
        public
        view
        returns (BN256Adapter.PointG2 memory, BN256Adapter.PointG2 memory)
    {
        return (
            trustedSetup.S2(nextFreeIndex.current()),
            trustedSetup.S2(trustedSetup.MAX_DEGREE())
        );
    }
}
