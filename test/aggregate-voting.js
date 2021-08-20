const { expect } = require("chai");
const { ethers } = require("ethers");

// WARNING: To avoid excess repetition, some tests have side-effects that are used to initialize subsequent tests
// Running a subset of the tests may produce unexpected results

describe.only("Aggregate Voting", function () {
  const TOPIC = "Is Pluto a planet?";
  const TOKEN_NAME = "Commitment Token";
  const TOKEN_SYMBOL = "CMT";

  let alice, bob, charlie, diane, evelyn;
  let aWallet, bWallet, cWallet, dWallet, eWallet;
  let s, adapter, setup, token, voting;

  // some tests may exceed the test time limit. Turn it off
  this.timeout(0);

  this.beforeAll(async function () {
    [alice, bob, charlie, diane, evelyn] = await ethers.getSigners();

    BN256Adapter = await ethers.getContractFactory("BN256Adapter");
    adapter = await BN256Adapter.deploy();
    await adapter.deployed();

    TrustedSetup = await ethers.getContractFactory("TrustedSetup", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    setup = await TrustedSetup.deploy();
    await setup.deployed();

    CommitmentToken = await ethers.getContractFactory("CommitmentToken", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    token = await CommitmentToken.connect(alice).deploy(
      TOKEN_NAME,
      TOKEN_SYMBOL,
      setup.address
    );
    await token.deployed();

    AggregateVoting = await ethers.getContractFactory("AggregateVoting");

    console.log("NOTE: creating 5 BLS wallets takes about 15 seconds...");
    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    aWallet = await SimulatedBLSWallet.deploy("Alice");
    bWallet = await SimulatedBLSWallet.deploy("Bob");
    cWallet = await SimulatedBLSWallet.deploy("Charlie");
    dWallet = await SimulatedBLSWallet.deploy("Diane");
    eWallet = await SimulatedBLSWallet.deploy("Evelyn");

    // since we're not testing this here, we could hardcode the initialization for efficiency
    console.log(
      "NOTE: initializing the trusted setup takes about 15 seconds..."
    );
    s = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("a secret"));
    let [updatedS1, updatedS2, proof] = await setup.generateUpdateProof(s);
    await setup.update(updatedS1, updatedS2, proof);
  });

  describe("Situational Context", async function () {
    const INITIAL_SUPPLY = ethers.BigNumber.from(10).pow(18).mul(1000); //1000e18
    const BOB_BAL = ethers.BigNumber.from(10).pow(18).mul(100);
    const CHARLIE_BAL = ethers.BigNumber.from(10).pow(18).mul(200);
    const DIANE_BAL = ethers.BigNumber.from(10).pow(18).mul(75);
    const EVELYN_BAL = ethers.BigNumber.from(10).pow(18).mul(250);
    const ALICE_BAL = INITIAL_SUPPLY.sub(BOB_BAL)
      .sub(CHARLIE_BAL)
      .sub(DIANE_BAL)
      .sub(EVELYN_BAL);

    describe("Alice transfers funds between the participants", async function () {
      this.beforeAll(async function () {
        await token.connect(alice).transfer(bob.address, BOB_BAL);
        await token.connect(alice).transfer(charlie.address, CHARLIE_BAL);
        await token.connect(alice).transfer(diane.address, DIANE_BAL);
        await token.connect(alice).transfer(evelyn.address, EVELYN_BAL);
      });

      it("should set Alice's balance to 375", async function () {
        const bal = await token.balanceOf(alice.address);
        expect(bal).to.equal(ALICE_BAL);
      });

      it("should set Bob's balance to 100", async function () {
        const bal = await token.balanceOf(bob.address);
        expect(bal).to.equal(BOB_BAL);
      });

      it("should set Charlie's balance to 150", async function () {
        const bal = await token.balanceOf(charlie.address);
        expect(bal).to.equal(CHARLIE_BAL);
      });

      it("should set Diane's balance to 150", async function () {
        const bal = await token.balanceOf(diane.address);
        expect(bal).to.equal(DIANE_BAL);
      });

      it("should set Evelyn's balance to 150", async function () {
        const bal = await token.balanceOf(evelyn.address);
        expect(bal).to.equal(EVELYN_BAL);
      });
    });

    describe("All participants register their keys", async function () {
      this.beforeAll(async function () {
        let artifacts, encodedKey, encodingArtifact, pk;

        artifacts = await token.registrationArtifacts();
        encodedKey = await aWallet.signPoint(artifacts[0]);
        encodingArtifact = await aWallet.signPoint(artifacts[1]);
        pk = await aWallet.PUBLIC_KEY();
        await token.connect(alice).register(pk, encodedKey, encodingArtifact);

        artifacts = await token.registrationArtifacts();
        encodedKey = await bWallet.signPoint(artifacts[0]);
        encodingArtifact = await bWallet.signPoint(artifacts[1]);
        pk = await bWallet.PUBLIC_KEY();
        await token.connect(bob).register(pk, encodedKey, encodingArtifact);

        artifacts = await token.registrationArtifacts();
        encodedKey = await cWallet.signPoint(artifacts[0]);
        encodingArtifact = await cWallet.signPoint(artifacts[1]);
        pk = await cWallet.PUBLIC_KEY();
        await token.connect(charlie).register(pk, encodedKey, encodingArtifact);

        artifacts = await token.registrationArtifacts();
        encodedKey = await dWallet.signPoint(artifacts[0]);
        encodingArtifact = await dWallet.signPoint(artifacts[1]);
        pk = await dWallet.PUBLIC_KEY();
        await token.connect(diane).register(pk, encodedKey, encodingArtifact);

        artifacts = await token.registrationArtifacts();
        encodedKey = await eWallet.signPoint(artifacts[0]);
        encodingArtifact = await eWallet.signPoint(artifacts[1]);
        pk = await eWallet.PUBLIC_KEY();
        await token.connect(evelyn).register(pk, encodedKey, encodingArtifact);
      });

      // this is not a particularly insightful test. I'd prefer to check the commitments themselves
      // once they're copied to the AggregateVoting contract and there should be some test in this
      // block to trigger the `beforeAll` function
      it("should record 5 keys", async function () {
        const next = Number(await token.nextIndex());
        expect(next).to.equal(6);
      });
    });

    describe("Deploy an AggregateVoting contract", async function () {
      this.beforeAll(async function () {
        voting = AggregateVoting.deploy(token, TOPIC);
        await voting.deployed();
      });

      it("should have a KeysCommitment with all BLS keys", async function () {
          const keysComm = await voting.KeysCommitment();
          const P1 = await adapter.P1();
          const aliceComm = (await aWallet.PUBLIC_KEY())
      });
    });
  });
});
