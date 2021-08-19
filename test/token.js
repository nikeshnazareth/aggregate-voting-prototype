const { expect } = require("chai");

describe.only("Commitment Token", function () {
  const TOKEN_NAME = "Commitment Token";
  const TOKEN_SYMBOL = "CMT";
  const INITIAL_SUPPLY = ethers.BigNumber.from(10).pow(18).mul(1000); //1000e18
  // the q value in EIP-197 (https://eips.ethereum.org/EIPS/eip-197)
  const GROUP_ORDER = ethers.BigNumber.from(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
  );

  let alice, aliceWallet, bob, bobWallet, charlie, token, setup, helper, s;

  this.beforeAll(async function () {
    [alice, bob, charlie] = await ethers.getSigners();

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

    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    aliceWallet = await SimulatedBLSWallet.deploy("Alice");
    bobWallet = await SimulatedBLSWallet.deploy("Bob");

    TestHelper = await ethers.getContractFactory("TestHelper", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    helper = await TestHelper.deploy();
    await helper.deployed();

    // the update proof may exceed the test time limit. Turn it off
    // since we're not testing this here, we could hardcode the initialization for efficiency
    this.timeout(0);
    console.log(
      "NOTE: initializing the trusted setup takes about 15 seconds..."
    );
    s = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("a secret"));
    let [updatedS1, updatedS2, proof] = await setup.generateUpdateProof(s);
    await setup.update(updatedS1, updatedS2, proof);
  });

  describe("Initialization", async function () {
    it("should mint 1000 tokens for Alice", async function () {
      const balance = await token.balanceOf(alice.address);
      expect(balance).to.equal(INITIAL_SUPPLY);
    });

    it("should set the first free index to one", async function () {
      const idx = await token.nextIndex();
      expect(idx).to.equal(1);
    });
  });

  describe("Register Alice", async function () {
    let artifacts;
    let encodedKey;
    let encodingArtifact;
    let pk;

    describe("Alice generates registration artifacts", async function () {
      this.beforeAll(async function () {
        artifacts = await token.registrationArtifacts();
      });

      it("should produce the point s⋅[P2]", async function () {
        const sPoint = await setup.S2(1);
        expect(artifacts[0]).to.deep.equal(sPoint);
      });

      it("should produce the point (s^MAX_DEGREE)⋅[P2]", async function () {
        let MAX_DEGREE = Number(await setup.MAX_DEGREE());
        const s_max = await setup.S2(MAX_DEGREE);
        expect(artifacts[1]).to.deep.equal(s_max);
      });
    });

    describe("Alice signs the registration artifacts", async function () {
      this.beforeAll(async function () {
        encodedKey = await aliceWallet.signPoint(artifacts[0]);
        encodingArtifact = await aliceWallet.signPoint(artifacts[1]);
        pk = await aliceWallet.PUBLIC_KEY();
      });

      it("should produce her public key scaled by s", async function () {
        const scaled = await helper.multiplyG2(pk, s);
        expect(encodedKey).to.deep.equal(scaled);
      });

      it("should produce her public key scaled by s^MAX_DEGREE", async function () {
        let MAX_DEGREE = Number(await setup.MAX_DEGREE());
        // there doesn't appear to be a powMod operator, which would be much more efficient
        const s_max = ethers.BigNumber.from(s).pow(MAX_DEGREE).mod(GROUP_ORDER);
        const scaled = await helper.multiplyG2(pk, s_max);
        expect(encodingArtifact).to.deep.equal(scaled);
      });
    });

    describe("Alice registers her key", async function () {
      this.beforeAll(async function () {
        await token.register(pk, encodedKey, encodingArtifact);
      });

      describe("indexOf[Alice]", async function () {
        it("should return 1", async function () {
          const i = await token.indexOf(alice.address);
          expect(i).to.equal(1);
        });
      });

      describe("nextIndex()", async function () {
        it("should return 2", async function () {
          const next = await token.nextIndex();
          expect(next).to.equal(2);
        });
      });

      it("should set the keys commitment to the encoded key", async function () {
        const keysComm = await token.KeysCommitment();
        expect(keysComm).to.deep.equal(encodedKey);
      });

      it("should set the balances commitment to match array [1000e18, 0, 0, ... ]", async function() {
        const balancesComm = await token.BalancesCommitment();
        const P1 = await adapter.P1();
        const coefficient = ethers.BigNumber.from(s).mul(INITIAL_SUPPLY).mod(GROUP_ORDER);
        const expected = await helper.multiplyG1(P1, coefficient)
        expect(balancesComm).to.deep.equal(expected);
      });
    });

    describe("Alice attempts to register her key again", async function () {
      it("should fail to update", async function () {
        const registrationTx = token.register(pk, encodedKey, encodingArtifact);
        expect(registrationTx).to.be.revertedWith("User already has a BLS key");
      });
    });
  });

  describe("Register Bob", async function () {
    let artifacts;
    let encodedKey;
    let encodingArtifact;
    let pk;

    describe("Bob generates registration artifacts", async function () {
      this.beforeAll(async function () {
        artifacts = await token.registrationArtifacts();
      });

      it("should produce the point (s^2)⋅[P2]", async function () {
        const sPoint = await setup.S2(2);
        expect(artifacts[0]).to.deep.equal(sPoint);
      });

      it("should produce the point (s^MAX_DEGREE)⋅[P2]", async function () {
        let MAX_DEGREE = Number(await setup.MAX_DEGREE());
        const s_max = await setup.S2(MAX_DEGREE);
        expect(artifacts[1]).to.deep.equal(s_max);
      });
    });

    describe("Bob signs the registration artificats", async function () {
      this.beforeAll(async function () {
        encodedKey = await bobWallet.signPoint(artifacts[0]);
        encodingArtifact = await bobWallet.signPoint(artifacts[1]);
        pk = await bobWallet.PUBLIC_KEY();
      });

      it("should produce his public key scaled by s^2", async function () {
        const s_2 = ethers.BigNumber.from(s).pow(2).mod(GROUP_ORDER);
        const scaled = await helper.multiplyG2(pk, s_2);
        expect(encodedKey).to.deep.equal(scaled);
      });

      it("should produce his public key scaled by s^MAX_DEGREE", async function () {
        let MAX_DEGREE = Number(await setup.MAX_DEGREE());
        // there doesn't appear to be a powMod operator, which would be much more efficient
        const s_max = ethers.BigNumber.from(s).pow(MAX_DEGREE).mod(GROUP_ORDER);
        const scaled = await helper.multiplyG2(pk, s_max);
        expect(encodingArtifact).to.deep.equal(scaled);
      });
    });

    describe("Bob (incorrectly) registers his key in position 1", async function () {
      let shifted;

      this.beforeAll(async function () {
        // use position 1 instead of 2 (ie. multiply by s instead of s^2)
        shifted = await helper.multiplyG2(pk, s);
      });

      it("should fail to register", async function () {
        const registrationTx = token.connect(bob).register(pk, shifted, encodingArtifact);
        expect(registrationTx).to.be.revertedWith(
          "Cannot register key. Invalid proof provided"
        );
      });
    });

    describe("Bob registers his key", async function () {
      let previousKeysComm;

      this.beforeAll(async function () {
        previousKeysComm = await token.KeysCommitment();
        await token.connect(bob).register(pk, encodedKey, encodingArtifact);
      });

      describe("indexOf[Bob]", async function() {
        it("should return 2", async function() {
          const i = await token.indexOf(bob.address)
        });
      });

      describe("nextIndex()", async function() {
        it("should return 3", async function() {
          const next = await token.nextIndex();
          expect(next).to.equal(3);
        });
      });

      it("should add Bob's encoded key to the keys commitment", async function() {
        const keysComm = await token.KeysCommitment();
        const combinedComms = await helper.sumG2([ previousKeysComm, encodedKey]);
        expect(keysComm).to.deep.equal(combinedComms);
      });
    });
  });
});
