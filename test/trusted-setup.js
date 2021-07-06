const { expect } = require("chai");

describe("Trusted Setup", function () {
  let adapter;
  let setup;
  let helper;
  let P1;
  let P2;
  let MAX_DEGREE;

  this.beforeAll(async function () {
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

    TestHelper = await ethers.getContractFactory("TestHelper", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    helper = await TestHelper.deploy();
    await helper.deployed();

    P1 = await adapter.P1();
    P2 = await adapter.P2();
    MAX_DEGREE = Number(await setup.MAX_DEGREE());
  });

  describe("Initialization", async function () {
    it("should set MAX_DEGREE to 10", async function () {
      expect(MAX_DEGREE).to.equal(10);
    });

    it("should set the powers of s to P1", async function () {
      for (let i = 0; i <= MAX_DEGREE; i++) {
        let power = await setup.S(i);
        expect(power).to.deep.equal(P1);
      }
    });

    it("should set the verifier artifact to P2", async function () {
      let verifierArtifact = await setup.verifierArtifact();
      expect(verifierArtifact).to.deep.equal(P2);
    });
  });

  describe("Alice generates an update proof", async function () {
    let aliceK;
    let aliceUpdated;
    let aliceProof;
    let aliceVerifierArtifact;

    this.beforeAll(async function () {
      aliceK = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("Alice's secret")
      );
      [aliceUpdated, aliceProof, aliceVerifierArtifact] =
        await setup.generateUpdateProof(aliceK);
    });

    it("should generate the powers of k in group G1", async function () {
      expect(aliceUpdated.length).to.equal(MAX_DEGREE + 1);
      expect(aliceUpdated[0]).to.deep.equal(P1);
      let next;
      for (let i = 1; i < aliceUpdated.length; i++) {
        next = await helper.multiplyG1(aliceUpdated[i - 1], aliceK);
        expect(aliceUpdated[i]).to.deep.equal(next);
      }
    });

    it("should generate k in group G1", async function () {
      const kP1 = await helper.multiplyG1(P1, aliceK);
      expect(aliceProof).to.deep.equal(kP1);
    });

    it("should generate k in group G2", async function () {
      const kP2 = await helper.multiplyG2(P2, aliceK);
      expect(aliceVerifierArtifact).to.deep.equal(kP2);
    });

    describe("Alice updates the trusted setup", async function () {
      this.beforeAll(async function () {
        await setup.update(aliceUpdated, aliceProof, aliceVerifierArtifact);
      });

      it("should update S", async function () {
        for (let i = 0; i <= MAX_DEGREE; i++) {
          let power = await setup.S(i);
          expect(power).to.deep.equal(aliceUpdated[i]);
        }
      });

      it("should update the verifier artifact", async function () {
        let va = await setup.verifierArtifact();
        expect(va).to.deep.equal(aliceVerifierArtifact);
      });
    });

    describe("Alice tampers with the first S value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the first element to ensure the check on the first term is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdated
        tampered = [aliceUpdated[1]].concat(aliceUpdated.slice(1));
      });

      it("should fail to update S", async function () {
        const update = setup.update(tampered, aliceProof, aliceVerifierArtifact);
        expect(update).to.be.reverted;
      });
    });

    describe("Alice tampers with the the second S value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the last element to ensure the check on the pairing consistencies is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdated
        tampered = aliceUpdated.slice(0, aliceUpdated.length - 1).concat([aliceUpdated[0]])
      });

      it("should fail to update S", async function () {
        const update = setup.update(tampered, aliceProof, aliceVerifierArtifact);
        expect(update).to.be.reverted;
      });
    });
  });
});
