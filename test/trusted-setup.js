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
    MAX_DEGREE = await setup.MAX_DEGREE();
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

    it("should set sP2 to P2", async function () {
      let sp2 = await setup.sP2();
      expect(sp2).to.deep.equal(P2);
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
      expect(aliceUpdated.length).to.equal(MAX_DEGREE);
      let previous = P1;
      let current;
      for (let i = 0; i < aliceUpdated.length; i++) {
        current = await helper.multiplyG1(previous, aliceK);
        expect(aliceUpdated[i]).to.deep.equal(current);
        previous = current;
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
  });
});
