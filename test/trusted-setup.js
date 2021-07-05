const { expect } = require("chai");

describe("Trusted Setup", function () {
  let adapter;
  let setup;
  let P1;
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

    P1 = await adapter.P1();
    MAX_DEGREE = await setup.MAX_DEGREE();
  });

  describe("Initialization", async function () {
    it("should set MAX_DEGREE to 10", async function () {
      expect(MAX_DEGREE).to.equal(10);
    });

    it("should set the powers of s to P1", async function() {
      for(let i = 0; i <= MAX_DEGREE; i++) {
        let power = await setup.S(i);
        expect(power).to.deep.equal(P1);
      }
    });
  });
});
