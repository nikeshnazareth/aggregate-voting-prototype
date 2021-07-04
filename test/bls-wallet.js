const { expect } = require("chai");

describe("BLS Wallet", function () {
  let SimulatedBLSWallet;
  let adapter;
  let helper;

  this.beforeAll(async function () {
    BN256Adapter = await ethers.getContractFactory("BN256Adapter");
    adapter = await BN256Adapter.deploy();
    await adapter.deployed();

    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });

    TestHelper = await ethers.getContractFactory("TestHelper", {
      libraries: {
        BN256Adapter: adapter.address,
      },
    });
    helper = await TestHelper.deploy();
    await helper.deployed();
  });

  describe("Alice creates a wallet", async function () {
    let aliceWallet;

    this.beforeAll(async function () {
      aliceWallet = await SimulatedBLSWallet.deploy("Alice");
      await aliceWallet.deployed();
    });

    it("should compute a public key", async function () {
      const pk = await aliceWallet.PUBLIC_KEY();

      // this should check that it matches the expected value, but I don't know what that is
      // I will defer this to the signatures consistency test
      expect(pk.x_real).to.not.equal(0);
      expect(pk.x_imag).to.not.equal(0);
      expect(pk.y_real).to.not.equal(0);
      expect(pk.y_imag).to.not.equal(0);
    });

    describe("Alice signs a message", async function () {
      const msg = ethers.utils.toUtf8Bytes("A sample message");
      let signature;

      this.beforeAll(async function () {
        signature = await aliceWallet.sign(msg);
      });

      it("should produce a signature", async function () {
        // this should check that it matches the expected value, but I don't know what that is
        // I will defer this to the signatures consistency test
        expect(signature.x).to.not.equal(0);
        expect(signature.y).to.not.equal(0);
      });

      it("should verify the signature", async function () {
        const pk = await aliceWallet.PUBLIC_KEY();
        const verified = await helper.verify(msg, signature, pk);
        expect(verified).to.equal(true);
      });
    });
  });
});
