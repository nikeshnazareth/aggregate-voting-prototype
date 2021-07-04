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
      let aliceSignature;

      this.beforeAll(async function () {
        aliceSignature = await aliceWallet.sign(msg);
      });

      it("should produce a signature", async function () {
        // this should check that it matches the expected value, but I don't know what that is
        // I will defer this to the signatures consistency test
        expect(aliceSignature.x).to.not.equal(0);
        expect(aliceSignature.y).to.not.equal(0);
      });

      it("should verify the signature", async function () {
        const pk = await aliceWallet.PUBLIC_KEY();
        const verified = await helper.verify(msg, aliceSignature, pk);
        expect(verified).to.equal(true);
      });

      describe("Bob and Charlie create wallets", async function () {
        let bobWallet;
        let charlieWallet;

        this.beforeAll(async function () {
          bobWallet = await SimulatedBLSWallet.deploy("Bob");
          await bobWallet.deployed();

          charlieWallet = await SimulatedBLSWallet.deploy("Charlie");
          await charlieWallet.deployed();
        });

        describe("Bob and Charlie sign the same message as Alice", async function () {
          let bobSignature;
          let charlieSignature;

          this.beforeAll(async function () {
            bobSignature = await bobWallet.sign(msg);
            charlieSignature = await charlieWallet.sign(msg);
          });

          it("should verify Bob's signature", async function () {
            const pk = await bobWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, bobSignature, pk);
            expect(verified).to.equal(true);
          });

          it("should verify Charlie's signature", async function () {
            const pk = await charlieWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, charlieSignature, pk);
            expect(verified).to.equal(true);
          });

          it("should fail to verify Bob's signature with Alice's public key", async function () {
            const pk = await aliceWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, bobSignature, pk);
            expect(verified).to.equal(false);
          });

          it("should fail to verify Charlie's signature with Alice's public key", async function () {
            const pk = await aliceWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, charlieSignature, pk);
            expect(verified).to.equal(false);
          });

          it("should validate the aggregate signature", async function () {
            const pks = [
              await aliceWallet.PUBLIC_KEY(),
              await bobWallet.PUBLIC_KEY(),
              await charlieWallet.PUBLIC_KEY(),
            ];
            const signatures = [aliceSignature, bobSignature, charlieSignature];

            const aggregatePK = await helper.sumG2(pks);
            const aggregateSignature = await helper.sumG1(signatures);
            const verified = await helper.verify(msg, aggregateSignature, aggregatePK);
            expect(verified).to.equal(true);
          });
        });

        describe("Bob sign the same message as Alice (m1); Charlie signs m2", async function () {
          const anotherMsg = ethers.utils.toUtf8Bytes("Another message");
          let bobSignature;
          let charlieSignature;

          this.beforeAll(async function () {
            bobSignature = await bobWallet.sign(msg);
            charlieSignature = await charlieWallet.sign(anotherMsg);
          });

          it("should verify Bob's signature on m1", async function () {
            const pk = await bobWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, bobSignature, pk);
            expect(verified).to.equal(true);
          });

          it("should fail to verify Bob's signature on m2", async function () {
            const pk = await bobWallet.PUBLIC_KEY();
            const verified = await helper.verify(anotherMsg, bobSignature, pk);
            expect(verified).to.equal(false);
          });

          it("should fail to verify Charlie's signature on m1", async function () {
            const pk = await charlieWallet.PUBLIC_KEY();
            const verified = await helper.verify(msg, charlieSignature, pk);
            expect(verified).to.equal(false);
          });

          it("should verify Charlie's signature on m2", async function () {
            const pk = await charlieWallet.PUBLIC_KEY();
            const verified = await helper.verify(anotherMsg, charlieSignature, pk);
            expect(verified).to.equal(true);
          });

          it("should fail to validate the aggregate signature", async function () {
            const pks = [
              await aliceWallet.PUBLIC_KEY(),
              await bobWallet.PUBLIC_KEY(),
              await charlieWallet.PUBLIC_KEY(),
            ];
            const signatures = [aliceSignature, bobSignature, charlieSignature];

            const aggregatePK = await helper.sumG2(pks);
            const aggregateSignature = await helper.sumG1(signatures);
            const verified = await helper.verify(msg, aggregateSignature, aggregatePK);
            expect(verified).to.equal(false);
          });
        });
      });
    });
  });
});
