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

    // this test suite saves values in context blocks to avoid recomputing them
    // in a later test we will require the update proof that Bob would have generated
    // if he ignored Alice's update. For simplicity, compute it now before Alice's update
    let bobK;
    let bobUpdated_solo;
    let bobProof_solo;
    let bobVerifierArtifact_solo;

    this.beforeAll(async function () {
      aliceK = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("Alice's secret")
      );
      [aliceUpdated, aliceProof, aliceVerifierArtifact] =
        await setup.generateUpdateProof(aliceK);

      // compute these in preparation for future tests
      bobK = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Bob's secret"));
      [bobUpdated_solo, bobProof_solo, bobVerifierArtifact_solo] =
        await setup.generateUpdateProof(bobK);
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

    describe("Alice tampers with the first S value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the first element to ensure the check on the first term is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdated
        tampered = [aliceUpdated[1]].concat(aliceUpdated.slice(1));
      });

      it("should fail to update S", async function () {
        const update = setup.update(
          tampered,
          aliceProof,
          aliceVerifierArtifact
        );
        expect(update).to.be.revertedWith("Invalid degree zero term. It should be P1");
      });
    });

    describe("Alice tampers with the the second S value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the last element to ensure the check on the pairing consistencies is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdated
        tampered = aliceUpdated
          .slice(0, aliceUpdated.length - 1)
          .concat([aliceUpdated[0]]);
      });

      it("should fail to update S", async function () {
        const update = setup.update(
          tampered,
          aliceProof,
          aliceVerifierArtifact
        );
        expect(update).to.be.revertedWith("Cannot update S. Invalid proofs provided");
      });
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

      describe("Bob generates a subsequent update proof", async function () {
        let bobUpdated;
        let bobProof;
        let bobVerifierArtifact;

        this.beforeAll(async function () {
          [bobUpdated, bobProof, bobVerifierArtifact] =
            await setup.generateUpdateProof(bobK);
        });

        it("should generate the powers of alicek * bobK in group G1", async function () {
          expect(bobUpdated.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdated[0]).to.deep.equal(P1);
          let intermediate, next;
          for (let i = 1; i < bobUpdated.length; i++) {
            // instead of computing aliceK * bobK % Q in javascript, do two multiplications
            intermediate = await helper.multiplyG1(bobUpdated[i - 1], aliceK);
            next = await helper.multiplyG1(intermediate, bobK);
            expect(bobUpdated[i]).to.deep.equal(next);
          }
        });

        it("should generate bobK in group G1", async function () {
          const kP1 = await helper.multiplyG1(P1, bobK);
          expect(bobProof).to.deep.equal(kP1);
        });

        it("should generate alicek * bobK in group G2", async function () {
          const intermediate = await helper.multiplyG2(P2, aliceK);
          const kP2 = await helper.multiplyG2(intermediate, bobK);
          expect(bobVerifierArtifact).to.deep.equal(kP2);
        });

        describe("Bob updates the trusted setup", async function () {
          this.beforeAll(async function () {
            await setup.update(bobUpdated, bobProof, bobVerifierArtifact);
          });

          it("should update S", async function () {
            for (let i = 0; i <= MAX_DEGREE; i++) {
              let power = await setup.S(i);
              expect(power).to.deep.equal(bobUpdated[i]);
            }
          });

          it("should update the verifier artifact", async function () {
            let va = await setup.verifierArtifact();
            expect(va).to.deep.equal(bobVerifierArtifact);
          });
        });
      });

      describe("Bob generates an update proof excluding Alice's update", async function () {
        // we calculated these values when computing Alice's update proof

        it("should generate the powers of bobK in group G1", async function () {
          expect(bobUpdated_solo.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdated_solo[0]).to.deep.equal(P1);
          let next;
          for (let i = 1; i < bobUpdated_solo.length; i++) {
            next = await helper.multiplyG1(bobUpdated_solo[i - 1], bobK);
            expect(bobUpdated_solo[i]).to.deep.equal(next);
          }
        });

        it("should generate bobK in group G1", async function () {
          const kP1 = await helper.multiplyG1(P1, bobK);
          expect(bobProof_solo).to.deep.equal(kP1);
        });

        it("should generate bobK in group G2", async function () {
          const kP2 = await helper.multiplyG2(P2, bobK);
          expect(bobVerifierArtifact_solo).to.deep.equal(kP2);
        });

        describe("Bob updates the trusted setup", async function () {
          it("should fail to update S", async function () {
            const update = setup.update(
              bobUpdated_solo,
              bobProof_solo,
              bobVerifierArtifact_solo
            );
            expect(update).to.be.revertedWith("Cannot update S. Invalid proofs provided");
          });
        });
      });
    });
  });
});
