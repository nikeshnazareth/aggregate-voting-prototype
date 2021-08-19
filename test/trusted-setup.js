const { expect } = require("chai");

// WARNING: To avoid excess repetition, some tests have side-effects that are used to initialize subsequent tests
// Running a subset of the tests may produce unexpected results

describe("Trusted Setup", function () {
  let adapter;
  let setup;
  let helper;
  let P1;
  let P2;
  let MAX_DEGREE;

  // the update proof exceeds the test time limit.
  // turn it off
  this.timeout(0);

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

    it("should set the S1 components to P1", async function () {
      for (let i = 0; i <= MAX_DEGREE; i++) {
        let power = await setup.S1(i);
        expect(power).to.deep.equal(P1);
      }
    });

    it("should set the S2 components to P2", async function () {
      for (let i = 0; i <= MAX_DEGREE; i++) {
        let power = await setup.S2(i);
        expect(power).to.deep.equal(P2);
      }
    });
  });

  describe("Alice generates an update proof", async function () {
    let aliceK;
    let aliceUpdatedS1;
    let aliceUpdatedS2;
    let aliceProof;

    // this test suite saves values in context blocks to avoid recomputing them
    // in a later test we will require the update proof that Bob would have generated
    // if he ignored Alice's update. For simplicity, compute it now before Alice's update
    let bobK;
    let bobUpdatedS1_solo;
    let bobUpdatedS2_solo;
    let bobProof_solo;

    this.beforeAll(async function () {
      console.log(
        "NOTE: generating the update proof takes about 15 seconds..."
      );
      aliceK = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("Alice's secret")
      );
      [aliceUpdatedS1, aliceUpdatedS2, aliceProof] =
        await setup.generateUpdateProof(aliceK);

      // compute these in preparation for future tests
      console.log(
        "NOTE: precomputing Bob's proof for future tests (another 15 seconds)..."
      );
      bobK = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Bob's secret"));
      [bobUpdatedS1_solo, bobUpdatedS2_solo, bobProof_solo] =
        await setup.generateUpdateProof(bobK);
    });

    it("should generate the powers of k in group G1", async function () {
      expect(aliceUpdatedS1.length).to.equal(MAX_DEGREE + 1);
      expect(aliceUpdatedS1[0]).to.deep.equal(P1);
      let next;
      for (let i = 1; i < aliceUpdatedS1.length; i++) {
        next = await helper.multiplyG1(aliceUpdatedS1[i - 1], aliceK);
        expect(aliceUpdatedS1[i]).to.deep.equal(next);
      }
    });

    it("should generate the powers of k in group G2", async function () {
      console.log(
        "NOTE: computing the G2 test comparison takes 15 seconds..."
      );
      expect(aliceUpdatedS2.length).to.equal(MAX_DEGREE + 1);
      expect(aliceUpdatedS2[0]).to.deep.equal(P2);
      let next;
      for (let i = 1; i < aliceUpdatedS2.length; i++) {
        next = await helper.multiplyG2(aliceUpdatedS2[i - 1], aliceK);
        expect(aliceUpdatedS2[i]).to.deep.equal(next);
      }
    });

    it("should generate k in group G1", async function () {
      const kP1 = await helper.multiplyG1(P1, aliceK);
      expect(aliceProof).to.deep.equal(kP1);
    });

    describe("Alice tampers with the first S1 value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the first element to ensure the check on the first term is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdatedS1
        tampered = [aliceUpdatedS1[1]].concat(aliceUpdatedS1.slice(1));
      });

      it("should fail to update S", async function () {
        const update = setup.update(tampered, aliceUpdatedS2, aliceProof);
        expect(update).to.be.revertedWith(
          "Invalid degree zero term for updatedS1. It should be P1"
        );
      });
    });

    describe("Alice tampers with the first S2 value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the first element to ensure the check on the first term is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdatedS2
        tampered = [aliceUpdatedS2[1]].concat(aliceUpdatedS2.slice(1));
      });

      it("should fail to update S", async function () {
        const update = setup.update(aliceUpdatedS1, tampered, aliceProof);
        expect(update).to.be.revertedWith(
          "Invalid degree zero term for updatedS2. It should be P2"
        );
      });
    });

    describe("Alice tampers with the the second S1 value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the last element to ensure the check on the pairing consistencies is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdatedS1
        tampered = aliceUpdatedS1
          .slice(0, aliceUpdatedS1.length - 1)
          .concat([aliceUpdatedS1[0]]);
      });

      it("should fail to update S", async function () {
        const update = setup.update(tampered, aliceUpdatedS2, aliceProof);
        expect(update).to.be.revertedWith(
          "Cannot update S. Invalid proofs provided"
        );
      });
    });

    describe("Alice tampers with the the second S2 value", async function () {
      let tampered;

      this.beforeAll(async function () {
        // there are lots of ways to tamper with the update
        // this just changes the last element to ensure the check on the pairing consistencies is triggered
        // it also just re-orders elements to avoid having side-effects that change aliceUpdatedS2
        tampered = aliceUpdatedS2
          .slice(0, aliceUpdatedS2.length - 1)
          .concat([aliceUpdatedS2[0]]);
      });

      it("should fail to update S", async function () {
        const update = setup.update(aliceUpdatedS1, tampered, aliceProof);
        expect(update).to.be.revertedWith(
          "Cannot update S. Invalid proofs provided"
        );
      });
    });

    describe("Alice updates the trusted setup", async function () {
      this.beforeAll(async function () {
        await setup.update(aliceUpdatedS1, aliceUpdatedS2, aliceProof);
      });

      it("should update S1", async function () {
        for (let i = 0; i <= MAX_DEGREE; i++) {
          let power = await setup.S1(i);
          expect(power).to.deep.equal(aliceUpdatedS1[i]);
        }
      });

      it("should update S2", async function () {
        for (let i = 0; i <= MAX_DEGREE; i++) {
          let power = await setup.S2(i);
          expect(power).to.deep.equal(aliceUpdatedS2[i]);
        }
      });

      describe("Bob generates a subsequent update proof", async function () {
        let bobUpdatedS1;
        let bobUpdatedS2;
        let bobProof;

        this.beforeAll(async function () {
          console.log(
            "NOTE: generating the update proof takes about 15 seconds..."
          );
          const updates = await setup.generateUpdateProof(bobK);
          // deferencing this in the natural way throws errors (about assigning `undefined` to undefined)
          // I don't understand why. I will just dereference explicitly for now
          bobUpdatedS1 = updates[0];
          bobUpdatedS2 = updates[1];
          bobProof = updates[2];
        });

        it("should generate the powers of alicek * bobK in group G1", async function () {
          expect(bobUpdatedS1.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdatedS1[0]).to.deep.equal(P1);
          let intermediate, next;
          for (let i = 1; i < bobUpdatedS1.length; i++) {
            // instead of computing aliceK * bobK % Q in javascript, do two multiplications
            intermediate = await helper.multiplyG1(bobUpdatedS1[i - 1], aliceK);
            next = await helper.multiplyG1(intermediate, bobK);
            expect(bobUpdatedS1[i]).to.deep.equal(next);
          }
        });

        it("should generate the powers of alicek * bobK in group G2", async function () {
          console.log(
            "NOTE: computing the G2 test comparison takes 15 seconds..."
          );
          expect(bobUpdatedS2.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdatedS2[0]).to.deep.equal(P2);
          let intermediate, next;
          for (let i = 1; i < bobUpdatedS2.length; i++) {
            // instead of computing aliceK * bobK % Q in javascript, do two multiplications
            intermediate = await helper.multiplyG2(bobUpdatedS2[i - 1], aliceK);
            next = await helper.multiplyG2(intermediate, bobK);
            expect(bobUpdatedS2[i]).to.deep.equal(next);
          }
        });

        it("should generate bobK in group G1", async function () {
          const kP1 = await helper.multiplyG1(P1, bobK);
          expect(bobProof).to.deep.equal(kP1);
        });

        describe("Bob updates the trusted setup", async function () {
          this.beforeAll(async function () {
            await setup.update(bobUpdatedS1, bobUpdatedS2, bobProof);
          });

          it("should update S1", async function () {
            for (let i = 0; i <= MAX_DEGREE; i++) {
              let power = await setup.S1(i);
              expect(power).to.deep.equal(bobUpdatedS1[i]);
            }
          });

          it("should update S2", async function () {
            for (let i = 0; i <= MAX_DEGREE; i++) {
              let power = await setup.S2(i);
              expect(power).to.deep.equal(bobUpdatedS2[i]);
            }
          });
        });
      });

      describe("Bob generates an update proof excluding Alice's update", async function () {
        // we calculated these values when computing Alice's update proof

        it("should generate the powers of bobK in group G1", async function () {
          expect(bobUpdatedS1_solo.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdatedS1_solo[0]).to.deep.equal(P1);
          let next;
          for (let i = 1; i < bobUpdatedS1_solo.length; i++) {
            next = await helper.multiplyG1(bobUpdatedS1_solo[i - 1], bobK);
            expect(bobUpdatedS1_solo[i]).to.deep.equal(next);
          }
        });

        it("should generate the powers of bobK in group G2", async function () {
          console.log(
            "NOTE: computing the G2 test comparison takes 15 seconds..."
          );
          expect(bobUpdatedS2_solo.length).to.equal(MAX_DEGREE + 1);
          expect(bobUpdatedS2_solo[0]).to.deep.equal(P2);
          let next;
          for (let i = 1; i < bobUpdatedS2_solo.length; i++) {
            next = await helper.multiplyG2(bobUpdatedS2_solo[i - 1], bobK);
            expect(bobUpdatedS2_solo[i]).to.deep.equal(next);
          }
        });

        it("should generate bobK in group G1", async function () {
          const kP1 = await helper.multiplyG1(P1, bobK);
          expect(bobProof_solo).to.deep.equal(kP1);
        });

        describe("Bob updates the trusted setup", async function () {
          it("should fail to update S", async function () {
            const update = setup.update(
              bobUpdatedS1_solo,
              bobUpdatedS2_solo,
              bobProof_solo
            );
            expect(update).to.be.revertedWith(
              "Cannot update S. Invalid proofs provided"
            );
          });
        });
      });
    });
  });
});
