const { expect } = require("chai");

describe("BLS Wallet", function () {

  let SimulatedBLSWallet;

  this.beforeAll(async () => {
    // const BN256G1 = await ethers.getContractFactory("BN256G1");
    // lib = await BN256G1.deploy();
    // await lib.deployed();
    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet");
  })
  
  it("Should compute a public key", async function () {
    const wallet = await SimulatedBLSWallet.deploy("Alice");
    await wallet.deployed();

    pk = await wallet.PUBLIC_KEY();
    
    // this should check that it matches the expected value, but I don't know what that is
    expect(pk.x).to.not.equal(0);
    expect(pk.y).to.not.equal(0);
  });
});
