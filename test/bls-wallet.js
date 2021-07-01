const { expect } = require("chai");

describe("BLS Wallet", function () {

  let SimulatedBLSWallet;

  this.beforeAll(async () => {
    const Alt_BN128Library = await ethers.getContractFactory("Alt_BN128Library");
    bn128Library = await Alt_BN128Library.deploy();
    await bn128Library.deployed();
    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet", {
      libraries: { Alt_BN128Library: bn128Library.address }
    });
  })
  
  it("Should compute a public key", async function () {
    const wallet = await SimulatedBLSWallet.deploy("Alice");
    await wallet.deployed();

    pk = await wallet.PUBLIC_KEY()
    // this should check that it matches the expected value, but I don't know what that is
    expect(pk.x).to.not.equal(0);
    expect(pk.y).to.not.equal(0);
  });
});
