const { expect } = require("chai");

describe("BLS Wallet", function () {

  let SimulatedBLSWallet;

  this.beforeAll(async () => {
    SimulatedBLSWallet = await ethers.getContractFactory("SimulatedBLSWallet");
  })
  
  it("Should compute a public key", async function () {
    const wallet = await SimulatedBLSWallet.deploy("Alice");
    await wallet.deployed();

    pk = await wallet.PUBLIC_KEY();
    
    // this should check that it matches the expected value, but I don't know what that is
    // I will defer this to the signatures tests
    expect(pk.x_real).to.not.equal(0);
    expect(pk.x_imag).to.not.equal(0);
    expect(pk.y_real).to.not.equal(0);
    expect(pk.y_imag).to.not.equal(0);
  });
});
