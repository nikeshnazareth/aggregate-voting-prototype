require("@nomiclabs/hardhat-waffle");

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async () => {
  const accounts = await ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.6.12",
  networks: {
    hardhat: {
      // generating an update proof for the Trusted Setup consumes too much gas
      // this is not a problem in practice because it's a `view` function
      // and a real-world trusted setup is not going to use the EVM
      // this increases the gas limit so the test suite can complete
      blockGasLimit:10**8
    }
  }
};

