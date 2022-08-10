// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");

async function erc20() {

  const [owner] = await hre.ethers.getSigners();
  const ownerAddr = await owner.getAddress();

  // We get the contract to deploy
  const Token = await hre.ethers.getContractFactory("ERC20Template");
  const token = await Token.deploy(ownerAddr, ownerAddr, "USDT coin", "USDT", 18);

  await token.deployed();

  console.log("ERC20 token deployed to:", token.address);

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
Promise.all([erc20()])
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
