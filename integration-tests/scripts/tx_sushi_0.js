// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Sushi = await hre.ethers.getContractFactory("SushiToken");

    const sushi = await Sushi.deploy();
    await sushi.deployed();
  
    console.log("temporary sushi deployed to:", sushi.address);
  
    const tx = await sushi.transferOwnership(deploy.sushiChef)
    await tx.wait()

    console.log("transfer token's ownership to chef")
}

  // We recommend this pattern to be able to use async/await everywhere
  // and properly handle errors.
  main()
    .then(() => {
        process.exit(0)
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
  