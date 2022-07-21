// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function dao() {
    console.log("vote addr", deploy.vote)
  
    const Dao = await hre.ethers.getContractFactory("GovernorMock");
    const dao = await Dao.deploy("governor mock", deploy.vote, 1, 1, 100);
  
    await dao.deployed();
  
    console.log("DAO deployed to:", dao.address);
  
  }

async function main() {

/*    const Sushi = await hre.ethers.getContractFactory("SushiToken");
    const sushiAddr = deploy.sushi
    if (!sushiAddr){
      throw 'no addr for sushi contract'
    }
    const sushi = Sushi.attach(sushiAddr)

    const Chef = await hre.ethers.getContractFactory("MasterChef");
    const addr = deploy.sushiChef
    if (!addr){
      throw 'no addr for sushi contract'
    }
    const chef = Chef.attach(addr)

    const tx = await sushi.transferOwnership(chef.address)
	await tx.wait()
	console.log("transfer token's ownership to chef")    */

    console.log(await hre.web3.eth.isMining())
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
  