// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Sushi = await hre.ethers.getContractFactory("SushiToken");
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

    const [owner] = await hre.ethers.getSigners();

    let poolLen = await chef.poolLength()
    console.log('pool length', poolLen)

    let pid = poolLen - 1

    console.log('pool info', await chef.poolInfo(pid))
    console.log('now sushi', await sushi.balanceOf(owner.address))

    const tx = await chef.withdraw(pid, BigInt(1e18))
    await tx.wait()
    console.log('now sushi after redraw', await sushi.balanceOf(owner.address))
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
  