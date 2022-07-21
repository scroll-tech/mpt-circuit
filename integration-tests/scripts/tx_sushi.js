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
    const nowbalance = await sushi.balanceOf(owner.address)
    if (nowbalance < BigInt(1e18)) {
        throw 'no enough balance, must re-deploy'
    }

    const tx2 = await chef.add(BigInt(1e18), sushiAddr, true)
    await tx2.wait()

    let poolLen = await chef.poolLength()
    console.log('pool length', poolLen)

    let pid = poolLen - 1

    const tx3 = await chef.set(pid, BigInt(1e18), true)
    await tx3.wait()

    console.log('pool info', await chef.poolInfo(pid))

    const tx4 = await sushi.approve(deploy.sushiChef, BigInt(1e18))
    await tx4.wait()

    const tx5 = await chef.deposit(pid, BigInt(1e18))
    await tx5.wait()

    console.log('now should wait for several (>4) blocks')
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
  