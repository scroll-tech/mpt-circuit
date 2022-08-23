// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Creater = await hre.ethers.getContractFactory("Creater");
    const addr = deploy.creater
    if (!addr){
      throw 'no addr for creater contract'
    }
    const creater = Creater.attach(addr)

    const CreaterDeep = await hre.ethers.getContractFactory("CreaterDeep");
    const addrDeep = deploy.createrdeep
    if (!addrDeep){
      throw 'no addr for creater deep contract'
    }
    const createrDeep = CreaterDeep.attach(addrDeep)

    const createGreetingTx = await creater.disp_failing(0);
    const failTx1 = await createrDeep.deep_disp_failing(0);
    const failTx2 = await createrDeep.deep_disp_failing_both(0);

    await Promise.allSettled([createGreetingTx.wait(), failTx1.wait(), failTx2.wait()])

    console.log('faiAddr result', await creater.disp_result(), await createrDeep.status())

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
  