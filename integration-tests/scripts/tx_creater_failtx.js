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

    const createGreetingTx = await creater.disp_failing(0);
    await createGreetingTx.wait()

    const failAddr = await creater.disp_result()

    console.log('faiAddr result', failAddr)

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
  