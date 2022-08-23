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

    const st = new Date().getTime()

    const createGreetingTx = await creater.disp(st);
    const deepCreateTx = await createrDeep.deep_disp(st);

    await Promise.all([createGreetingTx.wait(), deepCreateTx.wait()])

    const gtAddr = await creater.disp_result()

    console.log('greet at', gtAddr)
    const Greeter = await hre.ethers.getContractFactory("Greeter");
    const greeter = Greeter.attach(gtAddr)
    console.log('greet', await greeter.retrieve())

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
  