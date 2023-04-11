// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Greeter = await hre.ethers.getContractFactory("DualGreeter");
    const addr = deploy.dualgreeter
    if (!addr){
      throw 'no addr for greeter contract'
    }
    const greeter = Greeter.attach(addr)
    console.log('greet before', await greeter.retrieve1(), await greeter.retrieve2())
    const val = new Date().getTime();
    const setGreetingTx1 = await greeter.set_value1(val);
    const setGreetingTx2 = await greeter.set_value2(val+1);
    await Promise.all([setGreetingTx1.wait(), setGreetingTx2.wait()]);
    console.log('greet after', await greeter.retrieve1(), await greeter.retrieve2())
    const setGreetingTx1_clear = await greeter.set_value1(0);
    await setGreetingTx1_clear.wait();
    console.log('greet final', await greeter.retrieve1(), await greeter.retrieve2())

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
  