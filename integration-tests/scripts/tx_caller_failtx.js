// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Greeter = await hre.ethers.getContractFactory("Greeter");
    const addr = deploy.greeter
    if (!addr){
      throw 'no addr for greeter contract'
    }
    const greeter = Greeter.attach(addr)
    console.log('greet before', await greeter.retrieve())

    const Caller = await hre.ethers.getContractFactory("Caller");
    const callerAddr = deploy.caller
    if (!callerAddr){
      throw 'no addr for caller contract'
    }
    const caller = Caller.attach(callerAddr)

    const CallerDeep = await hre.ethers.getContractFactory("CallerDeep")
    const callerDeepAddr = deploy.callerdeep
    if (!callerDeepAddr){
      throw 'no addr for deep caller contract'
    }
    const callerDeep = CallerDeep.attach(callerDeepAddr)

    const st = new Date().getTime()
    const setGreetingTx1 = await caller.set_value_failing(st);
    const setGreetingTx2 = await callerDeep.set_value_failing_outer(st);
    const setGreetingTx3 = await callerDeep.set_value_failing_both(st);
    await Promise.allSettled([setGreetingTx1.wait(), setGreetingTx2.wait(), setGreetingTx3.wait()])
    console.log('failed greet after', await greeter.retrieve())

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
  