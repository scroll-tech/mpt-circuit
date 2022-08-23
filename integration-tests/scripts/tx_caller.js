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

    const setGreetingTx = await callerDeep.set_value_failing_deep(100);
    await setGreetingTx.wait()
    console.log('after failed deep', await callerDeep.status())

    const st = new Date().getTime()
    const setGreetingTx1 = await caller.set_value(st);
    const setGreetingTx2 = await callerDeep.set_value_deep(st);
    const setGreetingTx3 = await callerDeep.set_value_failing_deep(0); 
    await Promise.all([setGreetingTx1.wait(), setGreetingTx2.wait(), setGreetingTx3.wait()])
    console.log('greet after', await greeter.retrieve())
    console.log('greet after deep', await callerDeep.status())

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
  