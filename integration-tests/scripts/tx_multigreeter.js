// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Greeter = await hre.ethers.getContractFactory("MutipleGreeter");
    const dualAddr = deploy.dualgreeter
    if (!dualAddr){
      throw 'no addr for dual greeter contract'
    }
    const triAddr = deploy.trigreeter
    if (!triAddr){
      throw 'no addr for triple greeter contract'
    }

    const val = new Date().getTime();
    const greeter1 = Greeter.attach(dualAddr)
    console.log('dual greet before', await greeter1.retrieve(0), await greeter1.retrieve(1))
    const setGreetingTx1 = await greeter1.set_multiple(2, val);
    const greeter2 = Greeter.attach(triAddr)
    console.log('tri greet before', await greeter2.retrieve(0), await greeter2.retrieve(1), await greeter2.retrieve(2))
    const setGreetingTx2 = await greeter2.set_multiple(3, val);
    await Promise.all([setGreetingTx1.wait(), setGreetingTx2.wait()]);
    console.log('greet after', await greeter1.retrieve(0), await greeter2.retrieve(0), await greeter2.retrieve(1))
    const setGreetingTx1_clear = await greeter1.set_one(0, 0);
    const setGreetingTx2_clear = await greeter2.set_one(0, 0);
    const setGreetingTx3_clear = await greeter2.set_one(1, 0);
    await Promise.all([setGreetingTx1_clear.wait(), setGreetingTx2_clear.wait(), setGreetingTx3_clear.wait()]);
    console.log('greet final', await greeter1.retrieve(0), await greeter2.retrieve(0), await greeter2.retrieve(1))

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
  