// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const SCreater = await hre.ethers.getContractFactory("SuiciderCreater");
    const addr = deploy.suicider
    if (!addr){
      throw 'no addr for suicide creater contract'
    }

    const sCreater = SCreater.attach(addr)

    const createSuiderTx = await sCreater.give_birth();
    await createSuiderTx.wait()

    const suiderAddr = await sCreater.birth_result()

    console.log('suider at', suiderAddr)
    const Suider = await hre.ethers.getContractFactory("Suicider");
    const suider = Suider.attach(suiderAddr);

    const EdgeSuicider = await hre.ethers.getContractFactory("TestEdgeSelfDestruct");
    const edgeSuideTx = await EdgeSuicider.deploy({gasLimit: 1000000});
    const suideTx = await suider.my_suicide();
    await suideTx.wait()
    try {
      await edgeSuideTx.deployed()
    } catch (e) {
      console.log("Expected error")
    }
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

