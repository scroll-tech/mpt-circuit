// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")


async function main() {

  // We get the contract to deploy
  const SCaller = await hre.ethers.getContractFactory("StatticCaller");
  const s = await SCaller.deploy();

  const Caller = await hre.ethers.getContractFactory("Caller");
  const callerAddr = deploy.caller
  if (!callerAddr){
    throw 'no addr for caller contract'
  }
  const caller = Caller.attach(callerAddr)
  const tx1 = await caller.pay_failing(10)
  await Promise.all([tx1.wait(), s.deployed()])
  console.log("static Caller deployed:", s.address);
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
