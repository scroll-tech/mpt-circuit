// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const fs = require("fs")
const path = require('path')

async function greeter() {
  // Hardhat always runs the compile task when running scripts with its command
  // line interface.
  //
  // If this script is run directly using `node` you may want to call compile
  // manually to make sure everything is compiled
  // await hre.run('compile');

  // We get the contract to deploy
  const Greeter = await hre.ethers.getContractFactory("Greeter");
  const greeter = await Greeter.deploy(0);

  await greeter.deployed();

  console.log("Greeter deployed to:", greeter.address);

  return ["greeter", greeter.address]
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
Promise.all([greeter()])
  .then(res => {
    let fd = fs.openSync(path.join(__dirname, 'deploy.json'), 'w')
    fs.writeFileSync(fd, JSON.stringify(Object.fromEntries(res)))
    fs.closeSync(fd)
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
